package ss

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

// CryptoConfig groups encryption-related configuration.
type CryptoConfig struct {
	Method   string `json:"method"`
	Password string `json:"password"`
	Nonop    bool   `json:"nonop"`
	Safe     bool   `json:"safe"`
	Ivlen    int
}

// ObfsConfig groups obfuscation-related configuration.
type ObfsConfig struct {
	Obfs       bool     `json:"obfs"`
	ObfsMethod string   `json:"obfsmethod"`
	ObfsHost   []string `json:"obfshost"`
}

// NetworkConfig groups network addressing and routing configuration.
type NetworkConfig struct {
	Type       string   `json:"type"`
	Localaddr  string   `json:"localaddr"`
	Localaddrs []string `json:"localaddrs"`
	Remoteaddr string   `json:"remoteaddr"`
	Timeout    int      `json:"timeout"`
	// PreferIPv4 means different things by path:
	//   - DialTCP/ipselect: IPv4 candidates start first; IPv6 is still raced after the stagger.
	//   - LocalResolve pickTargetIP: dual-stack domains resolve to IPv4 only.
	PreferIPv4 bool `json:"prefer_ipv4"`
	NoIPv4     bool `json:"no_ipv4"`
	NoIPv6     bool `json:"no_ipv6"`
	// LocalResolve selects the target IP client-side.
	LocalResolve bool `json:"local_resolve"`
	// IPSelect is one of smart, race or off. Empty and invalid values fall
	// back to off in CheckBasicConfig.
	IPSelect string `json:"ipselect,omitempty"`
	// IPSelectDelayMs is the stagger between raced candidates. 0 or negative
	// means "use defaultIPSelectDelayMs"; values above maxIPSelectDelayMs are
	// clamped.
	IPSelectDelayMs int    `json:"ipselect_delay_ms,omitempty"`
	RtunnelService  string `json:"rtunnelservice"`
	Forward         string `json:"forward,omitempty"`
}

// HttpConfig groups HTTP-related configuration.
type HttpConfig struct {
	AllowHTTP    bool              `json:"allow_http"`
	LogHTTP      bool              `json:"loghttp"`
	SecureOrigin bool              `json:"secure_origin"`
	TargetMap    map[string]string `json:"target_map"`
}

// LimitConfig groups rate-limiting configuration.
type LimitConfig struct {
	Limit        int `json:"limit"`
	LimitPerConn int `json:"limitperconn"`
}

// ProxyConfig groups auto-proxy and routing configuration.
type ProxyConfig struct {
	AutoProxy bool   `json:"autoproxy"`
	ProxyList string `json:"proxylist"`
	BlackList string `json:"blacklist"`
	DumpList  bool   `json:"dumplist"`
	ChnList   string `json:"chnlist"`
	Direct    bool   `json:"direct"`
	MITM      bool   `json:"mitm"`
}

// runtime holds all live state for a Config. It is never JSON-serialized.
type runtime struct {
	limiters       []*Limiter
	Vlogger        *log.Logger
	Dlogger        *log.Logger
	Logger         *log.Logger
	Any            any
	Die            chan bool
	closers        []cb
	tcpFilterLock  sync.Mutex
	tcpFilterOnce  sync.Once
	tcpFilter      bytesFilter
	udpFilterOnce  sync.Once
	udpFilter      bytesFilter
	tcpIvChecker   ivChecker
	autoProxyCtx   *autoProxy
	chnListCtx     *chnRouteList
	crctbl         *crc32.Table
	disable        bool
	stat           *statServer
	dialHealth     *dialHealth
	ipSelCache     *ipScoreCache
	ipSelCacheOnce sync.Once
}

type dialHealth struct {
	mu        sync.Mutex
	success   int64
	fail      int64
	timeout   int64
	latencyNs int64
	dialCount int64
}

func (dh *dialHealth) recordSuccess(elapsed time.Duration) {
	dh.mu.Lock()
	dh.success++
	dh.latencyNs += elapsed.Nanoseconds()
	dh.dialCount++
	dh.mu.Unlock()
}

func (dh *dialHealth) recordFail(isTimeout bool) {
	dh.mu.Lock()
	dh.fail++
	if isTimeout {
		dh.timeout++
	}
	dh.mu.Unlock()
}

func (dh *dialHealth) snapshot() (success, fail, timeout int64, avgLatencyMs float64) {
	dh.mu.Lock()
	defer dh.mu.Unlock()
	if dh.dialCount > 0 {
		avgLatencyMs = float64(dh.latencyNs/dh.dialCount) / 1e6
	}
	return dh.success, dh.fail, dh.timeout, avgLatencyMs
}

func newRuntime() *runtime {
	return &runtime{Die: make(chan bool)}
}

func (rt *runtime) initStat() {
	if rt.stat == nil {
		rt.stat = &statServer{methodStats: make(map[string]*methodStat)}
	}
}

type Config struct {
	Nickname       string    `json:"nickname"`
	Verbose        bool      // set by -verbose flag
	Debug          bool      // set by -debug flag
	UDPRelay       bool      `json:"udprelay"`
	FilterCapacity int       `json:"filtcap"`
	Backend        *Config   `json:"backend"`
	Backends       []*Config `json:"backends"`
	SSProxy        bool      `json:"ssproxy"`
	ConnLogPath    string    `json:"connlogpath,omitempty"`
	AdminAddr      string    `json:"adminaddr"`
	ActiveBackend  string    `json:"active,omitempty"`
	Target         string    `json:"target,omitempty"`

	CryptoConfig
	ObfsConfig
	NetworkConfig
	HttpConfig
	LimitConfig
	ProxyConfig

	rt           *runtime
	targetRouter *targetRouter
}

type targetEntryType int

const (
	targetHost targetEntryType = iota
	targetHeader
	targetMethodURI
)

type targetEntry struct {
	entryType  targetEntryType
	host       string // host match, lowercase
	headerName string // header match, lowercase key
	headerVal  string // header match, value
	method     string // method+URI match ("GET", "POST", etc.)
	requestURI string // method+URI match
	target     string // destination address
}

type targetRouter struct {
	entries  []targetEntry
	fallback string // http_proxy_to target
}

func (tr *targetRouter) matchHTTP(r *http.Request) string {
	for i := range tr.entries {
		e := &tr.entries[i]
		switch e.entryType {
		case targetHeader:
			if strings.EqualFold(r.Header.Get(e.headerName), e.headerVal) {
				return e.target
			}
		case targetMethodURI:
			if strings.EqualFold(r.Method, e.method) && r.RequestURI == e.requestURI {
				return e.target
			}
		case targetHost:
			if strings.EqualFold(r.Host, e.host) {
				return e.target
			}
		}
	}
	return tr.fallback
}

func (tr *targetRouter) matchHost(host string) string {
	lower := strings.ToLower(host)
	for i := range tr.entries {
		e := &tr.entries[i]
		if e.entryType == targetHost && e.host == lower {
			return e.target
		}
	}
	return ""
}

func parseTargetRouter(raw map[string]string) *targetRouter {
	if len(raw) == 0 {
		return &targetRouter{}
	}
	tr := &targetRouter{entries: make([]targetEntry, 0, len(raw))}
	seen := make(map[string]string, len(raw))
	for k, v := range raw {
		lower := strings.ToLower(k)
		if prev, ok := seen[lower]; ok {
			log.Printf("target_map: key collision %q and %q both normalize to %q, using latter", prev, k, lower)
		}
		seen[lower] = k

		if lower == "http_proxy_to" {
			tr.fallback = v
			continue
		}

		e := targetEntry{target: v}
		if idx := strings.IndexByte(lower, ' '); idx >= 0 {
			first, second := lower[:idx], lower[idx+1:]
			if utils.IsValidHTTPMethod(strings.ToUpper(first)) {
				e.entryType = targetMethodURI
				e.method = strings.ToUpper(first)
				e.requestURI = second
			} else {
				e.entryType = targetHeader
				e.headerName = first
				e.headerVal = second
			}
		} else {
			e.entryType = targetHost
			e.host = lower
		}
		tr.entries = append(tr.entries, e)
	}
	return tr
}

// initRuntime lazily initializes the runtime and returns it.
func (c *Config) initRuntime() *runtime {
	if c.rt == nil {
		c.rt = newRuntime()
	}
	return c.rt
}

// InitRuntime is the exported version of initRuntime.
func (c *Config) InitRuntime() *runtime { return c.initRuntime() }

// Runtime accessors — all runtime state goes through these methods.
func (c *Config) getLimiters() []*Limiter {
	if c.rt == nil {
		return nil
	}
	return c.rt.limiters
}

func (c *Config) getLogger() *log.Logger {
	if c.rt == nil {
		return nil
	}
	return c.rt.Logger
}
func (c *Config) getVLogger() *log.Logger {
	if c.rt == nil {
		return nil
	}
	return c.rt.Vlogger
}
func (c *Config) getDLogger() *log.Logger {
	if c.rt == nil {
		return nil
	}
	return c.rt.Dlogger
}

func (c *Config) DieChan() chan bool { return c.initRuntime().Die }

func (c *Config) getClosers() []cb {
	if c.rt == nil {
		return nil
	}
	return c.rt.closers
}

func (c *Config) getTCPFilter() bytesFilter {
	if c.rt == nil {
		return nil
	}
	return c.rt.tcpFilter
}
func (c *Config) getTCPFilterLock() *sync.Mutex { return &c.initRuntime().tcpFilterLock }
func (c *Config) getTCPFilterOnce() *sync.Once  { return &c.initRuntime().tcpFilterOnce }
func (c *Config) setTCPFilter(f bytesFilter)    { c.initRuntime().tcpFilter = f }

func (c *Config) getUDPFilterOnce() *sync.Once { return &c.initRuntime().udpFilterOnce }
func (c *Config) getUDPFilter() bytesFilter {
	if c.rt == nil {
		return nil
	}
	return c.rt.udpFilter
}
func (c *Config) setUDPFilter(f bytesFilter) { c.initRuntime().udpFilter = f }

func (c *Config) getTCPIvChecker() *ivChecker {
	if c.rt == nil {
		return nil
	}
	return &c.rt.tcpIvChecker
}

func (c *Config) getAutoProxyCtx() *autoProxy {
	if c.rt == nil {
		return nil
	}
	return c.rt.autoProxyCtx
}
func (c *Config) setAutoProxyCtx(ap *autoProxy) { c.initRuntime().autoProxyCtx = ap }

func (c *Config) getChnListCtx() *chnRouteList {
	if c.rt == nil {
		return nil
	}
	return c.rt.chnListCtx
}
func (c *Config) setChnListCtx(cl *chnRouteList) { c.initRuntime().chnListCtx = cl }

func (c *Config) getCRCTable() *crc32.Table {
	if c.rt == nil {
		return nil
	}
	return c.rt.crctbl
}

func (c *Config) isDisabled() bool {
	if c.rt == nil {
		return false
	}
	return c.rt.disable
}
func (c *Config) setDisabled(v bool) { c.initRuntime().disable = v }
func (c *Config) getStat() *statServer {
	rt := c.initRuntime()
	rt.initStat()
	return rt.stat
}
func (c *Config) setStat(s *statServer) { c.initRuntime().stat = s }
func (c *Config) initDialHealth() *dialHealth {
	rt := c.initRuntime()
	if rt.dialHealth == nil {
		rt.dialHealth = &dialHealth{}
	}
	return rt.dialHealth
}

func (c *Config) getIPSelectCache() *ipScoreCache {
	rt := c.initRuntime()
	rt.ipSelCacheOnce.Do(func() {
		if rt.ipSelCache == nil {
			rt.ipSelCache = newIPScoreCache()
		}
	})
	return rt.ipSelCache
}

func (c *Config) GetTargetTracker() *TargetTracker {
	if s := c.getStat(); s != nil {
		return s.targetTracker
	}
	return nil
}

var globalLogWriter io.Writer = os.Stderr

// SetGlobalLogFile redirects all future log output to the given file.
// Call before ReadConfig or CheckConfig to take effect.
func SetGlobalLogFile(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	globalLogWriter = f
	return nil
}

func ReadConfig(path string) (configs []*Config, err error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return
	}
	err = json.Unmarshal(bytes, &configs)
	if err != nil {
		var c Config
		err = json.Unmarshal(bytes, &c)
		if err == nil {
			configs = append(configs, &c)
		}
	}
	for _, c := range configs {
		CheckConfig(c)
	}
	return
}

func (c *Config) Close() error {
	c.getTCPFilterLock().Lock()
	select {
	case <-c.DieChan():
	default:
		close(c.DieChan())
	}
	c.getTCPFilterLock().Unlock()
	for _, f := range c.getClosers() {
		f()
	}
	return nil
}

func (c *Config) udpFilterTestAndAdd(b []byte) bool {
	if c.Ivlen == 0 {
		return false
	}
	c.getUDPFilterOnce().Do(func() {
		c.setUDPFilter(newBloomFilter(c.FilterCapacity, defaultFilterFalseRate))
	})
	return c.getUDPFilter().TestAndAdd(b)
}

func (c *Config) tcpFilterTestAndAdd(b []byte) bool {
	if c.Ivlen == 0 {
		return false
	}
	c.getTCPFilterOnce().Do(func() {
		c.setTCPFilter(newBloomFilter(c.FilterCapacity, defaultFilterFalseRate))
	})
	c.getTCPFilterLock().Lock()
	ok1 := c.getTCPFilter().TestAndAdd(b)
	c.getTCPFilterLock().Unlock()
	return ok1
}

func CheckBasicConfig(c *Config) {
	c.targetRouter = parseTargetRouter(c.TargetMap)
	for i := range c.Backends {
		c.Backends[i].targetRouter = parseTargetRouter(c.Backends[i].TargetMap)
	}
	if len(c.Password) == 0 {
		c.Password = defaultPassword
	}
	if len(c.Method) == 0 {
		c.Method = defaultMethod
	}
	if c.Ivlen == 0 {
		c.Ivlen = crypto.GetIvLen(c.Method)
	}
	if len(c.Nickname) == 0 {
		if len(c.Localaddr) == 0 {
			c.Nickname = fmt.Sprintf("%v-%v-%v", c.Type, c.Method, c.Password)
		} else {
			c.Nickname = fmt.Sprintf("%v-%v", c.Type, c.Localaddr)
		}
	}
	rt := c.initRuntime()
	rt.Logger = log.New(globalLogWriter, fmt.Sprintf("[info] [%s] ", c.Nickname), log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	if c.Verbose {
		rt.Vlogger = log.New(globalLogWriter, fmt.Sprintf("[verbose] [%s] ", c.Nickname), log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	if c.Debug {
		rt.Dlogger = log.New(globalLogWriter, fmt.Sprintf("[debug] [%s] ", c.Nickname), log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	if c.Limit != 0 {
		rt.limiters = append(rt.limiters, NewLimiter(c.Limit))
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	if c.FilterCapacity == 0 {
		c.FilterCapacity = defaultFilterCapacity
	}
	if normalized := normalizeIPSelectMode(c.IPSelect); normalized != c.IPSelect {
		if c.IPSelect != "" {
			rt.Logger.Printf("invalid ipselect %q, fallback to %q", c.IPSelect, normalized)
		}
		c.IPSelect = normalized
	}
	// 0 and negative values mean "use the default stagger"; explicit values
	// are normalized here so admin/config readers see what actually runs.
	if c.IPSelectDelayMs <= 0 {
		c.IPSelectDelayMs = defaultIPSelectDelayMs
	} else if c.IPSelectDelayMs > maxIPSelectDelayMs {
		rt.Logger.Printf("ipselect_delay_ms %d too large, clamped to %d", c.IPSelectDelayMs, maxIPSelectDelayMs)
		c.IPSelectDelayMs = maxIPSelectDelayMs
	}
	if c.IPSelect == ipSelectSmart {
		c.getIPSelectCache() // initialize before concurrent dials start
	}
	rt.crctbl = crc32.MakeTable(crc32.ChecksumIEEE(utils.StringToSlice(c.Password)))
}

func CheckConfig(c *Config) {
	if len(c.Localaddr) == 0 && len(c.Localaddrs) > 0 {
		c.Localaddr = c.Localaddrs[0]
		c.Localaddrs = c.Localaddrs[1:]
	}
	if len(c.Type) == 0 {
		if len(c.Localaddr) != 0 && len(c.Remoteaddr) != 0 {
			c.Type = "local"
		} else if len(c.Localaddr) != 0 {
			c.Type = "server"
		}
	}
	if c.Type == "socks" {
		c.Type = "socksproxy"
		c.Backend = nil
		c.Backends = nil
	}
	c.initRuntime() // ensure Die is created
	CheckBasicConfig(c)
	if c.Backend != nil {
		c.Backends = append(c.Backends, c.Backend)
	}
	if c.AutoProxy {
		ap := newAutoProxy()
		ap.loadByPassList(c.BlackList)
		ap.loadPorxyList(c.ProxyList)
		c.setAutoProxyCtx(ap)
		if c.DumpList {
			go c.proxyListDump()
		}
	}
	if len(c.ChnList) != 0 {
		cl := new(chnRouteList)
		err := cl.load(c.ChnList)
		if err != nil {
			log.Println(err)
		} else {
			c.setChnListCtx(cl)
		}
	}
	c.getStat() // ensure initialized
	parentRt := c.rt
	for _, v := range c.Backends {
		v.initRuntime().Die = parentRt.Die
		if len(v.Type) == 0 {
			if len(v.Remoteaddr) != 0 {
				v.Type = "local"
			} else {
				v.Type = "server"
			}
		}
		if c.Obfs {
			v.Obfs = true
			v.ObfsHost = append(v.ObfsHost, c.ObfsHost...)
		}
		if c.Debug {
			v.Debug = true
		}
		if c.Safe {
			v.Safe = true
		}
		if c.Verbose {
			v.Verbose = true
		}
		if c.LogHTTP {
			v.LogHTTP = true
		}
		if v.Timeout == 0 {
			v.Timeout = c.Timeout
		}
		if c.PreferIPv4 {
			v.PreferIPv4 = true
		}
		if v.IPSelect == "" {
			v.IPSelect = c.IPSelect
		}
		if v.IPSelectDelayMs <= 0 {
			v.IPSelectDelayMs = c.IPSelectDelayMs
		}
		if parentRt.autoProxyCtx != nil {
			v.initRuntime().autoProxyCtx = parentRt.autoProxyCtx
		}
		CheckBasicConfig(v)
		if c.LimitPerConn != 0 && v.LimitPerConn == 0 {
			v.LimitPerConn = c.LimitPerConn
		}
		parentLimiters := parentRt.limiters
		if len(parentLimiters) != 0 {
			v.initRuntime().limiters = append(v.initRuntime().limiters, parentLimiters...)
		}
		v.getStat()
	}
}

func (c *Config) LogV(v ...any) {
	if vl := c.getVLogger(); vl != nil {
		vl.Output(2, fmt.Sprintln(v...))
	}
}

func (c *Config) LogD(v ...any) {
	if dl := c.getDLogger(); dl != nil {
		dl.Output(2, fmt.Sprintln(v...))
	}
}

func (c *Config) Log(v ...any) {
	if l := c.getLogger(); l != nil {
		l.Output(2, fmt.Sprintln(v...))
	}
}

func (c *Config) CallOnClosed(f cb) {
	c.initRuntime().closers = append(c.rt.closers, f)
}

func (c *Config) proxyListDump() {
	if c.BlackList == "" && c.ProxyList == "" {
		return
	}
	ap := c.getAutoProxyCtx()
	if ap == nil {
		return
	}
	die := c.DieChan()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
			case <-die:
				return
			}
			if len(c.BlackList) != 0 {
				hosts := ap.getByPassHosts()
				if len(hosts) != 0 {
					hoststr := strings.Join(hosts, "\n")
					err := os.WriteFile(c.BlackList, utils.StringToSlice(hoststr), 0644)
					if err != nil {
						c.Log(err)
					}
				}
			}
			if len(c.ProxyList) != 0 {
				hosts := ap.getProxyHosts()
				if len(hosts) != 0 {
					hoststr := strings.Join(hosts, "\n")
					err := os.WriteFile(c.ProxyList, utils.StringToSlice(hoststr), 0644)
					if err != nil {
						c.Log(err)
					}
				}
			}
		}
	}()
}
