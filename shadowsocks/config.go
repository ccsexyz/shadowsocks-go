package ss

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"log"
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
	ObfsAlive  bool     `json:"obfsalive"`
}

// NetworkConfig groups network addressing and routing configuration.
type NetworkConfig struct {
	Type           string   `json:"type"`
	Localaddr      string   `json:"localaddr"`
	Localaddrs     []string `json:"localaddrs"`
	Remoteaddr     string   `json:"remoteaddr"`
	Timeout        int      `json:"timeout"`
	PreferIPv4     bool     `json:"prefer_ipv4"`
	NoIPv4         bool     `json:"no_ipv4"`
	NoIPv6         bool     `json:"no_ipv6"`
	LocalResolve   bool     `json:"local_resolve"`
	RtunnelService string   `json:"rtunnelservice"`
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
	limiters      []*Limiter
	Vlogger       *log.Logger
	Dlogger       *log.Logger
	Logger        *log.Logger
	logfile       *os.File
	Any           interface{}
	Die           chan bool
	pool          *ConnPool
	closers       []cb
	tcpFilterLock sync.Mutex
	tcpFilterOnce sync.Once
	tcpFilter     bytesFilter
	udpFilterOnce sync.Once
	udpFilter     bytesFilter
	tcpIvChecker  ivChecker
	autoProxyCtx  *autoProxy
	chnListCtx    *chnRouteList
	crctbl        *crc32.Table
	disable       bool
	stat          *statServer
}

func newRuntime() *runtime {
	return &runtime{Die: make(chan bool)}
}

func (rt *runtime) initStat() {
	if rt.stat == nil {
		rt.stat = &statServer{}
	}
}

type Config struct {
	Nickname       string    `json:"nickname"`
	Verbose        bool      `json:"verbose"`
	Debug          bool      `json:"debug"`
	LogFile        string    `json:"logfile"`
	UDPRelay       bool      `json:"udprelay"`
	FilterCapacity int       `json:"filtcap"`
	Backend        *Config   `json:"backend"`
	Backends       []*Config `json:"backends"`
	UseMul         bool      `json:"usemul"`
	UseUDP         bool      `json:"useudp"`
	MulConn        int       `json:"mulconn"`
	FakeTCPAddr    string    `json:"faketcpaddr"`
	DataShard      int       `json:"datashard"`
	ParityShard    int       `json:"parityshard"`
	SSProxy        bool      `json:"ssproxy"`
	AdminAddr      string    `json:"adminaddr"`

	CryptoConfig
	ObfsConfig
	NetworkConfig
	HttpConfig
	LimitConfig
	ProxyConfig

	rt *runtime
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

func (c *Config) getLogFile() *os.File {
	if c.rt == nil {
		return nil
	}
	return c.rt.logfile
}

func (c *Config) DieChan() chan bool { return c.initRuntime().Die }

func (c *Config) getPool() *ConnPool {
	if c.rt == nil {
		return nil
	}
	return c.rt.pool
}
func (c *Config) setPool(p *ConnPool) { c.initRuntime().pool = p }

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
	lf := c.getLogFile()
	if len(c.LogFile) != 0 && lf != os.Stderr && lf != nil {
		lf.Close()
	}
	for _, bkn := range c.Backends {
		blf := bkn.getLogFile()
		if blf != lf && blf != os.Stderr {
			blf.Close()
		}
	}
	if p := c.getPool(); p != nil {
		p.Close()
	}
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

func CheckLogFile(c *Config) {
	rt := c.initRuntime()
	if len(c.LogFile) == 0 {
		rt.logfile = os.Stderr
		return
	}
	f, err := os.OpenFile(c.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		rt.logfile = os.Stderr
		log.Println(err)
	} else {
		rt.logfile = f
	}
}

func CheckBasicConfig(c *Config) {
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
	rt.Logger = log.New(rt.logfile, fmt.Sprintf("[info] [%s] ", c.Nickname), log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	if c.Verbose {
		rt.Vlogger = log.New(rt.logfile, fmt.Sprintf("[verbose] [%s] ", c.Nickname), log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	if c.Debug {
		rt.Dlogger = log.New(rt.logfile, fmt.Sprintf("[debug] [%s] ", c.Nickname), log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
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
	CheckLogFile(c)
	CheckBasicConfig(c)
	if c.getPool() == nil && c.Obfs && c.ObfsAlive && (c.Type == "server" || c.Type == "multiserver" || c.Type == "local") {
		c.setPool(NewConnPool())
	}
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
			if c.ObfsAlive {
				v.ObfsAlive = true
			}
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
		if parentRt.autoProxyCtx != nil {
			v.initRuntime().autoProxyCtx = parentRt.autoProxyCtx
		}
		if c.LogFile == v.LogFile {
			v.initRuntime().logfile = parentRt.logfile
		} else {
			CheckLogFile(v)
			vlf := v.getLogFile()
			if vlf == os.Stderr && parentRt.logfile != os.Stderr {
				v.initRuntime().logfile = parentRt.logfile
			}
		}
		if v.Obfs && v.ObfsAlive {
			if v.Type != "server" {
				v.setPool(NewConnPool())
			} else {
				v.setPool(c.getPool())
			}
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

func (c *Config) LogV(v ...interface{}) {
	if vl := c.getVLogger(); vl != nil {
		vl.Output(2, fmt.Sprintln(v...))
	}
}

func (c *Config) LogD(v ...interface{}) {
	if dl := c.getDLogger(); dl != nil {
		dl.Output(2, fmt.Sprintln(v...))
	}
}

func (c *Config) Log(v ...interface{}) {
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
