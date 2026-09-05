package ss

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed admin_ui/*
var adminUIRaw embed.FS

var adminUI, _ = fs.Sub(adminUIRaw, "admin_ui")

var adminRegistry struct {
	mu      sync.RWMutex
	configs []*Config
}

// adminWriteMu serializes all admin handlers that mutate live Config fields.
// Without it two concurrent settings updates could interleave their multi-key
// apply loops. Readers of those fields (handleGetConfigRaw, buildConfigSummary)
// pair with this mutex too, and the runtime dial-policy reader (see
// Config.dialPolicy) keeps its snapshot rebuilds under it, so no reader can
// observe a torn string or slice header.
var adminWriteMu sync.Mutex

// adminHostAllowed rejects requests whose Host header is a DNS name. With no
// token configured, the admin API is guarded only by network reachability, so
// a malicious web page can DNS-rebind its own domain to 127.0.0.1 and talk to
// a loopback-bound admin as a same-origin request from the victim's browser.
// Requiring an IP literal (or "localhost") breaks that attack while keeping
// every literal-IP access working; token-authenticated setups skip the check
// because the attacker cannot read or write without the token.
func adminHostAllowed(hostHeader string) bool {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	return net.ParseIP(host) != nil
}

// requireJSONContentType rejects requests whose body was not declared as
// JSON. A browser can send cross-site no-cors POSTs with text/plain bodies
// (no preflight required), so JSON-decoding handlers must not trust an
// undeclared body even when the admin API is loopback-only.
func requireJSONContentType(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err == nil && mt == "application/json" {
			return true
		}
	}
	http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
	return false
}

var adminStartTime = time.Now()

// SSE hub for real-time event streaming.
var sseHub = newSSEHub()

type sseBroker struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
}

func newSSEHub() *sseBroker {
	return &sseBroker{clients: make(map[chan []byte]struct{})}
}

func (h *sseBroker) subscribe() chan []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients) >= maxSSEClients {
		return nil
	}
	ch := make(chan []byte, 64)
	h.clients[ch] = struct{}{}
	return ch
}

func (h *sseBroker) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

func (h *sseBroker) publish(event string, data []byte) {
	msg := make([]byte, 0, len(event)+len(data)+16)
	msg = append(msg, "event: "...)
	msg = append(msg, event...)
	msg = append(msg, "\ndata: "...)
	msg = append(msg, data...)
	msg = append(msg, "\n\n"...)
	h.mu.RLock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default: // drop if client is slow
		}
	}
	h.mu.RUnlock()
}

// Per-connection event hub: connID → set of subscriber channels
var connEventHub = struct {
	mu   sync.RWMutex
	subs map[uint64]map[chan []byte]struct{}
}{
	subs: make(map[uint64]map[chan []byte]struct{}),
}

func connEventSubscribe(connID uint64) chan []byte {
	connEventHub.mu.Lock()
	defer connEventHub.mu.Unlock()
	if len(connEventHub.subs) >= maxSSEClients {
		return nil
	}
	ch := make(chan []byte, 64)
	if connEventHub.subs[connID] == nil {
		connEventHub.subs[connID] = make(map[chan []byte]struct{})
	}
	connEventHub.subs[connID][ch] = struct{}{}
	return ch
}

func connEventUnsubscribe(connID uint64, ch chan []byte) {
	connEventHub.mu.Lock()
	if m := connEventHub.subs[connID]; m != nil {
		delete(m, ch)
		if len(m) == 0 {
			delete(connEventHub.subs, connID)
		}
	}
	connEventHub.mu.Unlock()
}

func connEventPublish(connID uint64, event string, data []byte) {
	msg := make([]byte, 0, len(event)+len(data)+16)
	msg = append(msg, "event: "...)
	msg = append(msg, event...)
	msg = append(msg, "\ndata: "...)
	msg = append(msg, data...)
	msg = append(msg, "\n\n"...)
	connEventHub.mu.RLock()
	for ch := range connEventHub.subs[connID] {
		select {
		case ch <- msg:
		default:
		}
	}
	connEventHub.mu.RUnlock()
}

func ssePublishIndex(event string, idx int, data any) {
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	sseHub.publish(event, b)
}

// traffic history — circular buffer of per-index rate samples for sparklines
const trafficHistorySize = 60

var trafficHistory = struct {
	mu     sync.Mutex
	buf    []trafficSample
	pos    int
	filled bool
}{
	buf: make([]trafficSample, trafficHistorySize*64), // up to 64 configs
}

const minuteHistorySize = 30
const minuteInterval = 30

var minuteHistory = struct {
	mu      sync.Mutex
	buf     []trafficSample
	pos     int
	filled  bool
	tick    int
	accRead []int64
	accWrit []int64
}{
	buf:     make([]trafficSample, minuteHistorySize*64),
	accRead: make([]int64, 64),
	accWrit: make([]int64, 64),
}

type trafficSample struct {
	readRate  int64
	writRate  int64
	connRate  int64
	connCount int32
}

// SetAdminConfigs replaces the registry with a new slice of configs.
func SetAdminConfigs(cfgs []*Config) {
	adminRegistry.mu.Lock()
	adminRegistry.configs = cfgs
	adminRegistry.mu.Unlock()
}

func getAdminConfigs() []*Config {
	adminRegistry.mu.RLock()
	defer adminRegistry.mu.RUnlock()
	return adminRegistry.configs
}

func sampleTraffic() {
	cfgs := getAdminConfigs()
	if len(cfgs) == 0 {
		return
	}
	trafficHistory.mu.Lock()
	base := trafficHistory.pos * len(cfgs)
	// ensure buffer is large enough
	need := (trafficHistory.pos + 1) * len(cfgs)
	for len(trafficHistory.buf) < need {
		trafficHistory.buf = append(trafficHistory.buf, make([]trafficSample, trafficHistorySize*len(cfgs))...)
	}
	if len(trafficHistory.buf) < need {
		// grow buffer
		newBuf := make([]trafficSample, need*2)
		copy(newBuf, trafficHistory.buf)
		trafficHistory.buf = newBuf
	}
	for i, c := range cfgs {
		if s := c.getStat(); s != nil {
			// Assign each stat server its registry index once, atomically:
			// configIndex starts at -1 and the SSE publishers rely on the
			// sentinel to suppress events before this assignment.
			s.configIndex.CompareAndSwap(-1, int32(i))
			rr, wr, cr := s.Snap()
			trafficHistory.buf[base+i] = trafficSample{
				readRate:  rr,
				writRate:  wr,
				connRate:  cr,
				connCount: atomic.LoadInt32(&s.connections),
			}
		}
	}
	trafficHistory.pos++
	if trafficHistory.pos >= trafficHistorySize {
		trafficHistory.pos = 0
		trafficHistory.filled = true
	}
	trafficHistory.mu.Unlock()

	// Aggregate into minute-level history
	minuteHistory.mu.Lock()
	// ensure accumulator arrays are large enough
	for len(minuteHistory.accRead) < len(cfgs) {
		minuteHistory.accRead = append(minuteHistory.accRead, 0)
		minuteHistory.accWrit = append(minuteHistory.accWrit, 0)
	}
	for i := range cfgs {
		trafficHistory.mu.Lock()
		bi := trafficHistory.pos
		if bi == 0 && trafficHistory.filled {
			bi = trafficHistorySize
		}
		bi = (bi - 1 + trafficHistorySize) % trafficHistorySize
		idx := bi*len(cfgs) + i
		if idx < len(trafficHistory.buf) {
			minuteHistory.accRead[i] += trafficHistory.buf[idx].readRate
			minuteHistory.accWrit[i] += trafficHistory.buf[idx].writRate
		}
		trafficHistory.mu.Unlock()
	}
	minuteHistory.tick++
	if minuteHistory.tick >= minuteInterval {
		minuteHistory.tick = 0
		base := minuteHistory.pos * len(cfgs)
		need := (minuteHistory.pos + 1) * len(cfgs)
		for len(minuteHistory.buf) < need {
			minuteHistory.buf = append(minuteHistory.buf, make([]trafficSample, minuteHistorySize*len(cfgs))...)
		}
		for i := range cfgs {
			minuteHistory.buf[base+i] = trafficSample{
				readRate: minuteHistory.accRead[i],
				writRate: minuteHistory.accWrit[i],
			}
			minuteHistory.accRead[i] = 0
			minuteHistory.accWrit[i] = 0
		}
		minuteHistory.pos++
		if minuteHistory.pos >= minuteHistorySize {
			minuteHistory.pos = 0
			minuteHistory.filled = true
		}
	}
	minuteHistory.mu.Unlock()

	// emit SSE event for each config
	for i, c := range cfgs {
		ssePublishIndex("stats_updated", i, map[string]interface{}{
			"configIndex": i,
			"connections": atomic.LoadInt32(&c.getStat().connections),
			"readRate":    trafficHistory.buf[base+i].readRate,
			"writRate":    trafficHistory.buf[base+i].writRate,
		})
	}
}

// StartAdminServer starts the admin HTTP server on addr. When token is
// non-empty, /api/ endpoints require it (Authorization: Bearer, X-Admin-Token
// header, or ?token=). The static UI stays open so the login page can prompt.
func StartAdminServer(addr string, token string) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/configs", handleListConfigs)
	mux.HandleFunc("GET /api/configs/{index}", handleGetConfig)
	mux.HandleFunc("GET /api/configs/{index}/config", handleGetConfigRaw)
	mux.HandleFunc("PUT /api/configs/{index}/disable", handleToggleConfig)
	mux.HandleFunc("PUT /api/configs/{index}/autoproxy", handleToggleAutoProxy)
	mux.HandleFunc("PUT /api/configs/{index}/loghttp", handleToggleLogHTTP)
	mux.HandleFunc("PUT /api/configs/{index}/backends/{nickname}/disable", handleToggleBackend)
	mux.HandleFunc("GET /api/stats", handleAggregateStats)
	mux.HandleFunc("GET /api/traffic", handleTrafficHistory)
	mux.HandleFunc("GET /api/configs/{index}/connections", handleActiveConnections)
	mux.HandleFunc("GET /api/configs/{index}/connections/history", handleConnectionHistory)
	mux.HandleFunc("GET /api/configs/{index}/connection/{id}", handleGetConnection)
	mux.HandleFunc("PUT /api/configs/{index}/settings", handleUpdateSettings)
	mux.HandleFunc("GET /api/virtual", handleListVirtual)
	mux.HandleFunc("PUT /api/configs/{index}/backends/{nickname}", handleUpdateBackend)
	mux.HandleFunc("DELETE /api/configs/{index}/backends/{nickname}", handleDeleteBackend)
	mux.HandleFunc("POST /api/configs/{index}/backends", handleAddBackend)
	mux.HandleFunc("GET /api/configs/{index}/active", handleGetActiveBackend)
	mux.HandleFunc("PUT /api/configs/{index}/active", handleSetActiveBackend)
	mux.HandleFunc("GET /api/configs/{index}/rejects", handleRejectCounters)
	mux.HandleFunc("GET /api/configs/{index}/targets", handleTargets)
	mux.HandleFunc("GET /api/configs/{index}/targets/top", handleTargetsTop)
	mux.HandleFunc("GET /api/configs/{index}/connections/top", handleConnectionsTop)
	mux.HandleFunc("GET /api/configs/{index}/connections/distribution", handleConnDistribution)
	mux.HandleFunc("GET /api/traffic/minutes", handleMinuteHistory)
	mux.HandleFunc("GET /api/process", handleProcessHistory)
	mux.HandleFunc("GET /api/process/minutes", handleProcessMinuteHistory)
	mux.HandleFunc("GET /api/configs/{index}/connection/{id}/events", handleConnSSE)
	mux.HandleFunc("GET /api/events", handleSSE)

	mux.Handle("GET /", http.FileServer(http.FS(adminUI)))

	StartProcessMonitor()

	// background traffic sampling every 2s
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			sampleTraffic()
		}
	}()

	// Refuse a tokenless admin on a non-loopback address: unlike the
	// built-in admin:6666 service (which enforces isLocalSource), the webui
	// can reconfigure the whole proxy. SS_ADMIN_ALLOW_REMOTE=1 opts out for
	// deployments that deliberately want an open LAN admin.
	if token == "" && !adminAddrIsLoopbackOnly(addr) && os.Getenv("SS_ADMIN_ALLOW_REMOTE") != "1" {
		log.Fatalf("admin webui %q has no admintoken; refusing to expose it beyond loopback (set admintoken, bind to 127.0.0.1, or set SS_ADMIN_ALLOW_REMOTE=1 to override)", addr)
	}

	go func() {
		log.Printf("admin webui listening on %s", addr)
		if token == "" {
			log.Printf("warning: admin webui has no admintoken; anyone who can reach %s can reconfigure the proxy", addr)
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if !strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("X-Frame-Options", "DENY")
			}
			if token == "" && !adminHostAllowed(r.Host) {
				// DNS-rebinding guard for the tokenless setup; see
				// adminHostAllowed.
				http.Error(w, "forbidden host", http.StatusForbidden)
				return
			}
			if token != "" && strings.HasPrefix(r.URL.Path, "/api/") && !checkAdminToken(r, token) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			mux.ServeHTTP(w, r)
		})
		// Bound header reads and idle conns; no global WriteTimeout — SSE
		// handlers stream indefinitely and set per-write deadlines instead.
		srv := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("admin server error: %v", err)
		}
	}()
}

// adminAddrIsLoopbackOnly reports whether the listen address restricts the
// admin surface to the local machine.
func adminAddrIsLoopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "*" || host == "0.0.0.0" || host == "::" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// checkAdminToken validates the admin token in constant time.
//
// The ?token= query parameter exists only because EventSource cannot send
// headers (the SSE dashboard needs it). Unlike the header forms it puts the
// token in the URL, where proxies and access logs may retain it — prefer the
// header forms for everything else.
func checkAdminToken(r *http.Request, token string) bool {
	candidates := make([]string, 0, 3)
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		candidates = append(candidates, strings.TrimPrefix(auth, "Bearer "))
	}
	if h := r.Header.Get("X-Admin-Token"); h != "" {
		candidates = append(candidates, h)
	}
	if q := r.URL.Query().Get("token"); q != "" {
		candidates = append(candidates, q)
	}
	for _, c := range candidates {
		if subtle.ConstantTimeCompare([]byte(c), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

type configSummary struct {
	Index            int                    `json:"index"`
	Nickname         string                 `json:"nickname"`
	Type             string                 `json:"type"`
	LocalAddr        string                 `json:"localaddr"`
	RemoteAddr       string                 `json:"remoteaddr"`
	Disabled         bool                   `json:"disabled"`
	Connections      int32                  `json:"connections"`
	TotalConnections int64                  `json:"totalConnections"`
	PeakConnections  int32                  `json:"peakConnections"`
	ConnRate         int64                  `json:"connRate"`
	TotalReadBytes   int64                  `json:"totalReadBytes"`
	TotalWritBytes   int64                  `json:"totalWritBytes"`
	ReadRate         int64                  `json:"readRate"`
	WritRate         int64                  `json:"writRate"`
	AutoProxy        bool                   `json:"autoproxy"`
	LogHTTP          bool                   `json:"loghttp"`
	Method           string                 `json:"method"`
	ActiveBackend    string                 `json:"active,omitempty"`
	MethodStats      map[string]*methodStat `json:"methodStats,omitempty"`
	Backends         []backendSummary       `json:"backends"`
}

type backendSummary struct {
	Nickname         string  `json:"nickname"`
	RemoteAddr       string  `json:"remoteaddr"`
	Disabled         bool    `json:"disabled"`
	Method           string  `json:"method"`
	Target           string  `json:"target,omitempty"`
	Forward          string  `json:"forward,omitempty"`
	Connections      int32   `json:"connections"`
	TotalReadBytes   int64   `json:"totalReadBytes"`
	TotalWritBytes   int64   `json:"totalWritBytes"`
	DialSuccess      int64   `json:"dialSuccess,omitempty"`
	DialFail         int64   `json:"dialFail,omitempty"`
	DialTimeout      int64   `json:"dialTimeout,omitempty"`
	DialAvgLatencyMs float64 `json:"dialAvgLatencyMs,omitempty"`
	HealthStatus     string  `json:"healthStatus,omitempty"`
}

type aggregateStats struct {
	NumConfigs       int   `json:"numConfigs"`
	TotalConnections int32 `json:"totalConnections"`
	TotalReadBytes   int64 `json:"totalReadBytes"`
	TotalWritBytes   int64 `json:"totalWritBytes"`
	UptimeSeconds    int64 `json:"uptimeSeconds"`
}

func buildConfigSummary(i int, c *Config, numConfigs int) configSummary {
	// Resolve ActiveBackend before taking the lock: the lazy snapshot
	// publish inside GetActiveBackend also needs adminWriteMu.
	active := c.GetActiveBackend()

	// Serialize with the admin writers so no field read below can race a
	// settings or backend update.
	adminWriteMu.Lock()
	defer adminWriteMu.Unlock()

	s := configSummary{
		Index:         i,
		Nickname:      c.Nickname,
		Type:          c.Type,
		LocalAddr:     c.Localaddr,
		RemoteAddr:    c.Remoteaddr,
		Disabled:      c.isDisabled(),
		AutoProxy:     c.AutoProxy,
		LogHTTP:       c.LogHTTP,
		Method:        c.Method,
		ActiveBackend: active,
	}
	if c.getStat() != nil {
		s.Connections = atomic.LoadInt32(&c.getStat().connections)
		s.TotalConnections = atomic.LoadInt64(&c.getStat().totalConnections)
		s.PeakConnections = atomic.LoadInt32(&c.getStat().peakConnections)
		s.TotalReadBytes = atomic.LoadInt64(&c.getStat().totalReadBytes)
		s.TotalWritBytes = atomic.LoadInt64(&c.getStat().totalWritBytes)
	}
	// read latest rates from traffic history
	trafficHistory.mu.Lock()
	if trafficHistory.pos > 0 || trafficHistory.filled {
		lastIdx := trafficHistory.pos - 1
		if lastIdx < 0 {
			lastIdx = trafficHistorySize - 1
		}
		base := lastIdx * numConfigs
		if base+i < len(trafficHistory.buf) {
			ts := trafficHistory.buf[base+i]
			s.ReadRate = ts.readRate
			s.WritRate = ts.writRate
			s.ConnRate = ts.connRate
		}
	}
	trafficHistory.mu.Unlock()
	if c.getStat() != nil {
		s.MethodStats = c.getStat().getMethodStats()
	}
	for _, b := range c.SnapshotBackends() {
		bs := backendSummary{
			Nickname:   b.Nickname,
			RemoteAddr: b.Remoteaddr,
			Disabled:   b.isDisabled(),
			Method:     b.Method,
			Target:     b.Target,
			Forward:    b.Forward,
		}
		if b.getStat() != nil {
			bs.Connections = atomic.LoadInt32(&b.getStat().connections)
			bs.TotalReadBytes = atomic.LoadInt64(&b.getStat().totalReadBytes)
			bs.TotalWritBytes = atomic.LoadInt64(&b.getStat().totalWritBytes)
		}
		if b.initRuntime().dialHealth != nil {
			bs.DialSuccess, bs.DialFail, bs.DialTimeout, bs.DialAvgLatencyMs = b.initRuntime().dialHealth.snapshot()
			total := bs.DialSuccess + bs.DialFail
			if total == 0 {
				bs.HealthStatus = "unknown"
			} else if bs.DialFail == 0 {
				bs.HealthStatus = "green"
			} else if float64(bs.DialFail)/float64(total) < 0.1 {
				bs.HealthStatus = "yellow"
			} else {
				bs.HealthStatus = "red"
			}
		}
		s.Backends = append(s.Backends, bs)
	}
	return s
}

func handleListConfigs(w http.ResponseWriter, r *http.Request) {
	cfgs := getAdminConfigs()
	summaries := make([]configSummary, len(cfgs))
	for i, c := range cfgs {
		summaries[i] = buildConfigSummary(i, c, len(cfgs))
	}
	writeJSON(w, summaries)
}

func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	writeJSON(w, buildConfigSummary(idx, cfgs[idx], len(cfgs)))
}

func handleGetConfigRaw(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	c := cfgs[idx]
	// build a masked version for safe display
	type safeConfig struct {
		Nickname        string   `json:"nickname"`
		Type            string   `json:"type"`
		LocalAddr       string   `json:"localaddr"`
		LocalAddrs      []string `json:"localaddrs,omitempty"`
		RemoteAddr      string   `json:"remoteaddr"`
		Method          string   `json:"method"`
		Password        string   `json:"password"`
		UDPRelay        bool     `json:"udprelay"`
		Verbose         bool     `json:"verbose"`
		Debug           bool     `json:"debug"`
		Safe            bool     `json:"safe"`
		Timeout         int      `json:"timeout"`
		Obfs            bool     `json:"obfs"`
		ObfsMethod      string   `json:"obfsmethod,omitempty"`
		AutoProxy       bool     `json:"autoproxy"`
		LogHTTP         bool     `json:"loghttp"`
		SSProxy         bool     `json:"ssproxy"`
		AllowHTTP       bool     `json:"allow_http"`
		SecureOrigin    bool     `json:"secure_origin"`
		MITM            bool     `json:"mitm"`
		Direct          bool     `json:"direct"`
		PreferIPv4      bool     `json:"prefer_ipv4"`
		NoIPv4          bool     `json:"no_ipv4"`
		NoIPv6          bool     `json:"no_ipv6"`
		LocalResolve    bool     `json:"local_resolve"`
		IPSelect        string   `json:"ipselect"`
		IPSelectDelayMs int      `json:"ipselect_delay_ms"`
		Limit           int      `json:"limit"`
		LimitPerConn    int      `json:"limitperconn"`
		AdminAddr       string   `json:"adminaddr,omitempty"`
		BackendCount    int      `json:"backendCount"`
	}
	// Build the value copy under the same lock the admin writers use, so a
	// concurrent settings/backend update cannot tear a string or slice
	// header while it is being read.
	adminWriteMu.Lock()
	sc := safeConfig{
		Nickname:        c.Nickname,
		Type:            c.Type,
		LocalAddr:       c.Localaddr,
		LocalAddrs:      c.Localaddrs,
		RemoteAddr:      c.Remoteaddr,
		Method:          c.Method,
		Password:        maskPassword(c.Password),
		UDPRelay:        c.UDPRelay,
		Verbose:         c.Verbose,
		Debug:           c.Debug,
		Safe:            c.Safe,
		Timeout:         c.Timeout,
		Obfs:            c.Obfs,
		ObfsMethod:      c.ObfsMethod,
		AutoProxy:       c.AutoProxy,
		LogHTTP:         c.LogHTTP,
		SSProxy:         c.SSProxy,
		AllowHTTP:       c.AllowHTTP,
		SecureOrigin:    c.SecureOrigin,
		MITM:            c.MITM,
		Direct:          c.Direct,
		PreferIPv4:      c.PreferIPv4,
		NoIPv4:          c.NoIPv4,
		NoIPv6:          c.NoIPv6,
		LocalResolve:    c.LocalResolve,
		IPSelect:        c.IPSelect,
		IPSelectDelayMs: c.IPSelectDelayMs,
		Limit:           c.Limit,
		LimitPerConn:    c.LimitPerConn,
		AdminAddr:       c.AdminAddr,
		BackendCount:    len(c.SnapshotBackends()),
	}
	adminWriteMu.Unlock()
	writeJSON(w, sc)
}

func maskPassword(p string) string {
	if len(p) <= 4 {
		return "****"
	}
	return p[:2] + "****" + p[len(p)-2:]
}

func handleToggleConfig(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var body struct{ Disabled bool }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	adminWriteMu.Lock()
	cfgs[idx].setDisabled(body.Disabled)
	adminWriteMu.Unlock()
	ssePublishIndex("config_status_changed", idx, map[string]any{
		"configIndex": idx,
		"disabled":    body.Disabled,
	})
	writeJSON(w, map[string]string{"status": "ok"})
}

func handleToggleAutoProxy(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var body struct{ Enabled bool }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	adminWriteMu.Lock()
	cfgs[idx].AutoProxy = body.Enabled
	adminWriteMu.Unlock()
	writeJSON(w, map[string]string{"status": "ok"})
}

func handleToggleLogHTTP(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var body struct{ Enabled bool }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	adminWriteMu.Lock()
	cfgs[idx].LogHTTP = body.Enabled
	adminWriteMu.Unlock()
	writeJSON(w, map[string]string{"status": "ok"})
}

func handleToggleBackend(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	nickname := r.PathValue("nickname")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	var body struct{ Disabled bool }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	for _, b := range cfgs[idx].SnapshotBackends() {
		if b.Nickname == nickname {
			adminWriteMu.Lock()
			b.setDisabled(body.Disabled)
			adminWriteMu.Unlock()
			ssePublishIndex("backend_status_changed", idx, map[string]any{
				"configIndex": idx,
				"nickname":    nickname,
				"disabled":    body.Disabled,
			})
			writeJSON(w, map[string]string{"status": "ok"})
			return
		}
	}
	http.Error(w, "backend not found", http.StatusNotFound)
}

func handleAggregateStats(w http.ResponseWriter, r *http.Request) {
	cfgs := getAdminConfigs()
	s := aggregateStats{
		NumConfigs:    len(cfgs),
		UptimeSeconds: int64(time.Since(adminStartTime).Seconds()),
	}
	for _, c := range cfgs {
		if c.getStat() != nil {
			s.TotalConnections += atomic.LoadInt32(&c.getStat().connections)
			s.TotalReadBytes += atomic.LoadInt64(&c.getStat().totalReadBytes)
			s.TotalWritBytes += atomic.LoadInt64(&c.getStat().totalWritBytes)
		}
	}
	writeJSON(w, s)
}

func handleTrafficHistory(w http.ResponseWriter, r *http.Request) {
	cfgs := getAdminConfigs()
	if len(cfgs) == 0 {
		writeJSON(w, []any{})
		return
	}
	trafficHistory.mu.Lock()
	defer trafficHistory.mu.Unlock()

	// return all samples for each config as a 2D array [configIndex][sampleIndex]
	type sample struct {
		ReadRate  int64 `json:"readRate"`
		WritRate  int64 `json:"writRate"`
		ConnRate  int64 `json:"connRate"`
		ConnCount int32 `json:"connCount"`
	}

	size := trafficHistorySize
	if !trafficHistory.filled {
		size = trafficHistory.pos
	}

	result := make([][]sample, len(cfgs))
	for ci := range cfgs {
		result[ci] = make([]sample, size)
		for si := 0; si < size; si++ {
			// read in chronological order: oldest first
			idx := si
			if trafficHistory.filled {
				idx = (trafficHistory.pos + si) % trafficHistorySize
			}
			base := idx * len(cfgs)
			if base+ci < len(trafficHistory.buf) {
				ts := trafficHistory.buf[base+ci]
				result[ci][si] = sample{
					ReadRate:  ts.readRate,
					WritRate:  ts.writRate,
					ConnRate:  ts.connRate,
					ConnCount: ts.connCount,
				}
			}
		}
	}
	writeJSON(w, result)
}

func handleProcessHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getProcessHistory())
}

func handleProcessMinuteHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getProcessMinuteHistory())
}

func handleMinuteHistory(w http.ResponseWriter, r *http.Request) {
	cfgs := getAdminConfigs()
	if len(cfgs) == 0 {
		writeJSON(w, []any{})
		return
	}
	minuteHistory.mu.Lock()
	defer minuteHistory.mu.Unlock()

	type sample struct {
		ReadRate  int64 `json:"readRate"`
		WritRate  int64 `json:"writRate"`
		ConnRate  int64 `json:"connRate"`
		ConnCount int32 `json:"connCount"`
	}

	size := minuteHistorySize
	if !minuteHistory.filled {
		size = minuteHistory.pos
	}

	result := make([][]sample, len(cfgs))
	for ci := range cfgs {
		result[ci] = make([]sample, size)
		for si := 0; si < size; si++ {
			idx := si
			if minuteHistory.filled {
				idx = (minuteHistory.pos + si) % minuteHistorySize
			}
			base := idx * len(cfgs)
			if base+ci < len(minuteHistory.buf) {
				ts := minuteHistory.buf[base+ci]
				result[ci][si] = sample{
					ReadRate: ts.readRate,
					WritRate: ts.writRate,
				}
			}
		}
	}
	writeJSON(w, result)
}

func handleActiveConnections(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	c := cfgs[idx]
	if c.getStat() == nil || c.getStat().tracker == nil {
		writeJSON(w, []any{})
		return
	}
	conns := c.getStat().tracker.Active()
	q := r.URL.Query()
	if search := q.Get("q"); search != "" {
		conns = filterConns(conns, search)
	}
	sortConns(conns, q.Get("sort"), q.Get("order"))
	writeJSON(w, conns)
}

func handleGetConnection(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idStr := r.PathValue("id")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cid, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	c := cfgs[idx]
	if c.getStat() == nil || c.getStat().tracker == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// search active first, then history
	for _, rec := range c.getStat().tracker.Active() {
		if rec.ID == cid {
			writeJSON(w, rec)
			return
		}
	}
	for _, rec := range c.getStat().tracker.History() {
		if rec.ID == cid {
			writeJSON(w, rec)
			return
		}
	}
	http.Error(w, "connection not found", http.StatusNotFound)
}

func handleConnectionHistory(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	c := cfgs[idx]
	if c.getStat() == nil || c.getStat().tracker == nil {
		writeJSON(w, []any{})
		return
	}
	conns := c.getStat().tracker.History()
	q := r.URL.Query()
	if search := q.Get("q"); search != "" {
		conns = filterConns(conns, search)
	}
	sortConns(conns, q.Get("sort"), q.Get("order"))
	writeJSON(w, conns)
}

func handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	c := cfgs[idx]

	if !requireJSONContentType(w, r) {
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	adminWriteMu.Lock()
	defer adminWriteMu.Unlock()
	applied := []string{}
	for key, val := range body {
		ok := false
		switch key {
		case "verbose":
			if v, e := toBool(val); e == nil {
				c.Verbose = v
				ok = true
			}
		case "debug":
			if v, e := toBool(val); e == nil {
				c.Debug = v
				ok = true
			}
		case "safe":
			if v, e := toBool(val); e == nil {
				c.Safe = v
				ok = true
			}
		case "direct":
			if v, e := toBool(val); e == nil {
				c.Direct = v
				ok = true
			}
		case "ssproxy":
			if v, e := toBool(val); e == nil {
				c.SSProxy = v
				ok = true
			}
		case "disable":
			if v, e := toBool(val); e == nil {
				c.setDisabled(v)
				ssePublishIndex("config_status_changed", idx, map[string]any{
					"configIndex": idx,
					"disabled":    v,
				})
				ok = true
			}
		case "mitm":
			if v, e := toBool(val); e == nil {
				c.MITM = v
				ok = true
			}
		case "allow_http":
			if v, e := toBool(val); e == nil {
				c.AllowHTTP = v
				ok = true
			}
		case "secure_origin":
			if v, e := toBool(val); e == nil {
				c.SecureOrigin = v
				ok = true
			}
		case "prefer_ipv4":
			if v, e := toBool(val); e == nil {
				c.PreferIPv4 = v
				for _, b := range c.SnapshotBackends() {
					b.PreferIPv4 = v
				}
				ok = true
			}
		case "no_ipv4":
			if v, e := toBool(val); e == nil {
				c.NoIPv4 = v
				for _, b := range c.SnapshotBackends() {
					b.NoIPv4 = v
				}
				ok = true
			}
		case "no_ipv6":
			if v, e := toBool(val); e == nil {
				c.NoIPv6 = v
				for _, b := range c.SnapshotBackends() {
					b.NoIPv6 = v
				}
				ok = true
			}
		case "local_resolve":
			if v, e := toBool(val); e == nil {
				c.LocalResolve = v
				for _, b := range c.SnapshotBackends() {
					b.LocalResolve = v
				}
				ok = true
			}
		case "ipselect":
			if v, e := toString(val); e == nil {
				switch v {
				case ipSelectSmart, ipSelectRace, ipSelectOff:
					// Deliberately overrides per-backend values, matching the
					// existing timeout settings behavior.
					c.IPSelect = v
					for _, b := range c.SnapshotBackends() {
						b.IPSelect = v
					}
					ok = true
				}
			}
		case "ipselect_delay_ms":
			if v, e := toInt(val); e == nil && v >= 0 {
				// 0 means "reset to default"; store the normalized value so
				// GET /config reflects what dialIPSelect actually uses.
				if v == 0 {
					v = defaultIPSelectDelayMs
				} else if v > maxIPSelectDelayMs {
					v = maxIPSelectDelayMs
				}
				c.IPSelectDelayMs = v
				for _, b := range c.SnapshotBackends() {
					b.IPSelectDelayMs = v
				}
				ok = true
			}
		case "udprelay":
			if v, e := toBool(val); e == nil {
				c.UDPRelay = v
				ok = true
			}
		case "autoproxy":
			if v, e := toBool(val); e == nil {
				c.AutoProxy = v
				ok = true
			}
		case "loghttp":
			if v, e := toBool(val); e == nil {
				c.LogHTTP = v
				ok = true
			}
		case "limit":
			if v, e := toInt(val); e == nil && v >= 0 {
				c.Limit = v
				// update all limiters
				for _, l := range c.getLimiters() {
					l.SetLimit(v)
				}
				// also update backend limiters
				for _, b := range c.SnapshotBackends() {
					for _, l := range b.getLimiters() {
						l.SetLimit(v)
					}
				}
				ok = true
			}
		case "limitperconn":
			if v, e := toInt(val); e == nil && v >= 0 {
				c.LimitPerConn = v
				for _, b := range c.SnapshotBackends() {
					b.LimitPerConn = v
				}
				ok = true
			}
		case "timeout":
			if v, e := toInt(val); e == nil && v > 0 && v <= maxTimeoutSeconds {
				c.Timeout = v
				for _, b := range c.SnapshotBackends() {
					b.Timeout = v
				}
				ok = true
			}
		}
		if ok {
			applied = append(applied, key)
		}
	}
	// Republish the dial-policy snapshots so per-dial atomic readers see the
	// new values: the parent plus every backend the loop may have touched.
	c.publishDialPolicy()
	for _, b := range c.SnapshotBackends() {
		b.publishDialPolicy()
	}
	writeJSON(w, map[string]any{"status": "ok", "applied": applied})
}

func toBool(v any) (bool, error) {
	switch val := v.(type) {
	case bool:
		return val, nil
	case float64:
		return val != 0, nil
	case string:
		return val == "true" || val == "1", nil
	}
	return false, strconv.ErrSyntax
}

// maxSafeInt bounds toInt results: float64→int conversion of values beyond
// the float64-exact range is implementation-defined (arm64 saturates to
// MaxInt64, letting e.g. {"timeout": 1e308} sail past "> 0" checks), and
// downstream Duration arithmetic overflows far below even that.
//
// Two constants because one untyped constant cannot serve both branches:
// compared against float64 it is exactly representable, but 2^53 overflows
// 32-bit int, so the int branch compares through int64 (where the check is
// vacuous on 32-bit platforms — int already maxes far below it).
const (
	maxSafeIntF  = float64(1 << 53)
	maxSafeInt64 = int64(1) << 53
)

// maxTimeoutSeconds caps runtime timeout edits; larger values overflow
// time.Duration arithmetic at the use sites.
const maxTimeoutSeconds = 365 * 24 * 60 * 60

// Cap on concurrent SSE subscribers: each holds a goroutine and a 64-slot
// channel for its lifetime, and a zero-window client can otherwise pin
// both until it disconnects.
const maxSSEClients = 64

func toInt(v any) (int, error) {
	switch val := v.(type) {
	case float64:
		if math.IsNaN(val) || val > maxSafeIntF || val < -maxSafeIntF {
			return 0, strconv.ErrRange
		}
		return int(val), nil
	case string:
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0, err
		}
		if int64(n) > maxSafeInt64 || int64(n) < -maxSafeInt64 {
			return 0, strconv.ErrRange
		}
		return n, nil
	}
	return 0, strconv.ErrSyntax
}

// --- Backend CRUD ---

func findBackend(c *Config, nickname string) *Config {
	for _, b := range c.SnapshotBackends() {
		if b.Nickname == nickname {
			return b
		}
	}
	return nil
}

func handleUpdateBackend(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	nickname := r.PathValue("nickname")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	parent := cfgs[idx]
	b := findBackend(parent, nickname)
	if b == nil {
		http.Error(w, "backend not found", http.StatusNotFound)
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}

	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	// Hold adminWriteMu (like handleAddBackend) so these edits are mutually
	// exclusive with every locked reader of live fields — the admin summary
	// handlers read Method/Target/Forward under this lock, and a torn
	// string-header read would be memory-unsafe. backendsLock keeps the
	// backend slice consistent with add/delete; lock order matches
	// handleAddBackend (adminWriteMu first).
	adminWriteMu.Lock()
	defer adminWriteMu.Unlock()
	parent.initRuntime().backendsLock.Lock()
	defer parent.initRuntime().backendsLock.Unlock()
	applied := []string{}
	for key, val := range body {
		ok := false
		switch key {
		case "remoteaddr":
			if v, e := toString(val); e == nil && v != "" {
				b.Remoteaddr = v
				ok = true
			}
		case "method":
			if v, e := toString(val); e == nil && v != "" {
				b.Method = v
				b.Ivlen = 0
				CheckBasicConfig(b)
				ok = true
			}
		case "password":
			if v, e := toString(val); e == nil && v != "" {
				b.Password = v
				b.Ivlen = 0
				CheckBasicConfig(b)
				ok = true
			}
		case "ipselect":
			if v, e := toString(val); e == nil {
				switch v {
				case ipSelectSmart, ipSelectRace, ipSelectOff:
					b.IPSelect = v
					ok = true
				}
			}
		case "ipselect_delay_ms":
			if v, e := toInt(val); e == nil && v >= 0 {
				// Backend-level 0 means "inherit the parent value", matching
				// CheckConfig backend inheritance.
				if v == 0 {
					v = parent.IPSelectDelayMs
					if v <= 0 {
						v = defaultIPSelectDelayMs
					}
				} else if v > maxIPSelectDelayMs {
					v = maxIPSelectDelayMs
				}
				b.IPSelectDelayMs = v
				ok = true
			}
		}
		if ok {
			applied = append(applied, key)
		}
	}
	b.publishDialPolicy()
	writeJSON(w, map[string]any{"status": "ok", "applied": applied})
}

func handleDeleteBackend(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	nickname := r.PathValue("nickname")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	c := cfgs[idx]
	removed := false
	c.initRuntime().backendsLock.Lock()
	for i, b := range c.Backends {
		if b.Nickname == nickname {
			// Do NOT call b.Close(): admin-created backends share the parent
			// config's Die channel, and closing it kills the parent's
			// listeners (RunUDPServer watches DieChan).
			c.Backends = append(c.Backends[:i], c.Backends[i+1:]...)
			removed = true
			break
		}
	}
	c.initRuntime().backendsLock.Unlock()
	if !removed {
		http.Error(w, "backend not found", http.StatusNotFound)
		return
	}
	// If the deleted backend was the switch-mode target, re-point ActiveBackend
	// at the first remaining backend (or clear it) so the switch handler does
	// not fail every subsequent connection. The pre-lock GetActiveBackend
	// call warms the snapshot so the re-check under adminWriteMu is lock-free
	// (GetActiveBackend would self-deadlock on the non-reentrant mutex if it
	// had to publish lazily while we hold it). backendsLock is released before
	// adminWriteMu is taken, so this path never nests the two locks in the
	// order opposite to handleAddBackend/handleUpdateBackend.
	if c.GetActiveBackend() == nickname {
		adminWriteMu.Lock()
		if c.GetActiveBackend() == nickname {
			backends := c.SnapshotBackends()
			if len(backends) > 0 {
				c.ActiveBackend = backends[0].Nickname
			} else {
				c.ActiveBackend = ""
			}
			c.publishActiveBackend()
		}
		adminWriteMu.Unlock()
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func handleAddBackend(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	c := cfgs[idx]

	if !requireJSONContentType(w, r) {
		return
	}
	var body struct {
		Nickname   string `json:"nickname"`
		Remoteaddr string `json:"remoteaddr"`
		Method     string `json:"method"`
		Password   string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.Nickname == "" || body.Remoteaddr == "" {
		http.Error(w, "nickname and remoteaddr are required", http.StatusBadRequest)
		return
	}
	adminWriteMu.Lock()
	defer adminWriteMu.Unlock()
	if findBackend(c, body.Nickname) != nil {
		http.Error(w, "backend with this nickname already exists", http.StatusConflict)
		return
	}

	b := &Config{
		Nickname:      body.Nickname,
		NetworkConfig: NetworkConfig{Remoteaddr: body.Remoteaddr},
		CryptoConfig:  CryptoConfig{Method: body.Method, Password: body.Password},
	}
	if b.Method == "" {
		b.Method = c.Method
	}
	if b.Password == "" {
		b.Password = c.Password
	}
	b.initRuntime().Die = c.DieChan()
	b.setStat(newStatServer())
	b.LogHTTP = c.LogHTTP
	b.Timeout = c.Timeout
	b.PreferIPv4 = c.PreferIPv4
	b.IPSelect = c.IPSelect
	b.IPSelectDelayMs = c.IPSelectDelayMs
	b.Obfs = c.Obfs
	b.ObfsHost = append([]string{}, c.ObfsHost...)
	b.setAutoProxyCtx(c.getAutoProxyCtx())
	CheckBasicConfig(b)
	b.publishDialPolicy()
	if c.LimitPerConn != 0 {
		b.LimitPerConn = c.LimitPerConn
	}
	if parentLimiters := c.getLimiters(); len(parentLimiters) != 0 {
		b.initRuntime().limiters = append(b.initRuntime().limiters, parentLimiters...)
	}
	c.initRuntime().backendsLock.Lock()
	c.Backends = append(c.Backends, b)
	newIndex := len(c.Backends) - 1
	c.initRuntime().backendsLock.Unlock()
	writeJSON(w, map[string]any{"status": "ok", "index": newIndex})
}

func toString(v any) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(val), nil
	}
	return "", strconv.ErrSyntax
}

func handleListVirtual(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, ListVirtualServices())
}

func handleGetActiveBackend(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]string{"active": cfgs[idx].GetActiveBackend()})
}

func handleSetActiveBackend(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	var body struct{ Nickname string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.Nickname == "" {
		http.Error(w, "nickname is required", http.StatusBadRequest)
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	found := false
	for _, b := range cfgs[idx].SnapshotBackends() {
		if b.Nickname == body.Nickname {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "backend not found", http.StatusNotFound)
		return
	}
	adminWriteMu.Lock()
	cfgs[idx].ActiveBackend = body.Nickname
	cfgs[idx].publishActiveBackend()
	adminWriteMu.Unlock()
	writeJSON(w, map[string]string{"status": "ok", "active": body.Nickname})
}

func handleRejectCounters(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	s := cfgs[idx].getStat()
	if s == nil {
		writeJSON(w, RejectCounters{})
		return
	}
	writeJSON(w, s.getRejectCounters())
}

func handleTargets(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	tt := cfgs[idx].GetTargetTracker()
	if tt == nil {
		writeJSON(w, []*TargetStats{})
		return
	}
	writeJSON(w, tt.All())
}

func handleTargetsTop(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	tt := cfgs[idx].GetTargetTracker()
	if tt == nil {
		writeJSON(w, []*TargetStats{})
		return
	}
	n := 10
	if v := r.URL.Query().Get("n"); v != "" {
		if p, e := strconv.Atoi(v); e == nil && p > 0 {
			n = p
		}
	}
	by := r.URL.Query().Get("by")
	if by == "connections" {
		writeJSON(w, tt.TopByConns(n))
	} else {
		writeJSON(w, tt.Top(n))
	}
}

func handleConnectionsTop(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	c := cfgs[idx]
	if c.getStat() == nil || c.getStat().tracker == nil {
		writeJSON(w, []any{})
		return
	}
	conns := c.getStat().tracker.Active()
	n := 5
	if v := r.URL.Query().Get("n"); v != "" {
		if p, e := strconv.Atoi(v); e == nil && p > 0 {
			n = p
		}
	}
	by := r.URL.Query().Get("by")
	sort.Slice(conns, func(i, j int) bool {
		switch by {
		case "writBytes":
			return atomic.LoadInt64(&conns[i].WritBytes) > atomic.LoadInt64(&conns[j].WritBytes)
		case "duration":
			di := time.Since(conns[i].StartTime)
			dj := time.Since(conns[j].StartTime)
			return di > dj
		default: // readBytes
			return atomic.LoadInt64(&conns[i].ReadBytes) > atomic.LoadInt64(&conns[j].ReadBytes)
		}
	})
	if len(conns) > n {
		conns = conns[:n]
	}
	writeJSON(w, conns)
}

type connDistribution struct {
	P50Ms  float64 `json:"p50Ms"`
	P95Ms  float64 `json:"p95Ms"`
	P99Ms  float64 `json:"p99Ms"`
	MinMs  float64 `json:"minMs"`
	MaxMs  float64 `json:"maxMs"`
	MeanMs float64 `json:"meanMs"`
	Count  int     `json:"count"`
}

func handleConnDistribution(w http.ResponseWriter, r *http.Request) {
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	c := cfgs[idx]
	if c.getStat() == nil || c.getStat().tracker == nil {
		writeJSON(w, connDistribution{})
		return
	}
	history := c.getStat().tracker.History()
	durations := make([]float64, 0, len(history))
	for _, rec := range history {
		if end, ok := rec.ended(); ok {
			durMs := float64(end.Sub(rec.StartTime).Microseconds()) / 1000.0
			if durMs >= 0 {
				durations = append(durations, durMs)
			}
		}
	}
	if len(durations) == 0 {
		writeJSON(w, connDistribution{Count: 0})
		return
	}
	sort.Float64s(durations)
	n := len(durations)
	var sum float64
	for _, d := range durations {
		sum += d
	}
	writeJSON(w, connDistribution{
		P50Ms:  durations[n*50/100],
		P95Ms:  durations[n*95/100],
		P99Ms:  durations[n*99/100],
		MinMs:  durations[0],
		MaxMs:  durations[n-1],
		MeanMs: sum / float64(n),
		Count:  n,
	})
}

func filterConns(conns []*ConnRecord, search string) []*ConnRecord {
	search = strings.ToLower(search)
	filtered := make([]*ConnRecord, 0, len(conns))
	for _, cr := range conns {
		if strings.Contains(strings.ToLower(cr.Host), search) ||
			strings.Contains(strings.ToLower(cr.DstAddr), search) ||
			strings.Contains(strings.ToLower(cr.SrcAddr), search) {
			filtered = append(filtered, cr)
		}
	}
	return filtered
}

func sortConns(conns []*ConnRecord, sortBy, order string) {
	desc := order != "asc"
	sort.Slice(conns, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "writBytes":
			less = atomic.LoadInt64(&conns[i].WritBytes) < atomic.LoadInt64(&conns[j].WritBytes)
		case "duration":
			di := time.Since(conns[i].StartTime)
			dj := time.Since(conns[j].StartTime)
			less = di < dj
		case "target":
			ti := conns[i].DstAddr
			tj := conns[j].DstAddr
			if conns[i].Host != "" {
				ti = conns[i].Host
			}
			if conns[j].Host != "" {
				tj = conns[j].Host
			}
			less = ti < tj
		case "lastActive":
			less = atomic.LoadInt64(&conns[i].LastActivity) < atomic.LoadInt64(&conns[j].LastActivity)
		default: // readBytes
			less = atomic.LoadInt64(&conns[i].ReadBytes) < atomic.LoadInt64(&conns[j].ReadBytes)
		}
		if desc {
			return !less
		}
		return less
	})
}

func handleConnSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	idStr := r.PathValue("id")
	cid, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	cfgs := getAdminConfigs()
	if idx < 0 || idx >= len(cfgs) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}
	c := cfgs[idx]
	if c.getStat() == nil || c.getStat().tracker == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Find the connection record
	var rec *ConnRecord
	for _, r := range c.getStat().tracker.Active() {
		if r.ID == cid {
			rec = r
			break
		}
	}
	if rec == nil {
		for _, r := range c.getStat().tracker.History() {
			if r.ID == cid {
				rec = r
				break
			}
		}
	}
	if rec == nil {
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	rc := http.NewResponseController(w)

	// Subscribe before snapshotting so a connection that closes during the
	// scan still delivers its "closed" event instead of leaving the stream
	// hanging until the client disconnects on its own.
	ch := connEventSubscribe(cid)
	if ch == nil {
		http.Error(w, "too many SSE clients", http.StatusServiceUnavailable)
		return
	}
	defer connEventUnsubscribe(cid, ch)

	// Send initial full data
	b, _ := json.Marshal(rec)
	rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(w, "event: init\ndata: %s\n\n", b)
	flusher.Flush()

	// If already closed, send closed and exit
	if _, ended := rec.ended(); ended {
		fmt.Fprintf(w, "event: closed\ndata: %s\n\n", b)
		flusher.Flush()
		return
	}

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if _, err := w.Write(msg); err != nil {
				return
			}
			flusher.Flush()
			// If the event is "closed", stop streaming
			if bytes.Contains(msg, []byte("event: closed")) {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

func handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	ch := sseHub.subscribe()
	if ch == nil {
		http.Error(w, "too many SSE clients", http.StatusServiceUnavailable)
		return
	}
	defer sseHub.unsubscribe(ch)
	rc := http.NewResponseController(w)
	// Bound every write: a client that stops reading (zero TCP window)
	// would otherwise pin this goroutine forever; the deadline turns that
	// into a write error and the loop exits.
	setWDeadline := func() {
		rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// initial keepalive
	setWDeadline()
	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			setWDeadline()
			if _, err := w.Write(msg); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
