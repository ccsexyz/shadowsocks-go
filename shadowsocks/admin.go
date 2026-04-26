package ss

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strconv"
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

var adminStartTime = time.Now()

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
		if c.stat != nil {
			rr, wr, cr := c.stat.Snap()
			trafficHistory.buf[base+i] = trafficSample{
				readRate:  rr,
				writRate:  wr,
				connRate:  cr,
				connCount: atomic.LoadInt32(&c.stat.connections),
			}
		}
	}
	trafficHistory.pos++
	if trafficHistory.pos >= trafficHistorySize {
		trafficHistory.pos = 0
		trafficHistory.filled = true
	}
	trafficHistory.mu.Unlock()
}

// StartAdminServer starts the admin HTTP server on addr.
func StartAdminServer(addr string) {
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
	mux.HandleFunc("PUT /api/configs/{index}/backends/{nickname}", handleUpdateBackend)
	mux.HandleFunc("DELETE /api/configs/{index}/backends/{nickname}", handleDeleteBackend)
	mux.HandleFunc("POST /api/configs/{index}/backends", handleAddBackend)

	mux.Handle("GET /", http.FileServer(http.FS(adminUI)))

	// background traffic sampling every 2s
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			sampleTraffic()
		}
	}()

	go func() {
		log.Printf("admin webui listening on %s", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("admin server error: %v", err)
		}
	}()
}

type configSummary struct {
	Index            int              `json:"index"`
	Nickname         string           `json:"nickname"`
	Type             string           `json:"type"`
	LocalAddr        string           `json:"localaddr"`
	RemoteAddr       string           `json:"remoteaddr"`
	Disabled         bool             `json:"disabled"`
	Connections      int32            `json:"connections"`
	TotalConnections int64            `json:"totalConnections"`
	PeakConnections  int32            `json:"peakConnections"`
	ConnRate         int64            `json:"connRate"`
	TotalReadBytes   int64            `json:"totalReadBytes"`
	TotalWritBytes   int64            `json:"totalWritBytes"`
	ReadRate         int64            `json:"readRate"`
	WritRate         int64            `json:"writRate"`
	AutoProxy        bool             `json:"autoproxy"`
	LogHTTP          bool             `json:"loghttp"`
	Method           string           `json:"method"`
	Backends         []backendSummary `json:"backends"`
}

type backendSummary struct {
	Nickname        string `json:"nickname"`
	RemoteAddr      string `json:"remoteaddr"`
	Disabled        bool   `json:"disabled"`
	Method          string `json:"method"`
	Connections     int32  `json:"connections"`
	TotalReadBytes  int64  `json:"totalReadBytes"`
	TotalWritBytes  int64  `json:"totalWritBytes"`
}

type aggregateStats struct {
	NumConfigs        int   `json:"numConfigs"`
	TotalConnections  int32 `json:"totalConnections"`
	TotalReadBytes    int64 `json:"totalReadBytes"`
	TotalWritBytes    int64 `json:"totalWritBytes"`
	UptimeSeconds     int64 `json:"uptimeSeconds"`
}

func buildConfigSummary(i int, c *Config, numConfigs int) configSummary {
	s := configSummary{
		Index:      i,
		Nickname:   c.Nickname,
		Type:       c.Type,
		LocalAddr:  c.Localaddr,
		RemoteAddr: c.Remoteaddr,
		Disabled:   c.disable,
		AutoProxy:  c.AutoProxy,
		LogHTTP:    c.LogHTTP,
		Method:     c.Method,
	}
	if c.stat != nil {
		s.Connections = atomic.LoadInt32(&c.stat.connections)
		s.TotalConnections = atomic.LoadInt64(&c.stat.totalConnections)
		s.PeakConnections = atomic.LoadInt32(&c.stat.peakConnections)
		s.TotalReadBytes = atomic.LoadInt64(&c.stat.totalReadBytes)
		s.TotalWritBytes = atomic.LoadInt64(&c.stat.totalWritBytes)
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
	for _, b := range c.Backends {
		bs := backendSummary{
			Nickname:   b.Nickname,
			RemoteAddr: b.Remoteaddr,
			Disabled:   b.disable,
			Method:     b.Method,
		}
		if b.stat != nil {
			bs.Connections = atomic.LoadInt32(&b.stat.connections)
			bs.TotalReadBytes = atomic.LoadInt64(&b.stat.totalReadBytes)
			bs.TotalWritBytes = atomic.LoadInt64(&b.stat.totalWritBytes)
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
		Nickname       string   `json:"nickname"`
		Type           string   `json:"type"`
		LocalAddr      string   `json:"localaddr"`
		LocalAddrs     []string `json:"localaddrs,omitempty"`
		RemoteAddr     string   `json:"remoteaddr"`
		Method         string   `json:"method"`
		Password       string   `json:"password"`
		UDPRelay       bool     `json:"udprelay"`
		Verbose        bool     `json:"verbose"`
		Debug          bool     `json:"debug"`
		Safe           bool     `json:"safe"`
		Timeout        int      `json:"timeout"`
		Obfs           bool     `json:"obfs"`
		ObfsMethod     string   `json:"obfsmethod,omitempty"`
		AutoProxy      bool     `json:"autoproxy"`
		LogHTTP        bool     `json:"loghttp"`
		SSProxy        bool     `json:"ssproxy"`
		AllowHTTP      bool     `json:"allow_http"`
		SecureOrigin   bool     `json:"secure_origin"`
		MITM           bool     `json:"mitm"`
		Direct         bool     `json:"direct"`
		PreferIPv4     bool     `json:"prefer_ipv4"`
		NoIPv4         bool     `json:"no_ipv4"`
		NoIPv6         bool     `json:"no_ipv6"`
		LocalResolve   bool     `json:"local_resolve"`
		Limit          int      `json:"limit"`
		LimitPerConn   int      `json:"limitperconn"`
		DataShard      int      `json:"datashard"`
		ParityShard    int      `json:"parityshard"`
		AdminAddr      string   `json:"adminaddr,omitempty"`
		BackendCount   int      `json:"backendCount"`
	}
	sc := safeConfig{
		Nickname:     c.Nickname,
		Type:         c.Type,
		LocalAddr:    c.Localaddr,
		LocalAddrs:   c.Localaddrs,
		RemoteAddr:   c.Remoteaddr,
		Method:       c.Method,
		Password:     maskPassword(c.Password),
		UDPRelay:     c.UDPRelay,
		Verbose:      c.Verbose,
		Debug:        c.Debug,
		Safe:         c.Safe,
		Timeout:      c.Timeout,
		Obfs:         c.Obfs,
		ObfsMethod:   c.ObfsMethod,
		AutoProxy:    c.AutoProxy,
		LogHTTP:      c.LogHTTP,
		SSProxy:      c.SSProxy,
		AllowHTTP:    c.AllowHTTP,
		SecureOrigin: c.SecureOrigin,
		MITM:         c.MITM,
		Direct:       c.Direct,
		PreferIPv4:   c.PreferIPv4,
		NoIPv4:       c.NoIPv4,
		NoIPv6:       c.NoIPv6,
		LocalResolve: c.LocalResolve,
		Limit:        c.Limit,
		LimitPerConn: c.LimitPerConn,
		DataShard:    c.DataShard,
		ParityShard:  c.ParityShard,
		AdminAddr:    c.AdminAddr,
		BackendCount: len(c.Backends),
	}
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
	var body struct{ Disabled bool }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	cfgs[idx].disable = body.Disabled
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
	var body struct{ Enabled bool }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	cfgs[idx].AutoProxy = body.Enabled
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
	var body struct{ Enabled bool }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	cfgs[idx].LogHTTP = body.Enabled
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
	for _, b := range cfgs[idx].Backends {
		if b.Nickname == nickname {
			b.disable = body.Disabled
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
		if c.stat != nil {
			s.TotalConnections += atomic.LoadInt32(&c.stat.connections)
			s.TotalReadBytes += atomic.LoadInt64(&c.stat.totalReadBytes)
			s.TotalWritBytes += atomic.LoadInt64(&c.stat.totalWritBytes)
		}
	}
	writeJSON(w, s)
}

func handleTrafficHistory(w http.ResponseWriter, r *http.Request) {
	cfgs := getAdminConfigs()
	if len(cfgs) == 0 {
		writeJSON(w, []interface{}{})
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
	if c.stat == nil || c.stat.tracker == nil {
		writeJSON(w, []interface{}{})
		return
	}
	writeJSON(w, c.stat.tracker.Active())
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
	if c.stat == nil || c.stat.tracker == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// search active first, then history
	for _, rec := range c.stat.tracker.Active() {
		if rec.ID == cid {
			writeJSON(w, rec)
			return
		}
	}
	for _, rec := range c.stat.tracker.History() {
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
	if c.stat == nil || c.stat.tracker == nil {
		writeJSON(w, []interface{}{})
		return
	}
	writeJSON(w, c.stat.tracker.History())
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

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

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
				ok = true
			}
		case "no_ipv4":
			if v, e := toBool(val); e == nil {
				c.NoIPv4 = v
				ok = true
			}
		case "no_ipv6":
			if v, e := toBool(val); e == nil {
				c.NoIPv6 = v
				ok = true
			}
		case "local_resolve":
			if v, e := toBool(val); e == nil {
				c.LocalResolve = v
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
				for _, l := range c.limiters {
					l.SetLimit(v)
				}
				// also update backend limiters
				for _, b := range c.Backends {
					for _, l := range b.limiters {
						l.SetLimit(v)
					}
				}
				ok = true
			}
		case "limitperconn":
			if v, e := toInt(val); e == nil && v >= 0 {
				c.LimitPerConn = v
				for _, b := range c.Backends {
					b.LimitPerConn = v
				}
				ok = true
			}
		case "timeout":
			if v, e := toInt(val); e == nil && v > 0 {
				c.Timeout = v
				for _, b := range c.Backends {
					b.Timeout = v
				}
				ok = true
			}
		}
		if ok {
			applied = append(applied, key)
		}
	}
	writeJSON(w, map[string]interface{}{"status": "ok", "applied": applied})
}

func toBool(v interface{}) (bool, error) {
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

func toInt(v interface{}) (int, error) {
	switch val := v.(type) {
	case float64:
		return int(val), nil
	case string:
		return strconv.Atoi(val)
	}
	return 0, strconv.ErrSyntax
}

// --- Backend CRUD ---

func findBackend(c *Config, nickname string) *Config {
	for _, b := range c.Backends {
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
	b := findBackend(cfgs[idx], nickname)
	if b == nil {
		http.Error(w, "backend not found", http.StatusNotFound)
		return
	}

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

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
		}
		if ok {
			applied = append(applied, key)
		}
	}
	writeJSON(w, map[string]interface{}{"status": "ok", "applied": applied})
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
	for i, b := range c.Backends {
		if b.Nickname == nickname {
			b.Close()
			c.Backends = append(c.Backends[:i], c.Backends[i+1:]...)
			writeJSON(w, map[string]string{"status": "ok"})
			return
		}
	}
	http.Error(w, "backend not found", http.StatusNotFound)
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
	b.Die = c.Die
	b.stat = &statServer{}
	b.pool = c.pool
	b.LogHTTP = c.LogHTTP
	b.Timeout = c.Timeout
	b.PreferIPv4 = c.PreferIPv4
	b.Obfs = c.Obfs
	b.ObfsHost = append([]string{}, c.ObfsHost...)
	b.autoProxyCtx = c.autoProxyCtx
	CheckLogFile(b)
	CheckBasicConfig(b)
	if c.LimitPerConn != 0 {
		b.LimitPerConn = c.LimitPerConn
	}
	if len(c.limiters) != 0 {
		b.limiters = append(b.limiters, c.limiters...)
	}
	c.Backends = append(c.Backends, b)
	writeJSON(w, map[string]interface{}{"status": "ok", "index": len(c.Backends) - 1})
}

func toString(v interface{}) (string, error) {
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

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}