package ss

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ipselect implements dual-stack IP preference ("IP 优选"): when a domain
// resolves to multiple addresses, candidate IPs are raced concurrently
// (first TCP connect wins) and per-IP connect statistics are accumulated so
// that subsequent dials prefer historically fast IPs.
//
// It currently applies to TCP dials made through DialTCP and DialWsConn.
// SOCKS5 (proxy.Dialer), UDP and direct net.Dial call sites do not use it.

const (
	ipSelectSmart = "smart" // race + score cache
	ipSelectRace  = "race"  // race only, no scoring
	ipSelectOff   = "off"   // legacy behavior

	defaultIPSelectDelayMs = 150      // stagger between concurrent candidates
	maxIPSelectDelayMs     = 86400000 // 24h cap: keeps time.Duration math safe
	maxIPSelectCandidates  = 3        // max concurrent dial attempts per dial
	ipSelExploreProb       = 1.0 / 16.0
	ipSelStatTTL           = 30 * time.Minute
	ipSelMaxHosts          = 1024
	ipSelMaxIPsPerHost     = 32
	ipSelHistorySize       = 64 // decision-history ring size per cache
)

// normalizeIPSelectMode returns a valid ipselect mode. Empty and invalid
// values fall back to off so ad-hoc Configs, DialTCP and DialWsConn keep the
// pre-ipselect behavior unless a mode is configured explicitly.
func normalizeIPSelectMode(mode string) string {
	switch mode {
	case ipSelectSmart, ipSelectRace, ipSelectOff:
		return mode
	default:
		return ipSelectOff
	}
}

// ipSelPolicy carries the family/ordering policy for a dial.
type ipSelPolicy struct {
	NoIPv4     bool
	NoIPv6     bool
	PreferIPv4 bool
	Timeout    time.Duration // per-attempt dial timeout
	Delay      time.Duration // stagger between candidates
}

// newIPSelPolicy builds a policy from a Config.
func newIPSelPolicy(c *cfg) ipSelPolicy {
	p := c.dialPolicy()
	timeout := time.Duration(p.timeout) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(defaultTimeout) * time.Second
	}
	delayMs := p.ipSelectDelay
	if delayMs <= 0 {
		delayMs = defaultIPSelectDelayMs
	} else if delayMs > maxIPSelectDelayMs {
		delayMs = maxIPSelectDelayMs
	}
	delay := time.Duration(delayMs) * time.Millisecond
	return ipSelPolicy{
		NoIPv4:     p.noIPv4,
		NoIPv6:     p.noIPv6,
		PreferIPv4: p.preferIPv4,
		Timeout:    timeout,
		Delay:      delay,
	}
}

// filter removes families disabled by the policy, preserving input order.
func (p ipSelPolicy) filter(ips []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Is4() {
			if p.NoIPv4 {
				continue
			}
		} else if p.NoIPv6 {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// preferIPv4 groups all IPv4 candidates ahead of IPv6 while preserving the
// relative order inside each family. It is used by race mode, which has no
// score cache for orderScored to rank with.
func (p ipSelPolicy) preferIPv4(ips []netip.Addr) []netip.Addr {
	if !p.PreferIPv4 {
		return ips
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Is4() {
			out = append(out, ip)
		}
	}
	for _, ip := range ips {
		if !ip.Is4() {
			out = append(out, ip)
		}
	}
	return out
}

// ipStat tracks per-IP connect statistics for one host.
type ipStat struct {
	rtt        float64 // EWMA connect latency (nanoseconds); 0 = unknown
	success    int64
	fail       int64
	failStreak int64
	lastSeen   time.Time
}

// ipScoreCache is a bounded per-host/per-IP statistics store. All methods
// are safe for concurrent use.
type ipScoreCache struct {
	mu       sync.Mutex
	m        map[string]map[string]*ipStat
	maxHosts int
	maxIPs   int
	ttl      time.Duration
	hist     ipSelHistory
}

func newIPScoreCache() *ipScoreCache {
	return &ipScoreCache{
		m:        make(map[string]map[string]*ipStat),
		maxHosts: ipSelMaxHosts,
		maxIPs:   ipSelMaxIPsPerHost,
		ttl:      ipSelStatTTL,
	}
}

// scoreLocked returns the lower-is-better score of ip for host. 0 means
// unknown (either never seen or stale), which ranks as "try it early".
// Entries that have been seen but never succeeded rank below every IP that
// has ever connected successfully.
func (c *ipScoreCache) scoreLocked(host, ip string, now time.Time) float64 {
	m := c.m[host]
	if m == nil {
		return 0
	}
	st := m[ip]
	if st == nil || (st.success == 0 && st.fail == 0) || now.Sub(st.lastSeen) > c.ttl {
		return 0
	}
	penalty := 1 + 0.5*float64(st.failStreak)
	if penalty > 4 {
		penalty = 4
	}
	if st.rtt == 0 {
		return math.MaxFloat64
	}
	return st.rtt * penalty
}

// record stores the outcome of a dial attempt for host/ip.
func (c *ipScoreCache) record(host, ip string, elapsed time.Duration, ok bool) {
	if host == "" || ip == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	m := c.m[host]
	if m == nil {
		if len(c.m) >= c.maxHosts {
			c.evictLocked(now)
		}
		m = make(map[string]*ipStat)
		c.m[host] = m
	}
	st := m[ip]
	if st == nil {
		if len(m) >= c.maxIPs {
			c.evictIPLocked(m, now)
		}
		st = &ipStat{}
		m[ip] = st
	}
	st.lastSeen = now
	if ok {
		rtt := float64(elapsed)
		if st.rtt == 0 {
			st.rtt = rtt
		} else {
			st.rtt = st.rtt*0.75 + rtt*0.25
		}
		st.success++
		st.failStreak = 0
	} else {
		st.fail++
		st.failStreak++
	}
}

// evictIPLocked drops one IP for a host, preferring stale entries and then
// the least recently seen entry.
func (c *ipScoreCache) evictIPLocked(m map[string]*ipStat, now time.Time) {
	victim := ""
	oldest := now
	for ip, st := range m {
		if now.Sub(st.lastSeen) >= c.ttl {
			victim = ip
			break
		}
		if victim == "" || st.lastSeen.Before(oldest) {
			victim = ip
			oldest = st.lastSeen
		}
	}
	if victim != "" {
		delete(m, victim)
	}
}

// evictLocked drops one host, preferring hosts whose entries are all stale.
func (c *ipScoreCache) evictLocked(now time.Time) {
	fallback := ""
	for host, m := range c.m {
		if fallback == "" {
			fallback = host
		}
		stale := true
		for _, st := range m {
			if now.Sub(st.lastSeen) < c.ttl {
				stale = false
				break
			}
		}
		if stale {
			delete(c.m, host)
			return
		}
	}
	delete(c.m, fallback)
}

// ipSelScored couples a candidate with its cache snapshot: the ranking score
// plus the stats behind it, copied so they stay valid after the lock release.
type ipSelScored struct {
	addr       netip.Addr
	score      float64
	rtt        float64
	success    int64
	fail       int64
	failStreak int64
	lastSeen   time.Time
}

// scoreAll snapshots host's candidate scores in one lock pass.
func (c *ipScoreCache) scoreAll(host string, ips []netip.Addr, now time.Time) []ipSelScored {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.m[host]
	out := make([]ipSelScored, 0, len(ips))
	for _, ip := range ips {
		s := ipSelScored{addr: ip, score: c.scoreLocked(host, ip.String(), now)}
		if st := m[ip.String()]; st != nil {
			s.rtt, s.success, s.fail, s.failStreak, s.lastSeen = st.rtt, st.success, st.fail, st.failStreak, st.lastSeen
		}
		out = append(out, s)
	}
	return out
}

// orderScored sorts best-first. PreferIPv4 groups all v4 candidates ahead of
// v6 (head start, not exclusion); otherwise ordering is purely by score, with
// v4-ahead-of-v6 and the input order preserved for ties/unknowns — matching
// the resolver-order semantics this ranking has always had.
func orderScored(list []ipSelScored, p ipSelPolicy) []ipSelScored {
	sortBy := func(l []ipSelScored) {
		sort.SliceStable(l, func(i, j int) bool { return l[i].score < l[j].score })
	}
	v4 := make([]ipSelScored, 0, len(list))
	v6 := make([]ipSelScored, 0, len(list))
	for _, s := range list {
		if s.addr.Is4() {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	if p.PreferIPv4 {
		sortBy(v4)
		sortBy(v6)
		return append(v4, v6...)
	}
	all := append(v4, v6...)
	sortBy(all)
	return all
}

// Sentinel scoreMs values for the admin UI.
const (
	ipSelScoreUnknown        = -1.0 // no ranking data for this IP
	ipSelScoreNeverConnected = -2.0 // seen but never connected successfully
)

// Why a decision was made (ipSelDecision.Reason).
const (
	ipSelReasonRace    = "race"    // first successful connect won
	ipSelReasonExplore = "explore" // a random probe reshuffled candidates first
	ipSelReasonSingle  = "single"  // one usable candidate, no race
	ipSelReasonLiteral = "literal" // target was a literal IP, nothing to select
	ipSelReasonResolve = "resolve" // resolution or family filter left nothing to dial
	ipSelReasonFailed  = "failed"  // every candidate failed
)

// ipSelCandView is one candidate as recorded at decision time.
type ipSelCandView struct {
	IP        string  `json:"ip"`
	ScoreMs   float64 `json:"scoreMs"`
	ElapsedMs float64 `json:"elapsedMs"`
	Err       string  `json:"err,omitempty"`
}

// ipSelDecision is one dial decision as shown in the admin UI.
type ipSelDecision struct {
	Time       time.Time       `json:"time"`
	Host       string          `json:"host"`
	Reason     string          `json:"reason"`
	Winner     string          `json:"winner,omitempty"`
	Error      string          `json:"error,omitempty"`
	ElapsedMs  float64         `json:"elapsedMs"`
	Source     string          `json:"source,omitempty"` // backend nickname; filled by the admin API
	Candidates []ipSelCandView `json:"candidates,omitempty"`
}

// ipSelHistory is a bounded ring of recent decisions; the zero value is ready.
type ipSelHistory struct {
	mu   sync.Mutex
	buf  []ipSelDecision
	pos  int
	full bool
}

func (h *ipSelHistory) record(d ipSelDecision) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.buf == nil {
		h.buf = make([]ipSelDecision, ipSelHistorySize)
	}
	h.buf[h.pos] = d
	h.pos++
	if h.pos >= len(h.buf) {
		h.pos = 0
		h.full = true
	}
}

// snapshot returns the buffered decisions newest first.
func (h *ipSelHistory) snapshot() []ipSelDecision {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.pos
	if h.full {
		n = len(h.buf)
	}
	out := make([]ipSelDecision, 0, n)
	for i := 0; i < n; i++ {
		idx := h.pos - 1 - i
		if idx < 0 {
			idx += len(h.buf)
		}
		out = append(out, h.buf[idx])
	}
	return out
}

// recordDecision stores one decision for the admin UI. Elapsed is measured
// from d.Time, so callers only fill in the observable facts.
func (c *ipScoreCache) recordDecision(d ipSelDecision) {
	if c == nil {
		return
	}
	d.ElapsedMs = ipSelMs(time.Since(d.Time))
	c.hist.record(d)
}

// ipSelHostStat is one IP's live statistics for the admin UI.
type ipSelHostStat struct {
	IP         string    `json:"ip"`
	RTTMs      float64   `json:"rttMs"`
	Success    int64     `json:"success"`
	Fail       int64     `json:"fail"`
	FailStreak int64     `json:"failStreak"`
	LastSeen   time.Time `json:"lastSeen"`
	ScoreMs    float64   `json:"scoreMs"`
}

// ipSelHostView lists one host's known IPs in predicted dial order.
type ipSelHostView struct {
	Host       string          `json:"host"`
	Source     string          `json:"source,omitempty"` // backend nickname; filled by the admin API
	Candidates []ipSelHostStat `json:"candidates"`
}

// snapshotHosts returns every host with recorded stats, candidates ordered
// the way the next dial would try them.
func (c *ipScoreCache) snapshotHosts(p ipSelPolicy) []ipSelHostView {
	now := time.Now()
	c.mu.Lock()
	hosts := make([]string, 0, len(c.m))
	ipLists := make(map[string][]netip.Addr, len(c.m))
	for host, m := range c.m {
		hosts = append(hosts, host)
		ips := make([]netip.Addr, 0, len(m))
		for ipStr := range m {
			if a, err := netip.ParseAddr(ipStr); err == nil {
				ips = append(ips, a)
			}
		}
		ipLists[host] = ips
	}
	c.mu.Unlock()

	sort.Strings(hosts)
	out := make([]ipSelHostView, 0, len(hosts))
	for _, host := range hosts {
		scored := orderScored(c.scoreAll(host, ipLists[host], now), p)
		hv := ipSelHostView{Host: host, Candidates: make([]ipSelHostStat, 0, len(scored))}
		for _, s := range scored {
			hv.Candidates = append(hv.Candidates, ipSelHostStat{
				IP:         s.addr.String(),
				RTTMs:      ipSelMs(time.Duration(s.rtt)),
				Success:    s.success,
				Fail:       s.fail,
				FailStreak: s.failStreak,
				LastSeen:   s.lastSeen,
				ScoreMs:    ipSelScoreMs(s.score),
			})
		}
		out = append(out, hv)
	}
	return out
}

func (c *ipScoreCache) snapshotHistory() []ipSelDecision {
	return c.hist.snapshot()
}

// ipSelMs renders a duration in fractional milliseconds for the admin UI.
func ipSelMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

// ipSelScoreMs maps a raw ranking score to the UI representation.
func ipSelScoreMs(score float64) float64 {
	switch {
	case score == 0:
		return ipSelScoreUnknown
	case score == math.MaxFloat64:
		return ipSelScoreNeverConnected
	default:
		return score / 1e6
	}
}

// Test hooks: replaced in unit tests to control resolution and dialing.
var (
	ipSelLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	ipSelDial = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, time.Duration, error) {
		start := time.Now()
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, network, address)
		return conn, time.Since(start), err
	}
)

// capCandidates limits the race to maxIPSelectCandidates entries while
// keeping at least one candidate per available family (dual-stack failover).
// Returns a fresh slice.
func capCandidates(cand []netip.Addr) []netip.Addr {
	if len(cand) <= maxIPSelectCandidates {
		return append([]netip.Addr{}, cand...)
	}
	top := append([]netip.Addr{}, cand[:maxIPSelectCandidates]...)
	has4, has6 := false, false
	for _, ip := range top {
		if ip.Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	if has4 == has6 {
		return top
	}
	for _, ip := range cand[maxIPSelectCandidates:] {
		if (ip.Is4() && !has4) || (!ip.Is4() && !has6) {
			top[len(top)-1] = ip
			return top
		}
	}
	return top
}

// ipSelFailureShouldRecord reports whether err should be recorded as a
// real dial failure. Cancellation caused by the caller is not an IP-quality
// signal, so neither the stats nor the decision history record it.
func ipSelFailureShouldRecord(err error, parent context.Context) bool {
	return !errors.Is(err, context.Canceled) || parent.Err() == nil
}

// dialIPSelect dials address, racing the resolved candidates when address is
// a hostname. useScore enables score-based ranking and statistics recording;
// otherwise candidates race in resolver order.
func dialIPSelect(parent context.Context, network, address string, p ipSelPolicy, cache *ipScoreCache, useScore bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	// One deadline covers DNS resolution and all dial attempts. Individual
	// attempts still receive p.Timeout, but the shared deadline prevents the
	// staggered race from exceeding the configured timeout budget.
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = time.Duration(defaultTimeout) * time.Second
	}
	dialCtx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	decisionStart := time.Now()

	// Literal IP: no resolution, no race.
	if _, perr := netip.ParseAddr(host); perr == nil {
		ips := p.filter([]netip.Addr{netip.MustParseAddr(host)})
		if len(ips) == 0 {
			err := fmt.Errorf("address family of %s is disabled", host)
			cache.recordDecision(ipSelDecision{Time: decisionStart, Host: host, Reason: ipSelReasonLiteral, Error: err.Error()})
			return nil, err
		}
		conn, _, derr := ipSelDial(dialCtx, network, address, timeout)
		if derr == nil || ipSelFailureShouldRecord(derr, parent) {
			d := ipSelDecision{
				Time:       decisionStart,
				Host:       host,
				Reason:     ipSelReasonLiteral,
				Candidates: []ipSelCandView{{IP: host, ScoreMs: ipSelScoreUnknown}},
			}
			if derr != nil {
				d.Error = derr.Error()
			} else {
				d.Winner = host
			}
			cache.recordDecision(d)
		}
		return conn, derr
	}

	ips, err := ipSelLookup(dialCtx, host)
	if err != nil {
		if ipSelFailureShouldRecord(err, parent) {
			cache.recordDecision(ipSelDecision{Time: decisionStart, Host: host, Reason: ipSelReasonResolve, Error: err.Error()})
		}
		return nil, err
	}
	ips = p.preferIPv4(p.filter(ips))
	if len(ips) == 0 {
		err := fmt.Errorf("resolve %s: no usable ip found", host)
		cache.recordDecision(ipSelDecision{Time: decisionStart, Host: host, Reason: ipSelReasonResolve, Error: err.Error()})
		return nil, err
	}

	var cand []netip.Addr
	var scores map[string]float64
	if useScore && cache != nil {
		scored := orderScored(cache.scoreAll(host, ips, time.Now()), p)
		cand = make([]netip.Addr, len(scored))
		scores = make(map[string]float64, len(scored))
		for i, s := range scored {
			cand[i] = s.addr
			scores[s.addr.String()] = ipSelScoreMs(s.score)
		}
	} else {
		cand = ips
	}
	cand = capCandidates(cand)

	// Occasional exploration: try a random candidate first so scores of
	// rarely used IPs stay fresh.
	explored := false
	if useScore && cache != nil && len(cand) > 1 && rand.Float64() < ipSelExploreProb {
		i := rand.IntN(len(cand))
		cand[0], cand[i] = cand[i], cand[0]
		explored = true
	}

	// decision captures what the admin UI reports; nil without a cache.
	var decision *ipSelDecision
	if cache != nil {
		decision = &ipSelDecision{Time: decisionStart, Host: host, Reason: ipSelReasonRace}
		if explored {
			decision.Reason = ipSelReasonExplore
		}
		for _, ip := range cand {
			cv := ipSelCandView{IP: ip.String(), ScoreMs: ipSelScoreUnknown}
			if scores != nil {
				cv.ScoreMs = scores[ip.String()]
			}
			decision.Candidates = append(decision.Candidates, cv)
		}
	}

	// Single candidate: no race needed.
	if len(cand) == 1 {
		conn, elapsed, derr := ipSelDial(dialCtx, network, net.JoinHostPort(cand[0].String(), port), timeout)
		if decision != nil && (derr == nil || ipSelFailureShouldRecord(derr, parent)) {
			decision.Reason = ipSelReasonSingle
			decision.Candidates[0].ElapsedMs = ipSelMs(elapsed)
			if derr != nil {
				decision.Candidates[0].Err = derr.Error()
				decision.Error = derr.Error()
			} else {
				decision.Winner = cand[0].String()
			}
			cache.recordDecision(*decision)
		}
		if derr != nil {
			if conn != nil {
				conn.Close()
			}
			if useScore && cache != nil && ipSelFailureShouldRecord(derr, parent) {
				cache.record(host, cand[0].String(), elapsed, false)
			}
			return nil, derr
		}
		if useScore && cache != nil {
			cache.record(host, cand[0].String(), elapsed, true)
		}
		return conn, nil
	}

	type dialResult struct {
		ip      string
		conn    net.Conn
		elapsed time.Duration
		err     error
	}
	raceCtx, raceCancel := context.WithCancel(dialCtx)
	defer raceCancel()

	// Failure-accelerated stagger: candidate i starts after its stagger
	// delay OR as soon as all earlier candidates have failed.
	var failCount atomic.Int32
	failNotify := make(chan struct{}, len(cand))

	results := make(chan dialResult, len(cand))
	var wg sync.WaitGroup
	for i, ip := range cand {
		wg.Add(1)
		go func(i int, ip netip.Addr) {
			defer wg.Done()
			if i > 0 && p.Delay > 0 {
				t := time.NewTimer(time.Duration(i) * p.Delay)
				defer t.Stop()
				for {
					select {
					case <-raceCtx.Done():
						return
					case <-t.C:
						goto dial
					case <-failNotify:
						if int(failCount.Load()) >= i {
							goto dial
						}
					}
				}
			}
		dial:
			conn, elapsed, derr := ipSelDial(raceCtx, network, net.JoinHostPort(ip.String(), port), timeout)
			if derr != nil {
				failCount.Add(1)
				select {
				case failNotify <- struct{}{}:
				default:
				}
			}
			results <- dialResult{ip: ip.String(), conn: conn, elapsed: elapsed, err: derr}
		}(i, ip)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var winner dialResult
	var firstErr error
	haveWinner := false
	attachOutcome := func(r dialResult) {
		if decision == nil {
			return
		}
		for k := range decision.Candidates {
			if decision.Candidates[k].IP != r.ip {
				continue
			}
			decision.Candidates[k].ElapsedMs = ipSelMs(r.elapsed)
			if r.err != nil {
				decision.Candidates[k].Err = r.err.Error()
			}
			return
		}
	}
	for r := range results {
		attachOutcome(r)
		if r.err != nil {
			if r.conn != nil {
				r.conn.Close()
			}
			// Failures arriving after the winner are caused by raceCancel;
			// recording them would punish healthy IPs that merely lost the
			// race by a few milliseconds.
			if haveWinner {
				continue
			}
			if firstErr == nil {
				firstErr = r.err
			}
			if useScore && cache != nil && ipSelFailureShouldRecord(r.err, parent) {
				cache.record(host, r.ip, r.elapsed, false)
			}
			continue
		}
		if haveWinner {
			r.conn.Close() // reap a late finisher
			continue
		}
		haveWinner = true
		winner = r
		raceCancel() // stop the remaining attempts
	}
	if winner.conn == nil {
		if decision != nil && ipSelFailureShouldRecord(firstErr, parent) {
			decision.Reason = ipSelReasonFailed
			if firstErr != nil {
				decision.Error = firstErr.Error()
			}
			cache.recordDecision(*decision)
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("dial %s failed", address)
		}
		return nil, firstErr
	}
	if useScore && cache != nil {
		cache.record(host, winner.ip, winner.elapsed, true)
	}
	if decision != nil {
		decision.Winner = winner.ip
		cache.recordDecision(*decision)
	}
	return winner.conn, nil
}
