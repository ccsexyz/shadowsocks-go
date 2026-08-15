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
	timeout := time.Duration(c.Timeout) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(defaultTimeout) * time.Second
	}
	delayMs := c.IPSelectDelayMs
	if delayMs <= 0 {
		delayMs = defaultIPSelectDelayMs
	} else if delayMs > maxIPSelectDelayMs {
		delayMs = maxIPSelectDelayMs
	}
	delay := time.Duration(delayMs) * time.Millisecond
	return ipSelPolicy{
		NoIPv4:     c.NoIPv4,
		NoIPv6:     c.NoIPv6,
		PreferIPv4: c.PreferIPv4,
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
// score cache to perform the grouping in rankCandidates.
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

// rankCandidates orders ips best-first. PreferIPv4 groups all v4 candidates
// ahead of v6 (head start, not exclusion); otherwise ordering is purely by
// score with the resolver order preserved for ties/unknowns. Returns a new
// slice.
func (c *ipScoreCache) rankCandidates(host string, ips []netip.Addr, p ipSelPolicy) []netip.Addr {
	type scored struct {
		addr  netip.Addr
		score float64
	}
	now := time.Now()
	c.mu.Lock()
	v4 := make([]scored, 0, len(ips))
	v6 := make([]scored, 0, len(ips))
	for _, ip := range ips {
		s := scored{addr: ip, score: c.scoreLocked(host, ip.String(), now)}
		if ip.Is4() {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	c.mu.Unlock()

	sortBy := func(list []scored) {
		sort.SliceStable(list, func(i, j int) bool { return list[i].score < list[j].score })
	}

	out := make([]netip.Addr, 0, len(ips))
	if p.PreferIPv4 {
		sortBy(v4)
		sortBy(v6)
		for _, x := range v4 {
			out = append(out, x.addr)
		}
		for _, x := range v6 {
			out = append(out, x.addr)
		}
		return out
	}
	all := append(v4, v6...)
	sortBy(all)
	for _, x := range all {
		out = append(out, x.addr)
	}
	return out
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
// real dial failure. Cancellation caused by the caller is not an IP-quality signal.
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

	// Literal IP: no resolution, no race.
	if _, perr := netip.ParseAddr(host); perr == nil {
		ips := p.filter([]netip.Addr{netip.MustParseAddr(host)})
		if len(ips) == 0 {
			return nil, fmt.Errorf("address family of %s is disabled", host)
		}
		conn, _, err := ipSelDial(dialCtx, network, address, timeout)
		return conn, err
	}

	ips, err := ipSelLookup(dialCtx, host)
	if err != nil {
		return nil, err
	}
	ips = p.preferIPv4(p.filter(ips))
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no usable ip found", host)
	}

	var cand []netip.Addr
	if useScore && cache != nil {
		cand = cache.rankCandidates(host, ips, p)
	} else {
		cand = ips
	}
	cand = capCandidates(cand)

	// Occasional exploration: try a random candidate first so scores of
	// rarely used IPs stay fresh.
	if useScore && cache != nil && len(cand) > 1 && rand.Float64() < ipSelExploreProb {
		i := rand.IntN(len(cand))
		cand[0], cand[i] = cand[i], cand[0]
	}

	// Single candidate: no race needed.
	if len(cand) == 1 {
		conn, elapsed, derr := ipSelDial(dialCtx, network, net.JoinHostPort(cand[0].String(), port), timeout)
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
	for r := range results {
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
		if firstErr == nil {
			firstErr = fmt.Errorf("dial %s failed", address)
		}
		return nil, firstErr
	}
	if useScore && cache != nil {
		cache.record(host, winner.ip, winner.elapsed, true)
	}
	return winner.conn, nil
}
