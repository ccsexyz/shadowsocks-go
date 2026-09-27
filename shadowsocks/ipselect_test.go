package ss

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestIPSelectPolicyFilter(t *testing.T) {
	ips := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("5.6.7.8"),
	}

	if got := (ipSelPolicy{}).filter(ips); len(got) != 3 {
		t.Errorf("empty policy should keep all, got %v", got)
	}
	if got := (ipSelPolicy{NoIPv4: true}).filter(ips); len(got) != 1 || got[0] != ips[1] {
		t.Errorf("NoIPv4 filter = %v", got)
	}
	if got := (ipSelPolicy{NoIPv6: true}).filter(ips); len(got) != 2 {
		t.Errorf("NoIPv6 filter = %v", got)
	}
	if got := (ipSelPolicy{NoIPv4: true, NoIPv6: true}).filter(ips); len(got) != 0 {
		t.Errorf("both disabled should keep none, got %v", got)
	}
}

func TestIPSelectPolicyPreferIPv4Order(t *testing.T) {
	ips := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
	}
	got := (ipSelPolicy{PreferIPv4: true}).preferIPv4(ips)
	if len(got) != len(ips) {
		t.Fatalf("preferIPv4 changed length: %v", got)
	}
	if !got[0].Is4() || !got[1].Is4() || got[2].Is4() {
		t.Fatalf("PreferIPv4 should put both v4 candidates first, got %v", got)
	}
}

func TestNormalizeIPSelectMode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ipSelectOff},
		{ipSelectSmart, ipSelectSmart},
		{ipSelectRace, ipSelectRace},
		{ipSelectOff, ipSelectOff},
		{"bogus", ipSelectOff},
	} {
		if got := normalizeIPSelectMode(tc.in); got != tc.want {
			t.Errorf("normalizeIPSelectMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCheckBasicConfigNormalizesIPSelect(t *testing.T) {
	c := &Config{NetworkConfig: NetworkConfig{IPSelect: "bogus", IPSelectDelayMs: -1}}
	CheckBasicConfig(c)

	if c.IPSelect != ipSelectOff {
		t.Fatalf("invalid ipselect should fall back to off, got %q", c.IPSelect)
	}
	if c.IPSelectDelayMs != defaultIPSelectDelayMs {
		t.Fatalf("non-positive delay should use default, got %d", c.IPSelectDelayMs)
	}
	if rt := c.rt.Load(); rt != nil && rt.ipSelCache != nil {
		t.Fatal("off mode should not initialize the score cache during CheckBasicConfig")
	}

	smart := &Config{NetworkConfig: NetworkConfig{IPSelect: ipSelectSmart}}
	CheckBasicConfig(smart)
	if smart.getIPSelectCache() == nil {
		t.Fatal("smart mode should initialize the score cache during CheckBasicConfig")
	}

	clamped := &Config{NetworkConfig: NetworkConfig{IPSelect: ipSelectOff, IPSelectDelayMs: maxIPSelectDelayMs + 1}}
	CheckBasicConfig(clamped)
	if clamped.IPSelectDelayMs != maxIPSelectDelayMs {
		t.Fatalf("delay should clamp to %d, got %d", maxIPSelectDelayMs, clamped.IPSelectDelayMs)
	}
}

func TestIPScoreCacheRecordAndRank(t *testing.T) {
	c := newIPScoreCache()
	c.record("example.com", "1.1.1.1", 10*time.Millisecond, true)
	c.record("example.com", "2.2.2.2", 90*time.Millisecond, true)
	c.record("example.com", "4.4.4.4", 5*time.Second, true)
	c.record("example.com", "3.3.3.3", 0, false)

	ips := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2.2.2.2"),
		netip.MustParseAddr("4.4.4.4"),
		netip.MustParseAddr("3.3.3.3"),
	}
	rank := func(host string, list []netip.Addr, p ipSelPolicy) []netip.Addr {
		scored := orderScored(c.scoreAll(host, list, time.Now()), p)
		out := make([]netip.Addr, len(scored))
		for i, s := range scored {
			out[i] = s.addr
		}
		return out
	}
	ranked := rank("example.com", ips, ipSelPolicy{})
	if ranked[0] != ips[0] {
		t.Errorf("fastest ip should rank first, got %v", ranked)
	}
	if ranked[len(ranked)-1] != ips[3] {
		t.Errorf("never-succeeded ip should rank last, got %v", ranked)
	}
	if c.scoreLocked("example.com", "3.3.3.3", time.Now()) <= c.scoreLocked("example.com", "4.4.4.4", time.Now()) {
		t.Errorf("never-succeeded ip should rank below a successful but slow ip")
	}

	// PreferIPv4 groups all v4 ahead of v6.
	v6 := netip.MustParseAddr("2001:db8::1")
	mixed := []netip.Addr{v6, ips[1]}
	ranked = rank("example.com", mixed, ipSelPolicy{PreferIPv4: true})
	if ranked[0] != ips[1] {
		t.Errorf("PreferIPv4 should put v4 first, got %v", ranked)
	}
}

func TestIPScoreCacheBoundsIPsPerHost(t *testing.T) {
	c := newIPScoreCache()
	for i := 0; i < ipSelMaxIPsPerHost+8; i++ {
		c.record("bounded.test", fmt.Sprintf("192.0.2.%d", i+1), time.Millisecond, true)
	}
	c.mu.Lock()
	n := len(c.m["bounded.test"])
	c.mu.Unlock()
	if n != ipSelMaxIPsPerHost {
		t.Fatalf("per-host IP cache should be capped at %d, got %d", ipSelMaxIPsPerHost, n)
	}
}

func TestCapCandidatesKeepsDualFamily(t *testing.T) {
	v4s := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2.2.2.2"),
		netip.MustParseAddr("3.3.3.3"),
	}
	v6 := netip.MustParseAddr("2001:db8::1")
	got := capCandidates(append(append([]netip.Addr{}, v4s...), v6))
	if len(got) != maxIPSelectCandidates {
		t.Fatalf("expected %d candidates, got %d", maxIPSelectCandidates, len(got))
	}
	has4, has6 := false, false
	for _, ip := range got {
		if ip.Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	if !has4 || !has6 {
		t.Errorf("candidates should keep both families, got %v", got)
	}
}

func TestDialIPSelectRacePicksFastest(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	origLookup, origDial := ipSelLookup, ipSelDial
	t.Cleanup(func() { ipSelLookup, ipSelDial = origLookup, origDial })

	ipSelLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::1"), // slow / failing candidate
			netip.MustParseAddr("127.0.0.1"),   // fast candidate
		}, nil
	}
	ipSelDial = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, time.Duration, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, 0, err
		}
		if host == "2001:db8::1" {
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
			}
			return nil, 2 * time.Second, context.DeadlineExceeded
		}
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		return conn, time.Since(start), err
	}

	cache := newIPScoreCache()
	address := net.JoinHostPort("race.test", strconv.Itoa(port))
	start := time.Now()
	conn, err := dialIPSelect(context.Background(), "tcp", address,
		ipSelPolicy{Timeout: 3 * time.Second, Delay: 300 * time.Millisecond}, cache, true)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The slow candidate starts immediately and takes 2s; the fast one
	// starts after the 300ms stagger. A sub-1200ms total proves the race.
	if elapsed > 1200*time.Millisecond {
		t.Fatalf("race too slow (%v): candidates were not raced concurrently", elapsed)
	}
	if raddr, ok := conn.RemoteAddr().(*net.TCPAddr); !ok || !raddr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("winner should be 127.0.0.1, got %v", conn.RemoteAddr())
	}

	// The winner must have been recorded with its measured connect rtt.
	if s := cache.scoreLocked("race.test", "127.0.0.1", time.Now()); s <= 0 || s >= float64(time.Second) {
		t.Errorf("winner should be scored as measured rtt, got %v", s)
	}

	// The canceled loser must not be penalized.
	cache.mu.Lock()
	st := cache.m["race.test"]["2001:db8::1"]
	cache.mu.Unlock()
	if st != nil {
		t.Errorf("canceled loser should not be recorded, got %+v", st)
	}
}

func TestDialIPSelectRaceModePrefersIPv4(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	origLookup, origDial := ipSelLookup, ipSelDial
	t.Cleanup(func() { ipSelLookup, ipSelDial = origLookup, origDial })

	ipSelLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("127.0.0.1"),
		}, nil
	}
	ipSelDial = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, time.Duration, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, 0, err
		}
		if host == "2001:db8::1" {
			// A successful non-TCP candidate. Without PreferIPv4 ordering in
			// race mode this candidate starts first and wins the race.
			c1, c2 := net.Pipe()
			t.Cleanup(func() { c1.Close(); c2.Close() })
			return c1, time.Millisecond, nil
		}
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		return conn, time.Since(start), err
	}

	conn, err := dialIPSelect(context.Background(), "tcp",
		net.JoinHostPort("prefer.race.test", strconv.Itoa(port)),
		ipSelPolicy{PreferIPv4: true, Timeout: time.Second, Delay: 150 * time.Millisecond}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if raddr, ok := conn.RemoteAddr().(*net.TCPAddr); !ok || !raddr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("race mode with PreferIPv4 should pick v4, got %v", conn.RemoteAddr())
	}
}

func TestDialIPSelectFailureAccelerates(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	origLookup, origDial := ipSelLookup, ipSelDial
	t.Cleanup(func() { ipSelLookup, ipSelDial = origLookup, origDial })

	ipSelLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::1"), // fails immediately
			netip.MustParseAddr("127.0.0.1"),   // succeeds
		}, nil
	}
	ipSelDial = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, time.Duration, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, 0, err
		}
		if host == "2001:db8::1" {
			return nil, time.Millisecond, fmt.Errorf("connection refused")
		}
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		return conn, time.Since(start), err
	}

	address := net.JoinHostPort("race.test", strconv.Itoa(port))
	start := time.Now()
	conn, err := dialIPSelect(context.Background(), "tcp", address,
		ipSelPolicy{Timeout: 3 * time.Second, Delay: time.Second}, nil, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Without failure acceleration the second candidate would wait out the
	// full 1s stagger.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("second candidate was not accelerated after head failure: %v", elapsed)
	}
}

func TestDialIPSelectAllFailReturnsCandidateError(t *testing.T) {
	origLookup, origDial := ipSelLookup, ipSelDial
	t.Cleanup(func() { ipSelLookup, ipSelDial = origLookup, origDial })

	ipSelLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("127.0.0.1"),
		}, nil
	}
	ipSelDial = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, time.Duration, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, 0, err
		}
		if host == "2001:db8::1" {
			return nil, time.Millisecond, fmt.Errorf("first error")
		}
		return nil, time.Millisecond, fmt.Errorf("second error")
	}

	cache := newIPScoreCache()
	_, err := dialIPSelect(context.Background(), "tcp", "allfail.test:80",
		ipSelPolicy{Timeout: time.Second, Delay: 150 * time.Millisecond}, cache, true)
	if err == nil || (err.Error() != "first error" && err.Error() != "second error") {
		t.Fatalf("expected one of the candidate errors, got %v", err)
	}

	cache.mu.Lock()
	st6 := cache.m["allfail.test"]["2001:db8::1"]
	st4 := cache.m["allfail.test"]["127.0.0.1"]
	cache.mu.Unlock()
	if st6 == nil || st6.fail != 1 {
		t.Errorf("v6 failure should be recorded, got %+v", st6)
	}
	if st4 == nil || st4.fail != 1 {
		t.Errorf("v4 failure should be recorded, got %+v", st4)
	}
}

func TestDialIPSelectParentCancellation(t *testing.T) {
	origLookup, origDial := ipSelLookup, ipSelDial
	t.Cleanup(func() { ipSelLookup, ipSelDial = origLookup, origDial })

	ipSelLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	ipSelDial = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, time.Duration, error) {
		<-ctx.Done()
		return nil, time.Millisecond, ctx.Err()
	}

	parent, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	cache := newIPScoreCache()
	_, err := dialIPSelect(parent, "tcp", "cancel.test:80",
		ipSelPolicy{Timeout: 2 * time.Second, Delay: 150 * time.Millisecond}, cache, true)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	cache.mu.Lock()
	st := cache.m["cancel.test"]["127.0.0.1"]
	cache.mu.Unlock()
	if st != nil {
		t.Fatalf("parent cancellation should not be recorded as a failure, got %+v", st)
	}
	// The same rule applies to the decision history: a dial aborted by the
	// caller has no decision worth showing.
	if n := len(cache.snapshotHistory()); n != 0 {
		t.Fatalf("parent cancellation should not be recorded in the history, got %d entries", n)
	}

	// A canceled race (every candidate fails together) stays out too.
	ipSelLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("127.0.0.1"),
		}, nil
	}
	parent2, cancel2 := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel2()
	}()
	_, err = dialIPSelect(parent2, "tcp", "cancel.test:80",
		ipSelPolicy{Timeout: 2 * time.Second, Delay: 150 * time.Millisecond}, cache, true)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if n := len(cache.snapshotHistory()); n != 0 {
		t.Fatalf("canceled race should not be recorded in the history, got %d entries", n)
	}

	// And a canceled lookup.
	ipSelLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	parent3, cancel3 := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel3()
	}()
	_, err = dialIPSelect(parent3, "tcp", "cancel.test:80",
		ipSelPolicy{Timeout: 2 * time.Second, Delay: 150 * time.Millisecond}, cache, true)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if n := len(cache.snapshotHistory()); n != 0 {
		t.Fatalf("canceled lookup should not be recorded in the history, got %d entries", n)
	}
}

func TestDialIPSelectLiteralDisabledFamily(t *testing.T) {
	_, err := dialIPSelect(context.Background(), "tcp", "1.2.3.4:80",
		ipSelPolicy{NoIPv4: true, Timeout: time.Second, Delay: 100 * time.Millisecond}, nil, false)
	if err == nil {
		t.Error("expected error dialing v4 with NoIPv4")
	}
}

func TestDialIPSelectRecordsDecisionHistory(t *testing.T) {
	origLookup, origDial := ipSelLookup, ipSelDial
	t.Cleanup(func() { ipSelLookup, ipSelDial = origLookup, origDial })

	ipSelLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("127.0.0.1"),
		}, nil
	}
	ipSelDial = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, time.Duration, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, 0, err
		}
		if host == "2001:db8::1" {
			return nil, time.Millisecond, fmt.Errorf("refused")
		}
		c1, c2 := net.Pipe()
		t.Cleanup(func() { c1.Close(); c2.Close() })
		return c1, 5 * time.Millisecond, nil
	}

	cache := newIPScoreCache()
	// Seed the stats so ranking and the reported "why" are deterministic:
	// v4 is the known-good IP, v6 has never connected. A canceled race loser
	// is not dialed at all, so a two-candidate dial cannot seed them itself.
	cache.record("history.test", "127.0.0.1", 5*time.Millisecond, true)
	cache.record("history.test", "2001:db8::1", 0, false)

	conn, err := dialIPSelect(context.Background(), "tcp", "history.test:80",
		ipSelPolicy{Timeout: time.Second, Delay: 150 * time.Millisecond}, cache, true)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	hist := cache.snapshotHistory()
	if len(hist) != 1 {
		t.Fatalf("history = %d entries, want 1", len(hist))
	}
	d := hist[0]
	if d.Host != "history.test" || d.Winner != "127.0.0.1" {
		t.Fatalf("decision = %+v", d)
	}
	if d.ElapsedMs <= 0 || d.Time.IsZero() {
		t.Errorf("decision should carry time and elapsed, got %+v", d)
	}
	var v4, v6 *ipSelCandView
	for k := range d.Candidates {
		switch d.Candidates[k].IP {
		case "127.0.0.1":
			v4 = &d.Candidates[k]
		case "2001:db8::1":
			v6 = &d.Candidates[k]
		}
	}
	if v4 == nil || v6 == nil {
		t.Fatalf("candidates = %+v", d.Candidates)
	}
	// v4 carries its measured rtt as score; v6 has only failures.
	if v4.ScoreMs <= 0 || v4.ScoreMs > 10 {
		t.Errorf("v4 score = %v, want ~5ms (measured rtt)", v4.ScoreMs)
	}
	if v6.ScoreMs != ipSelScoreNeverConnected {
		t.Errorf("v6 score = %v, want never-connected sentinel", v6.ScoreMs)
	}
	if v4.Err != "" {
		t.Errorf("winner should have no error, got %q", v4.Err)
	}

	// All-fail dial: the decision records the failure and per-candidate errors.
	ipSelDial = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, time.Duration, error) {
		return nil, time.Millisecond, fmt.Errorf("refused")
	}
	if _, err := dialIPSelect(context.Background(), "tcp", "history.test:80",
		ipSelPolicy{Timeout: time.Second, Delay: 150 * time.Millisecond}, cache, true); err == nil {
		t.Fatal("expected all-fail dial to fail")
	}
	hist = cache.snapshotHistory()
	if len(hist) != 2 {
		t.Fatalf("history = %d entries, want 2", len(hist))
	}
	d = hist[0]
	if d.Reason != ipSelReasonFailed || d.Winner != "" || d.Error == "" {
		t.Fatalf("failed decision = %+v", d)
	}
	for _, cv := range d.Candidates {
		if cv.Err == "" {
			t.Errorf("every attempted candidate should carry its error: %+v", cv)
		}
	}
}

func TestDialIPSelectLiteralRecordsDecision(t *testing.T) {
	origDial := ipSelDial
	t.Cleanup(func() { ipSelDial = origDial })
	ipSelDial = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, time.Duration, error) {
		c1, c2 := net.Pipe()
		t.Cleanup(func() { c1.Close(); c2.Close() })
		return c1, time.Millisecond, nil
	}

	cache := newIPScoreCache()
	conn, err := dialIPSelect(context.Background(), "tcp", "1.2.3.4:80",
		ipSelPolicy{Timeout: time.Second}, cache, true)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	hist := cache.snapshotHistory()
	if len(hist) != 1 {
		t.Fatalf("history = %d entries, want 1", len(hist))
	}
	if d := hist[0]; d.Reason != ipSelReasonLiteral || d.Winner != "1.2.3.4" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestPickTargetIPFamilyPolicy(t *testing.T) {
	c := &Config{NetworkConfig: NetworkConfig{IPSelect: ipSelectSmart}}
	CheckBasicConfig(c)

	ips := []net.IP{net.IPv4(1, 2, 3, 4), net.ParseIP("2001:db8::1")}

	if got := pickTargetIP(c, ips); got == nil {
		t.Fatal("expected a pick")
	}

	// Direct field writes bypass the admin API, so each one must republish
	// the dial-policy snapshot the way the admin handlers do.
	c.NoIPv6 = true
	c.publishDialPolicy()
	if got := pickTargetIP(c, ips); got == nil || got.To4() == nil {
		t.Errorf("NoIPv6 should yield v4, got %v", got)
	}

	c.NoIPv6 = false
	c.NoIPv4 = true
	c.publishDialPolicy()
	if got := pickTargetIP(c, ips); got == nil || got.To4() != nil {
		t.Errorf("NoIPv4 should yield v6, got %v", got)
	}

	c.NoIPv4 = false
	c.PreferIPv4 = true
	c.publishDialPolicy()
	if got := pickTargetIP(c, ips); got == nil || got.To4() == nil {
		t.Errorf("PreferIPv4 with both families should yield v4, got %v", got)
	}
}

func TestCheckAndModifyTargetPicksResolvedIP(t *testing.T) {
	c := &Config{NetworkConfig: NetworkConfig{LocalResolve: true, IPSelect: ipSelectSmart}}
	CheckBasicConfig(c)

	opt := &DialOptions{Target: "localhost:80", C: c}
	newOpt, err := checkAndModifyTarget(opt)
	if err != nil {
		t.Fatal(err)
	}
	if newOpt == nil {
		t.Fatal("expected newOpt with LocalResolve on a domain")
	}
	host, _, err := net.SplitHostPort(newOpt.Target)
	if err != nil || net.ParseIP(host) == nil {
		t.Errorf("newOpt.Target %q should be an ip:port", newOpt.Target)
	}
}
