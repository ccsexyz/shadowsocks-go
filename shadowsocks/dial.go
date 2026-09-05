package ss

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	"golang.org/x/net/proxy"
)

type DialOptions struct {
	RawHeader []byte
	Data      []byte
	C         *Config
	Target    string
	Timeout   int
}

var (
	errNoBackends = fmt.Errorf("no available backends")
)

func dialSocks5WithOptions(opt *DialOptions) (conn Conn, err error) {
	var rawConn net.Conn
	var dialer proxy.Dialer

	c := opt.C

	dialer, err = proxy.SOCKS5("tcp", c.Remoteaddr, nil, proxy.Direct)
	if err != nil {
		return
	}

	rawConn, err = dialer.Dial("tcp", opt.Target)
	if err != nil {
		return
	}

	conn = newBaseConn(rawConn, c)
	if len(opt.Data) > 0 {
		_, err = conn.Write(opt.Data)
		opt.Data = nil
	}
	return
}

func checkAndModifyTarget(opt *DialOptions) (newOpt *DialOptions, err error) {
	c := opt.C
	p := c.dialPolicy()

	if !p.localResolve {
		return
	}

	isDomain, isV4, host, port := checkAddrType(opt.Target)
	if !isDomain {
		if isV4 && p.noIPv4 {
			err = fmt.Errorf("IPv4 is disabled")
		} else if !isV4 && p.noIPv6 {
			err = fmt.Errorf("IPv6 is disabled")
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return
	}

	ip := pickTargetIP(c, ips)
	if ip == nil {
		err = fmt.Errorf("resolve %s fail, no ip found", host)
		return
	}

	newOpt = new(DialOptions)
	*newOpt = *opt
	if newOpt.Data != nil {
		newOpt.Data = append([]byte{}, opt.Data...)
	}
	if newOpt.RawHeader != nil {
		newOpt.RawHeader = append([]byte{}, opt.RawHeader...)
	}
	newOpt.Target = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	c.Log("resolve", host, "to", ip.String())
	return
}

// pickTargetIP applies the family policy and picks one candidate IP from the
// resolved set. Note: the pick is uniform random — client-side scoring of
// target IPs is deliberately NOT done here because in local mode the dial
// succeeds as soon as the proxy handshake completes, which carries no signal
// about whether the proxy server could actually reach the target.
func pickTargetIP(c *Config, ips []net.IP) net.IP {
	var v4, v6 []netip.Addr
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}

	// Keep the historical PreferIPv4 semantics on this path: when the
	// domain has both families, prefer means v4 only.
	p := c.dialPolicy()
	noIPv6 := p.noIPv6
	if p.preferIPv4 && !p.noIPv6 && len(v4) > 0 && len(v6) > 0 {
		noIPv6 = true
	}

	var cand []netip.Addr
	if !p.noIPv4 {
		cand = append(cand, v4...)
	}
	if !noIPv6 {
		cand = append(cand, v6...)
	}
	if len(cand) == 0 {
		return nil
	}

	return net.IP(cand[rand.IntN(len(cand))].AsSlice())
}

func dialSSWithOptions(opt *DialOptions) (conn Conn, err error) {
	newOpt, err := checkAndModifyTarget(opt)
	if err != nil {
		return
	}
	if newOpt != nil {
		opt.Data = nil // prevent double-write from caller
		opt = newOpt
	}

	c := opt.C
	if c.Method == "socks5" {
		return dialSocks5WithOptions(opt)
	}
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
			conn = nil
		}
	}()
	backends := c.SnapshotBackends()
	if len(backends) != 0 {
		die := make(chan bool)
		num := len(backends)
		errch := make(chan error, num)
		// Unbuffered: a handoff completes only when the receiver below takes
		// this conn as the winner. A buffered channel needs a post-send
		// re-check to reap strays, and that re-check races the receiver's
		// close(die): if the winner is taken off the channel before its own
		// sender re-checks, the sender closes a live connection.
		conch := make(chan Conn)
		for _, v := range backends {
			if v.isDisabled() {
				num--
				continue
			}
			newOpts := *opt
			newOpts.C = v
			if len(opt.Data) > 0 {
				newOpts.Data = utils.CopyBuffer(opt.Data)
			}
			go func(newOpts *DialOptions) {
				if len(newOpts.Data) > 0 {
					defer utils.PutBuf(newOpts.Data)
				}
				rconn, err := dialSSWithOptions(newOpts)
				if err != nil {
					select {
					case <-die:
					case errch <- fmt.Errorf("cannot connect to %s : %s", newOpts.C.Remoteaddr, err.Error()):
					}
					return
				}
				select {
				case <-die:
					rconn.Close()
				case conch <- rconn:
				}
			}(&newOpts)
		}
		var lastErr error
		for i := 0; i < num; i++ {
			select {
			case conn = <-conch:
				close(die)
				i = num
			case e := <-errch:
				lastErr = e
			}
		}
		if conn == nil {
			// Surface the actual dial failures (errNoBackends alone made
			// multi-backend outages undiagnosable); fall back to the
			// sentinel when every backend was disabled and nothing dialed.
			if lastErr != nil {
				err = fmt.Errorf("no available backends: %w", lastErr)
			} else {
				err = errNoBackends
			}
			// Every sender reported an error and returned, so nothing is
			// left to release; close die defensively anyway.
			close(die)
		}
		opt.Data = nil
		return
	}
	if len(opt.RawHeader) == 0 {
		host, port, sperr := utils.SplitHostAndPort(opt.Target)
		if sperr != nil {
			return nil, sperr
		}
		opt.RawHeader, err = GetHeader(host, port)
		if err != nil {
			return
		}
	}
	start := time.Now()
	if c.Obfs {
		conn, err = DialObfs(c.Remoteaddr, c)
	} else {
		var tconn *BaseConn
		tconn, err = DialTCP(c.Remoteaddr, c)
		if tconn != nil {
			conn = tconn
		}
	}
	elapsed := time.Since(start)
	dh := c.initDialHealth()
	if err != nil {
		isTimeout := false
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			isTimeout = true
		}
		dh.recordFail(isTimeout)
		return
	}
	dh.recordSuccess(elapsed)
	if len(c.getLimiters()) != 0 || c.LimitPerConn != 0 {
		conn = &LimitConn{
			Conn:      conn,
			Rlimiters: buildLimiters(c),
		}
	}
	if crypto.IsAEAD2022(c.Method) {
		ssConn, derr := ss2022DialWithConn(conn, opt)
		if derr != nil {
			err = derr
			return // conn still holds the raw conn; the deferred cleanup closes it
		}
		conn = ssConn
		return
	}
	dec, err := crypto.NewDecrypter(c.Method, c.Password)
	if err != nil {
		return
	}
	enc, err := crypto.NewEncrypter(c.Method, c.Password)
	if err != nil {
		return
	}
	C := newCryptoConnStream(conn, enc, dec)
	conn = C
	if c.Nonop {
		conn = &RemainConn{
			Conn:    conn,
			wremain: opt.RawHeader,
		}
	} else {
		header := make([]byte, 512)
		headerLen := 0
		noplen := rand.IntN(4)
		noplen += int(crc32.Checksum(header, c.getCRCTable()) % (128 - (lenTs + 5)))
		headerLen += copy(header[headerLen:], []byte{typeNop, byte(noplen)})
		headerLen += noplen
		header[headerLen] = typeTs
		headerLen++
		binary.BigEndian.PutUint64(header[headerLen:], uint64(time.Now().Unix()))
		headerLen += lenTs
		conn = &RemainConn{
			Conn:    conn,
			wremain: append(header[:headerLen], opt.RawHeader...),
		}
	}
	if len(opt.Data) > 0 {
		if _, werr := conn.Write(opt.Data); werr != nil {
			err = werr
			return
		}
		opt.Data = nil
	}
	return
}

func DialSSWithOptions(opt *DialOptions) (conn Conn, err error) {
	defer func() {
		if conn != nil {
			if err == nil && len(opt.Data) > 0 {
				_, err = conn.Write(opt.Data)
			}
			if err != nil {
				conn.Close()
				conn = nil
			}
		}
	}()

	c := opt.C

	if len(opt.Target) == 0 && c.MITM && len(opt.Data) > 0 {
		ok, _, msg := utils.ParseTLSClientHelloMsg(opt.Data)
		if ok {
			if len(msg.ServerName) != 0 {
				if strings.ContainsRune(msg.ServerName, ':') {
					opt.Target = msg.ServerName
				} else {
					opt.Target = msg.ServerName + ":443"
				}
			}
		} else {
			parser := utils.NewHTTPHeaderParser(utils.GetBuf(httpbuffersize))
			defer utils.PutBuf(parser.GetBuf())
			ok, _ = parser.Read(opt.Data)
			if ok {
				hosts, ok := parser.Load([]byte("Host"))
				if ok && len(hosts) > 0 && len(hosts[0]) > 0 {
					target := utils.SliceToString(hosts[0])
					if strings.ContainsRune(target, ':') {
						opt.Target = target
					} else {
						opt.Target = target + ":80"
					}
				}
			}
		}
	}

	var direct, proxy bool
	var ip net.IP

	host, _, err := net.SplitHostPort(opt.Target)
	if err != nil {
		return
	}

	ip = net.ParseIP(host)

	if c.Direct {
		direct = true
	} else if ip != nil && c.getChnListCtx() != nil {
		if c.getChnListCtx().testIP(ip) {
			c.LogD("host", host, "hit chn route")
			direct = true
		} else {
			c.LogD("host", host, "miss chn route")
			proxy = true
		}
	} else {
		if !c.AutoProxy || c.getAutoProxyCtx() == nil {
			proxy = true
		} else if c.getAutoProxyCtx().checkIfByPass(host) {
			c.LogD("host", host, "hit bypass list")
			direct = true
		} else if c.getAutoProxyCtx().checkIfProxy(host) {
			c.LogD("host", host, "hit proxy list")
			proxy = true
		} else if host == "localhost" {
			direct = true
		} else if !strings.ContainsRune(host, '.') {
			proxy = true
		}
	}

	if direct {
		return DialTCPConn(opt.Target, opt.C)
	}

	if proxy {
		return dialSSWithOptions(opt)
	}

	die := make(chan bool)
	num := 2
	errch := make(chan error, 2)
	conch := make(chan Conn)

	type dialer func(*DialOptions) (Conn, error)
	work := func(d dialer, direct bool) {
		// Each racer works on its own copy: dialSSWithOptions mutates opt
		// (RawHeader, Data) in flight, and sharing one struct across the two
		// goroutines plus the deferred write below races the pool-owned Data
		// buffer across connections. Data stays nil here — the deferred write
		// in DialSSWithOptions sends it once, to whichever side wins.
		newOpt := *opt
		newOpt.Data = nil
		rconn, err := d(&newOpt)
		if err != nil {
			select {
			case <-die:
			case errch <- err:
			}
			return
		}
		select {
		case <-die:
			rconn.Close()
		case conch <- rconn:
			if ip == nil {
				if direct {
					c.getAutoProxyCtx().markHostByPass(host)
					c.LogD("add", host, "to bypass list")
				} else {
					c.getAutoProxyCtx().markHostNeedProxy(host)
					c.LogD("add", host, "to proxy list")
				}
			}
		}
	}

	go work(dialSSWithOptions, false)
	go work(func(opt *DialOptions) (Conn, error) { return DialTCPConn(opt.Target, opt.C) }, true)

	for i := 0; i < num; i++ {
		select {
		case conn = <-conch:
			close(die)
			i = num
			err = nil
		case err = <-errch:
		}
	}

	return
}
