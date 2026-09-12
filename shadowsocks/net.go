package ss

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/domain"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	"github.com/gorilla/websocket"
)

// Listener accepts connections using the project Conn type.
type Listener interface {
	Accept() (Conn, error)
	Close() error
	Addr() net.Addr
}

type chListener struct {
	ch   chan net.Conn
	done chan struct{}
	addr net.Addr
	once sync.Once
}

func (cl *chListener) Accept() (net.Conn, error) {
	select {
	case conn := <-cl.ch:
		return conn, nil
	case <-cl.done:
		// Close queued-but-unaccepted conns instead of leaking them; the
		// channel itself is never closed so a racing send can't panic.
		for {
			select {
			case conn := <-cl.ch:
				conn.Close()
				continue
			default:
			}
			return nil, fmt.Errorf("listener closed")
		}
	}
}

func (cl *chListener) Addr() net.Addr {
	return cl.addr
}

// Close signals the Serve loop to stop. Closing ch directly is not an option:
// the acceptor goroutine may be mid-send on the same channel and a send on a
// closed channel would panic.
func (cl *chListener) Close() error {
	cl.once.Do(func() {
		close(cl.done)
	})
	return nil
}

type AcceptAction int

const (
	AcceptReject AcceptAction = iota // 0 = safe zero value for bare returns
	AcceptContinue
	AcceptDrop
	AcceptDone
)

type AcceptResult struct {
	Action AcceptAction
	Conn   Conn
}

type AcceptHandler func(Conn, *listener) AcceptResult

type listener struct {
	rawlis   net.Listener
	c        *Config
	die      chan bool
	dieOnce  sync.Once
	connch   chan Conn
	errch    chan error
	httpch   chan net.Conn
	httpsrv  *http.Server
	handlers []AcceptHandler
}

// Exported handler variables for building accept-time handler chains.
var (
	LimitHandler   = AcceptHandler(limitAcceptHandler)
	ObfsHandler    = AcceptHandler(obfsAcceptHandler)
	SSHandler      = AcceptHandler(ssAcceptHandler)
	SS2022Handler  = AcceptHandler(ss2022AcceptHandler)
	SSMultiHandler = AcceptHandler(ssMultiAcceptHandler)
	SocksAcceptor  = AcceptHandler(socksAcceptor)
)

func limitAcceptHandler(conn Conn, lis *listener) AcceptResult {
	return AcceptResult{AcceptContinue, &LimitConn{
		Conn:      conn,
		Rlimiters: buildLimiters(lis.c),
	}}
}

func NewListener(lis net.Listener, c *Config, handlers []AcceptHandler) *listener {
	l := &listener{
		rawlis:   lis,
		c:        c,
		handlers: handlers,
		die:      make(chan bool),
		connch:   make(chan Conn, 32),
		httpch:   make(chan net.Conn, 32),
		errch:    make(chan error, 32),
	}
	if c.Type == "wstunnel" {
		// ReadHeaderTimeout bounds unauthenticated slowloris header holds;
		// IdleTimeout reaps dead keep-alive conns. Hijacked (websocket)
		// conns are exempt from both, so relay traffic is unaffected.
		l.httpsrv = &http.Server{
			Handler:           l,
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		go func() {
			err := l.httpsrv.Serve(&chListener{ch: l.httpch, done: make(chan struct{}), addr: lis.Addr()})
			if err != nil {
				select {
				case l.errch <- err:
				default:
				}
			}
		}()
	}
	go l.acceptor()
	return l
}

func checkUpgrade(r *http.Request) bool {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	return upgrade == "websocket"
}

func (lis *listener) checkProto(r *http.Request) bool {
	if lis.c.AllowHTTP {
		return true
	}
	proto := strings.ToLower(r.Header.Get("X-Forwarded-Proto"))
	return proto == "https"
}

func (lis *listener) getTargetByHost(host string) string {
	if lis.c.targetRouter != nil {
		return lis.c.targetRouter.matchHost(host)
	}
	return lis.c.TargetMap[strings.ToLower(host)]
}

func (lis *listener) getHttpProxyTarget(r *http.Request) string {
	if r == nil {
		return ""
	}
	if lis.c.targetRouter != nil {
		return lis.c.targetRouter.matchHTTP(r)
	}
	// Fallback for configs loaded without targetRouter (e.g. tests)
	for key, values := range r.Header {
		for _, value := range values {
			tKey := fmt.Sprintf("%s %s", key, value)
			target := lis.c.TargetMap[strings.ToLower(tKey)]
			if len(target) > 0 {
				return target
			}
		}
	}
	uriKey := fmt.Sprintf("%s %s", r.Method, r.RequestURI)
	target := lis.c.TargetMap[strings.ToLower(uriKey)]
	if len(target) > 0 {
		return target
	}
	return lis.c.TargetMap["http_proxy_to"]
}

func getUpgrader(lis *listener) *websocket.Upgrader {
	checkOrigin := func(r *http.Request) bool { return true }
	if lis.c.SecureOrigin {
		checkOrigin = nil
	}
	return &websocket.Upgrader{
		ReadBufferSize:  10240,
		WriteBufferSize: 10240,
		CheckOrigin:     checkOrigin,
	}
}

func (lis *listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !checkUpgrade(r) || !lis.checkProto(r) {
		if target := lis.getHttpProxyTarget(r); len(target) != 0 {
			utils.HttpProxyTo(w, r, target)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
		return
	}

	conn, err := getUpgrader(lis).Upgrade(w, r, nil)
	if err != nil {
		lis.c.Log(err)
		return
	}

	wConn := newWsConn(conn)
	tConn := newBaseConn(wConn, lis.c)

	target := lis.getTargetByHost(r.Host)
	if len(target) > 0 {
		tConn.SetDst(domain.NewDstAddr(target, ""))
		tConn.SetHost(r.Host)
		select {
		case <-lis.die:
			tConn.Close()
		case lis.connch <- tConn:
		}
		return
	}

	go lis.handleNewConn(tConn)
}

func (lis *listener) acceptor() {
	defer lis.Close()
	isWstunnel := lis.c.Type == "wstunnel"
	for {
		conn, err := lis.rawlis.Accept()
		if err != nil {
			if operr, ok := err.(*net.OpError); ok {
				lis.c.Log(operr.Net, operr.Op, operr.Addr, operr.Err)
				if operr.Timeout() || operr.Temporary() {
					time.Sleep(time.Second)
					continue
				}
			}
			select {
			case lis.errch <- err:
			default:
			}
			return
		}
		if isWstunnel {
			select {
			case lis.httpch <- conn:
			case <-lis.die:
				conn.Close()
			}
			continue
		}
		go lis.handleNewConn(newBaseConn(conn, lis.c))
	}
}

func (lis *listener) handleNewConn(conn Conn) {
	conn.SetReadDeadline(time.Now().Add(time.Second * 4))
	for _, handler := range lis.handlers {
		oldconn := conn
		result := handler(conn, lis)
		switch result.Action {
		case AcceptReject:
			oldconn.Close()
			return
		case AcceptDrop, AcceptDone:
			return
		case AcceptContinue:
			conn = result.Conn
		}
	}
	conn.SetReadDeadline(time.Time{})
	select {
	case <-lis.die:
		conn.Close()
	case lis.connch <- conn:
	}
}

func (lis *listener) Addr() net.Addr {
	return lis.rawlis.Addr()
}

func (lis *listener) Close() error {
	// select-default-close is not atomic: two concurrent Closes (e.g. the
	// config die goroutine and an acceptor's deferred Close) can both see
	// the channel open and panic on the second close.
	lis.dieOnce.Do(func() { close(lis.die) })
	if lis.httpsrv != nil {
		lis.httpsrv.Close()
	}
	return lis.rawlis.Close()
}

func (lis *listener) Accept() (conn Conn, err error) {
	for {
		select {
		case <-lis.die:
			// Non-blocking: the acceptor may have dropped its final error
			// when errch was full, and blocking here would hang shutdown.
			select {
			case err = <-lis.errch:
			default:
				err = fmt.Errorf("cannot accept from closed listener")
			}
			if err == nil {
				err = fmt.Errorf("cannot accept from closed listener")
			}
			return
		case newconn := <-lis.connch:
			result := bultinServiceHandler(newconn, lis)
			switch result.Action {
			case AcceptReject:
				newconn.Close()
				continue
			case AcceptDrop, AcceptDone:
				continue
			case AcceptContinue:
				if lis.c.isDisabled() {
					result.Conn.Close()
					lis.c.LogD("accept: server", lis.c.Nickname, "is disabled")
					continue
				}
				var target Addr
				if cm := getConnMeta(result.Conn); cm != nil {
					target = cm.GetDst()
				}
				accepted := &AcceptedConn{
					Conn:   newStatConn(result.Conn, lis.c.getStat()),
					Target: target,
					Config: lis.c,
				}
				conn = accepted
				return
			}
		}
	}
}

// Listen creates a TCP or virtual listener with the given handler chain.
func Listen(address string, c *Config, handlers []AcceptHandler) (Listener, error) {
	if strings.HasPrefix(address, "@") {
		vl := RegisterVirtualForce(address, c.Nickname)
		return NewListener(vl, c, handlers), nil
	}
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, c, handlers), nil
}

func ssMultiAcceptHandler2(conn Conn, lis *listener, addr *SockAddr, n int,
	data []byte, dec crypto.CipherStream, chs *Config) (c Conn) {
	if chs.Ivlen != 0 && !lis.c.Safe {
		var exists bool
		if addr.Ts {
			exists = !(chs.getTCPIvChecker().check(utils.SliceToString(dec.GetIV())))
		} else {
			exists = chs.tcpFilterTestAndAdd(dec.GetIV())
		}
		if exists {
			lis.c.Log("receive duplicate iv from", conn.RemoteAddr().String(), ", this means that you maight be attacked!")
			return
		}
	}

	enc, err := crypto.NewEncrypter(chs.Method, chs.Password)
	if err != nil {
		lis.c.Log("create encrypter failed", err, "method", chs.Method, "from", conn.RemoteAddr().String())
		return
	}

	ssConn := newCryptoConnStream(conn, enc, dec)
	conn = ssConn
	if len(data) != 0 {
		conn = &RemainConn{Conn: ssConn, remain: slices.Clone(data)}
	}
	if cm, ok := conn.(ConnMeta); ok {
		cm.SetDst(addr)
	}
	setInnerCfg(conn, chs)
	c = conn
	chs.LogD("choose", chs.Method, addr.Host(), addr.Port())
	return
}

func setInnerCfg(conn Conn, cfg *Config) {
	for {
		if bc, ok := conn.(*BaseConn); ok {
			bc.SetCfg(cfg)
			return
		}
		if uw, ok := conn.(Unwrapper); ok {
			c, ok := uw.Unwrap().(Conn)
			if !ok {
				return
			}
			conn = c
		} else {
			return
		}
	}
}

func ssMultiAcceptHandler(conn Conn, lis *listener) AcceptResult {
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err := ReadN(conn, buf, nil)
	if err != nil {
		lis.c.getStat().incReject("other")
		return AcceptResult{AcceptReject, nil}
	}

	ctx, err := ParseAddrWithMultipleBackends(buf[:n], lis.c.SnapshotBackends())
	if err != nil {
		conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		nn, rerr := ReadN(conn, buf[n:], nil)
		conn.SetReadDeadline(time.Time{})
		if rerr == nil && nn > 0 {
			n += nn
			ctx, err = ParseAddrWithMultipleBackends(buf[:n], lis.c.SnapshotBackends())
		}
		if err != nil {
			lis.c.Log("recv an unexpected header from", conn.RemoteAddr().String(),
				"numBackends:", len(lis.c.SnapshotBackends()),
				"read:", n, "bytes", "raw:", buf[:n],
				"err:", err)
			lis.c.getStat().incReject("parse")
			return AcceptResult{AcceptReject, nil}
		}
	}
	if ctx.cliCipher != nil {
		c := ss2022MultiAcceptHandler2(conn, lis, ctx)
		if c == nil {
			lis.c.getStat().incReject("decrypt")
			return AcceptResult{AcceptReject, nil}
		}
		return AcceptResult{AcceptContinue, c}
	}
	c := ssMultiAcceptHandler2(conn, lis, ctx.addr, n, ctx.data, ctx.dec, ctx.chs)
	if c == nil {
		lis.c.getStat().incReject("decrypt")
		return AcceptResult{AcceptReject, nil}
	}
	return AcceptResult{AcceptContinue, c}
}

func ss2022MultiAcceptHandler2(conn Conn, lis *listener, ctx *parseContext) (c Conn) {
	chs := ctx.chs

	// SIP022: check salt for replay before accepting
	saltStr := utils.SliceToString(ctx.cliSalt)
	if !chs.getTCPIvChecker().check(saltStr) {
		chs.Log("reject replayed salt from", conn.RemoteAddr().String())
		return
	}

	psk, err := crypto.DecodePSK(chs.Password, chs.Ivlen)
	if err != nil {
		lis.c.Log("decode PSK failed:", err)
		return
	}

	svSalt := utils.GetRandomBytes(chs.Ivlen)
	ssConn := newServerCryptoConn2022(conn, chs.Method, psk, svSalt, ctx.cliSalt, ctx.cliCipher)
	ssConn.DeferClose()
	conn = ssConn
	if len(ctx.data) != 0 {
		conn = &RemainConn{Conn: ssConn, remain: ctx.data}
	}
	if cm, ok := conn.(ConnMeta); ok {
		cm.SetDst(ctx.addr)
	}
	setInnerCfg(conn, chs)
	c = conn
	chs.LogD("choose SS2022", chs.Method, ctx.addr.Host(), ctx.addr.Port())
	return
}

func ssAcceptHandler(conn Conn, lis *listener) AcceptResult {
	data := make([]byte, buffersize)
	n, err := ReadN(conn, data, nil)
	defer func() {
		if err != nil {
			lis.c.Log("recv an unexpected header from", conn.RemoteAddr().String(),
				"method:", lis.c.Method,
				"err:", err,
				"read:", n, "bytes",
				"raw:", data[:n])
		}
	}()
	if err != nil {
		lis.c.getStat().incReject("other")
		return AcceptResult{AcceptReject, nil}
	}
	if n < lis.c.Ivlen+2 {
		err = fmt.Errorf("too short: got %d bytes, need at least iv(%d)+2=%d", n, lis.c.Ivlen, lis.c.Ivlen+2)
		lis.c.getStat().incReject("other")
		return AcceptResult{AcceptReject, nil}
	}
	dec, err := crypto.NewDecrypter(lis.c.Method, lis.c.Password)
	if err != nil {
		lis.c.Log(err)
		lis.c.getStat().incReject("decrypt")
		return AcceptResult{AcceptReject, nil}
	}
	if err = dec.WriteFrame(data[:n]); err != nil {
		err = fmt.Errorf("dec.WriteFrame failed: %w (method=%s, input=%d bytes: %x)", err, lis.c.Method, n, data[:n])
		lis.c.getStat().incReject("decrypt")
		return AcceptResult{AcceptReject, nil}
	}
	frame, err := dec.ReadFrame(nil)
	if err != nil {
		conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		nn, rerr := ReadN(conn, data[n:], nil)
		conn.SetReadDeadline(time.Time{})
		if rerr == nil && nn > 0 {
			n += nn
			dec, err = crypto.NewDecrypter(lis.c.Method, lis.c.Password)
			if err != nil {
				lis.c.Log(err)
				lis.c.getStat().incReject("decrypt")
				return AcceptResult{AcceptReject, nil}
			}
			if err = dec.WriteFrame(data[:n]); err != nil {
				err = fmt.Errorf("dec.WriteFrame(2nd) failed: %w (method=%s, total=%d bytes)", err, lis.c.Method, n)
				lis.c.getStat().incReject("decrypt")
				return AcceptResult{AcceptReject, nil}
			}
			frame, err = dec.ReadFrame(nil)
		}
		if err != nil {
			err = fmt.Errorf("dec.ReadFrame failed: %w (method=%s, input=%d bytes: %x)", err, lis.c.Method, n, data[:n])
			lis.c.getStat().incReject("decrypt")
			return AcceptResult{AcceptReject, nil}
		}
	}
	if frame == nil {
		err = fmt.Errorf("dec.ReadFrame returned nil frame (method=%s, input=%d bytes)", lis.c.Method, n)
		lis.c.getStat().incReject("decrypt")
		return AcceptResult{AcceptReject, nil}
	}
	pdata := frame
	addr, rest, err := ParseAddr(pdata)
	if err != nil {
		// Never log decrypted payload bytes; on a wrong-but-matching
		// password this would be the user's plaintext traffic.
		err = fmt.Errorf("ParseAddr after decrypt: %w (method=%s, decrypted=%d bytes)", err, lis.c.Method, len(pdata))
		lis.c.getStat().incReject("parse")
		return AcceptResult{AcceptReject, nil}
	}
	if lis.c.Ivlen != 0 && !lis.c.Safe {
		var exists bool
		if addr.Ts {
			exists = !(lis.c.getTCPIvChecker().check(utils.SliceToString(dec.GetIV())))
		} else {
			exists = lis.c.tcpFilterTestAndAdd(dec.GetIV())
		}
		if exists {
			lis.c.Log("receive duplicate iv from", conn.RemoteAddr().String(), ", this means that you maight be attacked!")
			lis.c.getStat().incReject("replay")
			return AcceptResult{AcceptReject, nil}
		}
	}
	enc, err := crypto.NewEncrypter(lis.c.Method, lis.c.Password)
	if err != nil {
		lis.c.getStat().incReject("cipher")
		return AcceptResult{AcceptReject, nil}
	}
	ssConn := newCryptoConnStream(conn, enc, dec)
	if !addr.Nop {
		ssConn.DeferClose()
	}
	if len(rest) != 0 {
		conn = &RemainConn{Conn: ssConn, remain: slices.Clone(rest)}
	} else {
		conn = ssConn
	}
	if cm, ok := conn.(ConnMeta); ok {
		cm.SetDst(addr)
	}
	return AcceptResult{AcceptContinue, conn}
}

func httpProxyAcceptor(conn Conn, lis *listener) AcceptResult {
	parser := utils.NewHTTPHeaderParser(utils.GetBuf(buffersize))
	defer utils.PutBuf(parser.GetBuf())
	buf := make([]byte, 4096)
	// Bytes that followed the header inside the last segment (a small POST
	// body, pipelined request) — the parser consumes them but they belong to
	// the tunneled stream, so they are replayed after the rewritten header.
	// Copied immediately: the Encode below reuses buf and would clobber them.
	var excess []byte
	fed := 0
	lastN := 0
	for {
		n, err := ReadN(conn, buf, nil)
		if err != nil {
			return AcceptResult{AcceptReject, nil}
		}
		fed += n
		lastN = n
		ok, err := parser.Read(buf[:n])
		if err != nil {
			return AcceptResult{AcceptReject, nil}
		}
		if ok {
			if over := fed - parser.HeaderLen(); over > 0 {
				// over is bounded by lastN: the header must complete inside
				// the final segment, so the excess is its tail. Clamp anyway
				// so a parser that reports completion early can't make the
				// slice bounds go negative.
				if over > lastN {
					over = lastN
				}
				excess = append(excess, buf[lastN-over:lastN]...)
			}
			break
		}
	}
	requestMethod, err := parser.GetFirstLine1()
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}
	requestURI, err := parser.GetFirstLine2()
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}
	uri := utils.SliceToString(requestURI)
	if bytes.Equal(requestMethod, []byte("CONNECT")) {
		host, port, err := net.SplitHostPort(uri)
		if err != nil {
			return AcceptResult{AcceptReject, nil}
		}
		_, err = io.WriteString(AsReadWriteCloser(conn, nil), "HTTP/1.1 200 Connection Established\r\n\r\n")
		if err != nil {
			return AcceptResult{AcceptReject, nil}
		}
		// Bytes that followed the CONNECT header belong to the tunneled
		// stream. The parse buffer is 4KB while the peeked segment can be
		// much larger, so the excess may be split: what the parser consumed
		// beyond the header (excess) comes first in stream order, then any
		// bytes the parse buffer never reached (the peeked conn's remain).
		if rconn, ok := conn.(*RemainConn); ok {
			var newRemain []byte
			newRemain = append(newRemain, excess...)
			newRemain = append(newRemain, rconn.remain...)
			rconn.remain = newRemain
		} else if len(excess) > 0 {
			conn = &RemainConn{Conn: conn, remain: excess}
		}
		conn = DecayRemainConn(conn)
		if cm, ok := conn.(ConnMeta); ok {
			cm.SetDst(domain.NewDstAddr(host, port))
		}
		return AcceptResult{AcceptContinue, conn}
	}
	if bytes.HasPrefix(requestURI, []byte("http://")) {
		requestURI = requestURI[7:]
	}
	it := bytes.IndexByte(requestURI, '/')
	if it < 0 {
		return AcceptResult{AcceptReject, nil}
	}
	ok := parser.StoreFirstline2(requestURI[it:])
	if !ok {
		return AcceptResult{AcceptReject, nil}
	}
	hosts, ok := parser.Load([]byte("Host"))
	if !ok || len(hosts) == 0 || len(hosts[0]) == 0 {
		return AcceptResult{AcceptReject, nil}
	}
	dst := string(hosts[0])
	var portSep string
	if dst[0] == '[' {
		portSep = "]:"
	} else {
		portSep = ":"
	}
	it = strings.Index(dst, portSep)
	if it < 0 {
		dst = dst + ":80"
	}
	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}
	proxys, ok := parser.Load([]byte("Proxy-Connection"))
	if ok && len(proxys) > 0 && len(proxys[0]) > 0 {
		parser.Store([]byte("Connection"), proxys[0])
		parser.Delete([]byte("Proxy-Connection"))
	}
	n, err := parser.Encode(buf)
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}
	buf = buf[:n]
	rconn, ok := conn.(*RemainConn)
	if !ok {
		rconn = &RemainConn{Conn: conn}
		conn = rconn
	}
	// Stream order after the rewrite: rewritten header, then the excess the
	// parser consumed past the header, then any peek bytes the 4KB parse
	// buffer never reached (a large single segment splits the payload).
	pending := append([]byte{}, rconn.remain...)
	rconn.remain = rconn.remain[:0]
	rconn.remain = append(rconn.remain, buf...)
	rconn.remain = append(rconn.remain, excess...)
	rconn.remain = append(rconn.remain, pending...)
	if cm, ok := conn.(ConnMeta); ok {
		cm.SetDst(domain.NewDstAddr(host, port))
	}
	return AcceptResult{AcceptContinue, conn}
}

type Acceptor func(net.Conn) net.Conn

func getConfigs(method, password string) []*Config {
	cfgs := getConfigs0(method, password)
	for _, cfg := range cfgs {
		CheckBasicConfig(cfg)
	}
	return cfgs
}

func getConfigs0(method, password string) []*Config {
	if method != "multi" && len(method) != 0 {
		return []*Config{
			&Config{CryptoConfig: CryptoConfig{Method: method, Password: password}},
		}
	} else {
		return []*Config{
			&Config{CryptoConfig: CryptoConfig{Method: "aes-128-gcm", Password: password}},
			&Config{CryptoConfig: CryptoConfig{Method: "aes-192-gcm", Password: password}},
			&Config{CryptoConfig: CryptoConfig{Method: "aes-256-gcm", Password: password}},
			&Config{CryptoConfig: CryptoConfig{Method: "chacha20poly1305", Password: password}},
		}
	}
}

// protocolDetector is a single protocol detection function.
// It receives a connection pre-loaded with peek data, and the original peeked buffer.
// Returns (result, matched) — matched=false means the detector did not recognize the protocol.
type protocolDetector func(conn Conn, buf []byte, n int, lis *listener) (AcceptResult, bool)

func socksAcceptor(conn Conn, lis *listener) AcceptResult {
	if lis.c.MITM {
		return AcceptResult{AcceptContinue, conn}
	}
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err := ReadN(conn, buf, nil)
	if err != nil || n < 2 {
		return AcceptResult{AcceptReject, nil}
	}

	// The peeked conn replays the initial bytes so detectors that need
	// to re-read them (e.g. httpProxyAcceptor) don't lose data.
	peeked := &RemainConn{remain: DupBuffer(buf[:n]), Conn: conn}

	detectors := []protocolDetector{
		socks4Detector,
		socks6Detector,
		socks5Detector,
		httpProxyDetector,
	}
	for _, d := range detectors {
		result, matched := d(peeked, buf, n, lis)
		if matched {
			return result
		}
	}

	// SS fallback: try shadowsocks protocol if SSProxy mode is enabled
	if lis.c.SSProxy {
		return ssFallbackDetector(conn, buf, n, lis)
	}
	return AcceptResult{AcceptReject, nil}
}

func socks4Detector(conn Conn, buf []byte, n int, lis *listener) (AcceptResult, bool) {
	ver := buf[0]
	cmd := buf[1]
	if ver != verSocks4 || cmd != cmdConnect {
		return AcceptResult{}, false
	}
	if n < 9 || buf[n-1] != 0 {
		return AcceptResult{AcceptReject, nil}, true
	}
	var dstaddr Addr
	if buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0 {
		// socks4a
		var firstNullIdx int
		for firstNullIdx = 8; firstNullIdx < n-1 && buf[firstNullIdx] != 0; firstNullIdx++ {
		}
		if firstNullIdx == n-1 {
			return AcceptResult{AcceptReject, nil}, true
		}
		port := strconv.Itoa(int(binary.BigEndian.Uint16(buf[2:4])))
		host := string(buf[firstNullIdx+1 : n-1])
		dstaddr = domain.NewDstAddr(host, port)
	} else {
		addrbuf := make([]byte, lenIPv4+3)
		addrbuf[0] = typeIPv4
		copy(addrbuf[lenIPv4+1:], buf[2:4])
		copy(addrbuf[1:lenIPv4+1], buf[4:4+lenIPv4])
		dstaddr = &SockAddr{Hdr: addrbuf}
	}
	buf[0] = verSocks4Resp
	buf[1] = cmdSocks4OK
	_, err := conn.Write(buf[:8])
	if err != nil {
		return AcceptResult{AcceptReject, nil}, true
	}
	// Drop the peeked SOCKS4 request: it is protocol framing, not payload.
	// Returning the RemainConn as-is would replay the request bytes
	// (VER CMD DSTPORT DSTIP USERID) into the tunneled stream.
	if rconn, ok := conn.(*RemainConn); ok {
		conn = rconn.Conn
	}
	if cm, ok := conn.(ConnMeta); ok {
		cm.SetDst(dstaddr)
	}
	return AcceptResult{AcceptContinue, conn}, true
}

func socks6Detector(conn Conn, buf []byte, n int, lis *listener) (AcceptResult, bool) {
	if buf[0] != verSocks6 || buf[1] != cmdConnect {
		return AcceptResult{}, false
	}
	if n < 3 {
		// Not enough bytes for VER+CMD+ATYP; ParseAddr(buf[2:n]) would panic.
		return AcceptResult{AcceptReject, nil}, true
	}
	addr, data, err := ParseAddr(buf[2:n])
	if err != nil {
		return AcceptResult{AcceptReject, nil}, true
	}
	// Strip the full peeked request (VER+CMD+address) and keep only the
	// post-address bytes as replay data. Wrapping the already-wrapped peeked
	// conn used to replay data followed by the whole request into the
	// tunneled stream.
	base := conn
	if rconn, ok := conn.(*RemainConn); ok {
		base = rconn.Conn
	}
	if len(data) > 0 {
		base = &RemainConn{Conn: base, remain: slices.Clone(data)}
	}
	if cm, ok := base.(ConnMeta); ok {
		cm.SetDst(addr)
	}
	return AcceptResult{AcceptContinue, base}, true
}

func socks5Detector(conn Conn, buf []byte, n int, lis *listener) (AcceptResult, bool) {
	ver := buf[0]
	if ver != verSocks5 {
		return AcceptResult{}, false
	}
	if n < 2 {
		return AcceptResult{AcceptReject, nil}, true
	}
	nmethods := int(buf[1])
	greetingLen := 2 + nmethods
	if n < greetingLen {
		// RFC 1928 clients may split the greeting across TCP segments and
		// the peeked read consumed only the first ones. Accumulate the
		// remainder from the raw connection — reading through the peeked
		// RemainConn would replay bytes already consumed. greetingLen is
		// at most 257, far below the buffer, and the accept deadline bounds
		// a client that never sends the rest.
		raw := conn
		if rconn, ok := conn.(*RemainConn); ok {
			raw = rconn.Conn
		}
		for n < greetingLen {
			nn, rerr := ReadN(raw, buf[n:greetingLen], nil)
			if rerr != nil || nn == 0 {
				return AcceptResult{AcceptReject, nil}, true
			}
			n += nn
		}
	}
	// RFC 1928 method negotiation: this server only implements no-auth, so
	// accept only when the client offered it and reply NO ACCEPTABLE METHODS
	// otherwise. Replying {5,0} unconditionally broke strict clients that
	// only offer user/pass.
	hasNoAuth := false
	for _, m := range buf[2:greetingLen] {
		if m == 0 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		conn.Write([]byte{verSocks5, 0xFF})
		return AcceptResult{AcceptReject, nil}, true
	}
	_, err := conn.Write([]byte{verSocks5, 0})
	if err != nil {
		return AcceptResult{AcceptReject, nil}, true
	}
	// Re-scope the replayed bytes: drop the greeting, keep any request bytes
	// that arrived in the same segment so the request assembly below sees
	// them instead of losing them with the greeting.
	if rconn, ok := conn.(*RemainConn); ok {
		if n > greetingLen {
			conn = &RemainConn{Conn: rconn.Conn, remain: DupBuffer(buf[greetingLen:n])}
		} else {
			conn = rconn.Conn
		}
	}
	// Assemble the CONNECT/UDP request: it may have arrived partially inside
	// the greeting segment or fragmented across TCP segments. Parse the
	// ATYP-dependent length and read until the full request is buffered;
	// every index below is guarded by have/n checks (a short read used to be
	// able to reach ParseAddr with stale greeting bytes and panic).
	have := 0
	req := 0
	for {
		// Request layout: VER CMD RSV ATYP ADDR PORT — the address header
		// starts at buf[3].
		if have >= 4 {
			switch buf[3] {
			case typeIPv4:
				req = 4 + lenIPv4 + 2
			case typeIPv6:
				req = 4 + lenIPv6 + 2
			case 3:
				if have >= 5 {
					req = 5 + int(buf[4]) + 2
				}
			default:
				return AcceptResult{AcceptReject, nil}, true
			}
		}
		if req != 0 && have >= req {
			break
		}
		if have >= len(buf) {
			return AcceptResult{AcceptReject, nil}, true
		}
		nn, rerr := ReadN(conn, buf[have:], nil)
		if rerr != nil || nn == 0 {
			return AcceptResult{AcceptReject, nil}, true
		}
		have += nn
	}
	n = req
	if buf[0] != verSocks5 || (buf[1] != cmdConnect && buf[1] != cmdUDP) || (!lis.c.UDPRelay && buf[1] == cmdUDP) {
		return AcceptResult{AcceptReject, nil}, true
	}
	if lis.c.UDPRelay && buf[1] == cmdUDP {
		addr, err := net.ResolveUDPAddr("udp", lis.c.Localaddr)
		if err != nil {
			return AcceptResult{AcceptReject, nil}, true
		}
		// Encode BND.ADDR per the resolved address family: with an IPv6
		// Localaddr, addr.IP.To4() returns nil and the old code broadcast
		// junk left over from the client's request in the IPv4 reply.
		var resp []byte
		if ip4 := addr.IP.To4(); ip4 != nil {
			resp = []byte{5, 0, 0, 1}
			resp = append(resp, ip4...)
		} else {
			resp = []byte{5, 0, 0, 4}
			resp = append(resp, addr.IP.To16()...)
		}
		resp = binary.BigEndian.AppendUint16(resp, uint16(addr.Port))
		if _, err := conn.Write(resp); err != nil {
			return AcceptResult{AcceptReject, nil}, true
		}
		// Standard clients hold the UDP ASSOCIATE control connection open and
		// idle. handleNewConn armed a 4s detection deadline that would kill
		// every relay after 4s of TCP silence, so clear it: this drain loop
		// runs for the lifetime of the association and exits when the client
		// disconnects.
		conn.SetReadDeadline(time.Time{})
		for {
			if _, err := ReadN(conn, buf, nil); err != nil {
				break
			}
		}
		return AcceptResult{AcceptReject, nil}, true
	}
	// A client may pipeline payload with the request (one TCP segment). The
	// assembly loop read past the request into buf[req:have], and the peeked
	// RemainConn may still hold bytes the assembly buffer never reached —
	// both belong to the tunneled stream, in stream order.
	base := conn
	if rc, ok := conn.(*RemainConn); ok {
		base = rc.Conn
		var leftover []byte
		if have > req {
			leftover = append(leftover, buf[req:have]...)
		}
		if len(rc.remain) > 0 {
			leftover = append(leftover, rc.remain...)
		}
		if len(leftover) > 0 {
			conn = &RemainConn{Conn: base, remain: leftover}
		} else {
			conn = base
		}
	} else if have > req {
		conn = &RemainConn{Conn: base, remain: append([]byte{}, buf[req:have]...)}
	}
	addr, _, err := ParseAddr(buf[3:n])
	if err != nil {
		return AcceptResult{AcceptReject, nil}, true
	}
	_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return AcceptResult{AcceptReject, nil}, true
	}
	if cm, ok := conn.(ConnMeta); ok {
		cm.SetDst(addr)
	}
	return AcceptResult{AcceptContinue, conn}, true
}

func httpProxyDetector(conn Conn, buf []byte, n int, lis *listener) (AcceptResult, bool) {
	ver := buf[0]
	if ver == verSocks4 || ver == verSocks5 || ver == verSocks6 {
		return AcceptResult{}, false
	}
	parser := utils.NewHTTPHeaderParser(utils.GetBuf(buffersize))
	defer utils.PutBuf(parser.GetBuf())
	_, err := parser.Read(buf[:n])
	if err != nil {
		return AcceptResult{}, false
	}
	return httpProxyAcceptor(conn, lis), true
}

func ssFallbackDetector(conn Conn, buf []byte, n int, lis *listener) AcceptResult {
	// Shared, once-built configs: rebuilding them per connection gave every
	// connection a fresh IV checker, silently disabling salt replay
	// detection on this path (and re-running kdf per conn).
	ctx, sserr := ParseAddrWithMultipleBackends(buf[:n], lis.c.getSSProxyConfigs())
	if sserr != nil {
		lis.c.Log("receive invalid header from", conn.RemoteAddr().String(),
			"method:", lis.c.Method,
			"read:", n, "bytes", "raw:", buf[:n],
			"errinfo:", sserr)
		return AcceptResult{AcceptReject, nil}
	}
	var c Conn
	if ctx.cliCipher != nil {
		c = ss2022MultiAcceptHandler2(conn, lis, ctx)
	} else {
		c = ssMultiAcceptHandler2(conn, lis, ctx.addr, n, ctx.data, ctx.dec, ctx.chs)
	}
	if c == nil {
		return AcceptResult{AcceptReject, nil}
	}
	return AcceptResult{AcceptContinue, c}
}

func DialUDP(c *Config) (conn Conn, err error) {
	rconn, err := dialUDP(c)
	if err != nil {
		return
	}
	conn = NewUDPConn2(rconn, c)
	return
}

func ListenUDP(c *Config) (*UDPConn, error) {
	lis, err := listenUDP(c)
	if err != nil {
		return nil, err
	}
	return NewUDPConn3(lis, c), nil
}

func ListenMultiUDP(c *Config) (*MultiUDPConn, error) {
	lis, err := listenUDP(c)
	if err != nil {
		return nil, err
	}
	return NewMultiUDPConn(lis, c), nil
}
