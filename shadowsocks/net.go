package ss

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/domain"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	"github.com/ccsexyz/shadowsocks-go/redir"
	"github.com/gorilla/websocket"
)

type chListener struct {
	ch   chan net.Conn
	addr net.Addr
}

func (cl *chListener) Accept() (net.Conn, error) {
	conn, ok := <-cl.ch
	if !ok {
		return nil, fmt.Errorf("channel closed")
	}
	return conn, nil
}

func (cl *chListener) Addr() net.Addr {
	return cl.addr
}

func (cl *chListener) Close() error {
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
	RedirAcceptor  = AcceptHandler(redirAcceptor)
)

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
		l.httpsrv = &http.Server{Handler: l}
		go func() {
			err := l.httpsrv.Serve(&chListener{ch: l.httpch, addr: lis.Addr()})
			if err != nil {
				l.errch <- err
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
	target, _ := lis.c.TargetMap[strings.ToLower(host)]
	return target
}

func (lis *listener) getHttpProxyTarget(r *http.Request) string {
	if r != nil {
		for key, values := range r.Header {
			for _, value := range values {
				tKey := fmt.Sprintf("%s %s", key, value)

				target := lis.getTargetByHost(tKey)
				if len(target) > 0 {
					return target
				}
			}
		}

		uriKey := fmt.Sprintf("%s %s", r.Method, r.RequestURI)
		target := lis.getTargetByHost(uriKey)
		if len(target) > 0 {
			return target
		}
	}

	return lis.getTargetByHost("http_proxy_to")
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
				if operr.Timeout() {
					time.Sleep(time.Second)
					continue
				}
			}
			lis.errch <- err
			return
		}
		if isWstunnel {
			lis.httpch <- conn
			continue
		}
		go lis.handleNewConn(newBaseConn(utils.NewConn(conn), lis.c))
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
	select {
	case <-lis.die:
	default:
		close(lis.die)
	}
	if lis.httpsrv != nil {
		lis.httpsrv.Close()
	}
	return lis.rawlis.Close()
}

func (lis *listener) Accept() (conn net.Conn, err error) {
	for {
		select {
		case <-lis.die:
			err = <-lis.errch
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
				accepted := &AcceptedConn{
					Conn:   newStatConn(result.Conn, lis.c.getStat()),
					Target: result.Conn.GetDst(),
					Config: lis.c,
				}
				conn = accepted
				return
			}
		}
	}
}

// Listen creates a TCP or virtual listener with the given handler chain.
func Listen(address string, c *Config, handlers []AcceptHandler) (net.Listener, error) {
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

func (lis *listener) drainPool(handler AcceptHandler) {
	go func() {
		for {
			conn, err := lis.c.getPool().Get()
			if err != nil {
				return
			}
			obfsconn, ok := conn.(*ObfsConn)
			if !ok {
				conn.Close()
				return
			}
			obfsconn.wremain = []byte(buildHTTPResponse(""))
			obfsconn.req = true
			obfsconn.chunkLen = 0
			go func(obfsconn *ObfsConn) {
				result := handler(obfsconn, lis)
				if result.Action != AcceptContinue {
					return
				}
				select {
				case <-lis.die:
					obfsconn.RemainConn.Close()
					result.Conn.Close()
				case lis.connch <- result.Conn:
				}
			}(obfsconn)
		}
	}()
}

func backendSorter(lis *listener) {
	ticker := time.NewTicker(30 * time.Second)
	i := 0
	for {
		i++
		select {
		case <-ticker.C:
		case <-lis.die:
			return
		}
		backends := make([]*Config, len(lis.c.Backends))
		lis.c.getTCPFilterLock().Lock()
		copy(backends, lis.c.Backends)
		sort.SliceStable(backends, func(i, j int) bool {
			ihits := *(backends[i].initRuntime().Any.(*int))
			jhits := *(backends[j].initRuntime().Any.(*int))
			return jhits < ihits
		})
		if i%60 == 0 {
			for _, v := range backends {
				*(v.initRuntime().Any.(*int)) /= 2
			}
		}
		lis.c.Backends = backends
		lis.c.getTCPFilterLock().Unlock()
	}
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

	ssConn := newCryptoConn(conn, newCipherStreamCodec(enc, dec))
	conn = ssConn
	if len(data) != 0 {
		conn = &RemainConn{Conn: ssConn, remain: data}
	}
	conn.SetDst(addr)
	c = conn
	chs.LogD("choose", chs.Method, chs.Password, addr.Host(), addr.Port())
	return
}

func ssMultiAcceptHandler(conn Conn, lis *listener) AcceptResult {
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err := conn.Read(buf)
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}

	ctx, err := ParseAddrWithMultipleBackends(buf[:n], lis.c.Backends)
	if err != nil {
		conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		nn, rerr := conn.Read(buf[n:])
		conn.SetReadDeadline(time.Time{})
		if rerr == nil && nn > 0 {
			n += nn
			ctx, err = ParseAddrWithMultipleBackends(buf[:n], lis.c.Backends)
		}
		if err != nil {
			lis.c.Log("recv an unexpected header from", conn.RemoteAddr().String(),
				"numBackends:", len(lis.c.Backends),
				"read:", n, "bytes", "raw:", buf[:n],
				"err:", err)
			return AcceptResult{AcceptReject, nil}
		}
	}
	if ctx.cliCipher != nil {
		c := ss2022MultiAcceptHandler2(conn, lis, ctx)
		if c == nil {
			return AcceptResult{AcceptReject, nil}
		}
		return AcceptResult{AcceptContinue, c}
	}
	c := ssMultiAcceptHandler2(conn, lis, ctx.addr, n, ctx.data, ctx.dec, ctx.chs)
	if c == nil {
		return AcceptResult{AcceptReject, nil}
	}
	return AcceptResult{AcceptContinue, c}
}

func ss2022MultiAcceptHandler2(conn Conn, lis *listener, ctx *parseContext) (c Conn) {
	chs := ctx.chs

	psk, err := crypto.DecodePSK(chs.Password, chs.Ivlen)
	if err != nil {
		lis.c.Log("decode PSK failed:", err)
		return
	}

	svSalt := utils.GetRandomBytes(chs.Ivlen)
	ssConn := newCryptoConn(conn, newServerAead2022Codec(chs.Method, psk, svSalt, ctx.cliSalt, ctx.cliCipher))
	conn = ssConn
	if len(ctx.data) != 0 {
		conn = &RemainConn{Conn: ssConn, remain: ctx.data}
	}
	conn.SetDst(ctx.addr)
	c = conn
	chs.LogD("choose SS2022", chs.Method, ctx.addr.Host(), ctx.addr.Port())
	return
}

func ssAcceptHandler(conn Conn, lis *listener) AcceptResult {
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err := conn.Read(buf)
	defer func() {
		if err != nil {
			lis.c.Log("recv an unexpected header from", conn.RemoteAddr().String(),
				"method:", lis.c.Method,
				"err:", err,
				"read:", n, "bytes",
				"raw:", buf[:n])
		}
	}()
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}
	if n < lis.c.Ivlen+2 {
		err = fmt.Errorf("too short: got %d bytes, need at least iv(%d)+2=%d", n, lis.c.Ivlen, lis.c.Ivlen+2)
		return AcceptResult{AcceptReject, nil}
	}
	dec, err := crypto.NewDecrypter(lis.c.Method, lis.c.Password)
	if err != nil {
		lis.c.Log(err)
		return AcceptResult{AcceptReject, nil}
	}
	_, err = dec.Write(buf[:n])
	if err != nil {
		err = fmt.Errorf("dec.Write failed: %w (method=%s, input=%d bytes: %x)", err, lis.c.Method, n, buf[:n])
		return AcceptResult{AcceptReject, nil}
	}
	dbuf := utils.GetBuf(buffersize)
	defer utils.PutBuf(dbuf)
	dn, err := dec.Read(dbuf)
	if err != nil {
		conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		nn, rerr := conn.Read(buf[n:])
		conn.SetReadDeadline(time.Time{})
		if rerr == nil && nn > 0 {
			n += nn
			dec, err = crypto.NewDecrypter(lis.c.Method, lis.c.Password)
			if err != nil {
				lis.c.Log(err)
				return AcceptResult{AcceptReject, nil}
			}
			_, err = dec.Write(buf[:n])
			if err != nil {
				err = fmt.Errorf("dec.Write(2nd) failed: %w (method=%s, total=%d bytes)", err, lis.c.Method, n)
				return AcceptResult{AcceptReject, nil}
			}
			dn, err = dec.Read(dbuf)
		}
		if err != nil {
			err = fmt.Errorf("dec.Read failed: %w (method=%s, input=%d bytes: %x)", err, lis.c.Method, n, buf[:n])
			return AcceptResult{AcceptReject, nil}
		}
	}
	addr, data, err := ParseAddr(dbuf[:dn])
	if err != nil {
		err = fmt.Errorf("ParseAddr after decrypt: %w (method=%s, decrypted=%d bytes: %x)", err, lis.c.Method, dn, dbuf[:dn])
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
			return AcceptResult{AcceptReject, nil}
		}
	}
	enc, err := crypto.NewEncrypter(lis.c.Method, lis.c.Password)
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}
	ssConn := newCryptoConn(conn, newCipherStreamCodec(enc, dec))
	if !addr.Nop {
		ssConn.DeferClose()
	}
	if len(data) != 0 {
		conn = &RemainConn{Conn: ssConn, remain: data}
	} else {
		conn = ssConn
	}
	conn.SetDst(addr)
	return AcceptResult{AcceptContinue, conn}
}

func httpProxyAcceptor(conn Conn, lis *listener) AcceptResult {
	parser := utils.NewHTTPHeaderParser(utils.GetBuf(buffersize))
	defer utils.PutBuf(parser.GetBuf())
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return AcceptResult{AcceptReject, nil}
		}
		ok, err := parser.Read(buf[:n])
		if err != nil {
			return AcceptResult{AcceptReject, nil}
		}
		if ok {
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
		_, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if err != nil {
			return AcceptResult{AcceptReject, nil}
		}
		conn = DecayRemainConn(conn)
		conn.SetDst(domain.NewDstAddr(host, port))
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
	}
	rconn.remain = append(rconn.remain, buf...)
	conn.SetDst(domain.NewDstAddr(host, port))
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
	n, err := conn.Read(buf)
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
	conn.SetDst(dstaddr)
	return AcceptResult{AcceptContinue, conn}, true
}

func socks6Detector(conn Conn, buf []byte, n int, lis *listener) (AcceptResult, bool) {
	if buf[0] != verSocks6 || buf[1] != cmdConnect {
		return AcceptResult{}, false
	}
	addr, data, err := ParseAddr(buf[2:n])
	if err != nil {
		return AcceptResult{AcceptReject, nil}, true
	}
	conn.SetDst(addr)
	return AcceptResult{AcceptContinue, &RemainConn{Conn: conn, remain: data}}, true
}

func socks5Detector(conn Conn, buf []byte, n int, lis *listener) (AcceptResult, bool) {
	ver := buf[0]
	cmd := buf[1]
	if ver != verSocks5 {
		return AcceptResult{}, false
	}
	if n != int(cmd)+2 {
		return AcceptResult{AcceptReject, nil}, true
	}
	_, err := conn.Write([]byte{5, 0})
	if err != nil {
		return AcceptResult{AcceptReject, nil}, true
	}
	// Drain pre-loaded greeting bytes from the peeked conn before
	// reading the CONNECT request from the raw connection.
	if rconn, ok := conn.(*RemainConn); ok && len(rconn.remain) > 0 {
		conn = rconn.Conn
	}
	n, err = conn.Read(buf)
	if err != nil {
		return AcceptResult{AcceptReject, nil}, true
	}
	ver = buf[0]
	cmd = buf[1]
	if ver != verSocks5 || (cmd != cmdConnect && cmd != cmdUDP) || (!lis.c.UDPRelay && cmd == cmdUDP) {
		return AcceptResult{AcceptReject, nil}, true
	}
	if lis.c.UDPRelay && cmd == cmdUDP {
		addr, err := net.ResolveUDPAddr("udp", lis.c.Localaddr)
		if err != nil {
			return AcceptResult{AcceptReject, nil}, true
		}
		copy(buf, []byte{5, 0, 0, 1})
		copy(buf[4:], addr.IP.To4())
		binary.BigEndian.PutUint16(buf[8:], uint16(addr.Port))
		_, err = conn.Write(buf[:10])
		for err == nil {
			_, err = conn.Read(buf)
		}
		return AcceptResult{AcceptReject, nil}, true
	}
	addr, _, err := ParseAddr(buf[3:n])
	if err != nil {
		return AcceptResult{AcceptReject, nil}, true
	}
	_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return AcceptResult{AcceptReject, nil}, true
	}
	conn.SetDst(addr)
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
		return AcceptResult{AcceptReject, nil}, true // matched but invalid
	}
	return httpProxyAcceptor(conn, lis), true
}

func ssFallbackDetector(conn Conn, buf []byte, n int, lis *listener) AcceptResult {
	ctx, sserr := ParseAddrWithMultipleBackends(buf[:n], getConfigs(lis.c.Method, lis.c.Password))
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

func redirAcceptor(conn Conn, lis *listener) AcceptResult {
	tconn, err := GetNetTCPConn(conn)
	if err != nil {
		lis.c.Log(err)
		return AcceptResult{AcceptReject, nil}
	}
	target, err := redir.GetOrigDst(tconn)
	if err != nil || len(target) == 0 {
		lis.c.Log(err)
		return AcceptResult{AcceptReject, nil}
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}
	conn.SetDst(domain.NewDstAddr(host, port))
	return AcceptResult{AcceptContinue, conn}
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
