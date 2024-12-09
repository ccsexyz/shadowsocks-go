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

type listenHandler func(Conn, *listener) Conn

type listener struct {
	net.TCPListener
	c        *Config
	die      chan bool
	connch   chan Conn
	errch    chan error
	httpch   chan net.Conn
	httpsrv  *http.Server
	handlers []listenHandler
}

func NewListener(lis *net.TCPListener, c *Config, handlers []listenHandler) *listener {
	l := &listener{
		TCPListener: *lis,
		c:           c,
		handlers:    handlers,
		die:         make(chan bool),
		connch:      make(chan Conn, 32),
		httpch:      make(chan net.Conn, 32),
		errch:       make(chan error, 1),
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
	target, _ := lis.c.TargetMap[host]
	return target
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  10240,
	WriteBufferSize: 10240,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func (lis *listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !checkUpgrade(r) || !lis.checkProto(r) {
		if target := lis.getTargetByHost("http_proxy_to"); len(target) != 0 {
			utils.HttpProxyTo(w, r, target)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		lis.c.Log(err)
		return
	}

	wConn := newWsConn(conn)
	tConn := newTCPConn(wConn, lis.c)

	target := lis.getTargetByHost(r.Host)
	if len(target) > 0 {
		tConn.SetDst(&DstAddr{host: target})
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
		conn, err := lis.TCPListener.AcceptTCP()
		if err != nil {
			if operr, ok := err.(*net.OpError); ok {
				lis.c.Log(operr.Net, operr.Op, operr.Addr, operr.Err)
				if operr.Temporary() {
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
		go lis.handleNewConn(newTCPConn(utils.NewConn(conn), lis.c))
	}
}

func (lis *listener) handleNewConn(conn Conn) {
	conn.SetReadDeadline(time.Now().Add(time.Second * 4))
	for _, handler := range lis.handlers {
		conn2 := conn
		conn = handler(conn, lis)
		if conn == nil {
			conn2.Close()
			return
		} else if conn == nilConn {
			return
		}
	}
	conn.SetReadDeadline(time.Time{})
	select {
	case <-lis.die:
		conn.Close()
	case lis.connch <- conn:
	}
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
	return lis.TCPListener.Close()
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
			conn = bultinServiceHandler(newconn, lis)
			if conn == nil {
				newconn.Close()
			} else if conn == nilConn {
				continue
			} else {
				if lis.c.disable {
					conn.Close()
					lis.c.LogD("accept: server", lis.c.Nickname, "is disabled")
					continue
				}
				conn = newStatConn(conn.(Conn), lis.c.stat)
				return
			}
		}
	}
}

func ListenSS(service string, c *Config) (lis net.Listener, err error) {
	addr, err := net.ResolveTCPAddr("tcp", service)
	if err != nil {
		return
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}
	var handlers []listenHandler
	handlers = append(handlers, limitAcceptHandler)
	if c.Obfs {
		handlers = append(handlers, obfsAcceptHandler)
	}
	handlers = append(handlers, ssAcceptHandler)
	li := NewListener(l, c, handlers)
	if c.Obfs && c.pool != nil {
		go func() {
			for {
				conn, err := c.pool.Get()
				if err != nil {
					return
				}
				obfsconn := conn.(*ObfsConn)
				obfsconn.wremain = []byte(buildHTTPResponse(""))
				obfsconn.req = true
				obfsconn.chunkLen = 0
				go func(obfsconn *ObfsConn) {
					conn := ssAcceptHandler(obfsconn, li)
					if conn == nil {
						return
					}
					select {
					case <-li.die:
						obfsconn.RemainConn.Close()
						conn.Close()
					case li.connch <- conn:
					}
				}(obfsconn)
			}
		}()
	}
	lis = li
	return
}

func ListenMultiSS(service string, c *Config) (lis net.Listener, err error) {
	addr, err := net.ResolveTCPAddr("tcp", service)
	if err != nil {
		return
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}
	for _, v := range c.Backends {
		hits := 0
		v.Any = &hits
	}
	var handlers []listenHandler
	handlers = append(handlers, limitAcceptHandler)
	if c.Obfs {
		handlers = append(handlers, obfsAcceptHandler)
	}
	handlers = append(handlers, ssMultiAcceptHandler)
	li := NewListener(l, c, handlers)
	if c.Obfs && c.pool != nil {
		go func() {
			for {
				conn, err := c.pool.Get()
				if err != nil {
					return
				}
				obfsconn := conn.(*ObfsConn)
				obfsconn.wremain = []byte(buildHTTPResponse(""))
				obfsconn.req = true
				obfsconn.chunkLen = 0
				go func(obfsconn *ObfsConn) {
					conn := ssMultiAcceptHandler(obfsconn, li)
					if conn == nil {
						return
					}
					select {
					case <-li.die:
						obfsconn.RemainConn.Close()
						conn.Close()
					case li.connch <- conn:
					}
				}(obfsconn)
			}
		}()
	}
	lis = li
	go func(lis *listener) {
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
			lis.c.tcpFilterLock.Lock()
			copy(backends, lis.c.Backends)
			sort.SliceStable(backends, func(i, j int) bool {
				ihits := *(backends[i].Any.(*int))
				jhits := *(backends[j].Any.(*int))
				return jhits < ihits
			})
			if i%60 == 0 {
				for _, v := range backends {
					*(v.Any.(*int)) /= 2
				}
			}
			lis.c.Backends = backends
			lis.c.tcpFilterLock.Unlock()
		}
	}(lis.(*listener))
	return
}

func ssMultiAcceptHandler2(conn Conn, lis *listener, addr *SockAddr, n int,
	data []byte, dec utils.CipherStream, chs *Config) (c Conn) {
	if chs.Ivlen != 0 && !lis.c.Safe {
		var exists bool
		if addr.ts {
			exists = !(chs.tcpIvChecker.check(utils.SliceToString(dec.GetIV())))
		} else {
			exists = chs.tcpFilterTestAndAdd(dec.GetIV())
		}
		if exists {
			lis.c.Log("receive duplicate iv from", conn.RemoteAddr().String(), ", this means that you maight be attacked!")
			return
		}
	}

	enc, err := utils.NewEncrypter(chs.Method, chs.Password)
	if err != nil {
		lis.c.Log("create encrypter failed", err, "method", chs.Method, "from", conn.RemoteAddr().String())
		return
	}

	ssConn := &SsConn{Conn: conn, dec: dec, enc: enc, c: chs}
	conn = ssConn
	if len(data) != 0 {
		conn = &RemainConn{Conn: ssConn, remain: data}
	}
	conn.SetDst(addr)
	c = conn
	chs.LogD("choose", chs.Method, chs.Password, addr.Host(), addr.Port())
	return
}

func ssMultiAcceptHandler(conn Conn, lis *listener) (c Conn) {
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	ctx, err := ParseAddrWithMultipleBackends(buf[:n], lis.c.Backends)
	if err != nil {
		lis.c.Log("recv an unexpected header from", conn.RemoteAddr().String(), err)
		return
	}
	c = ssMultiAcceptHandler2(conn, lis, ctx.addr, n, ctx.data, ctx.dec, ctx.chs)
	return
}

func ssAcceptHandler(conn Conn, lis *listener) (c Conn) {
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err := conn.Read(buf)
	defer func() {
		if err != nil {
			lis.c.Log("recv an unexpected header from", conn.RemoteAddr().String(), err, buf[:n], n)
		}
	}()
	if err != nil {
		return
	}
	if n < lis.c.Ivlen+2 {
		err = io.ErrShortBuffer
		return
	}
	dec, err := utils.NewDecrypter(lis.c.Method, lis.c.Password)
	if err != nil {
		lis.c.Log(err)
		return
	}
	_, err = dec.Write(buf[:n])
	if err != nil {
		return
	}
	dbuf := utils.GetBuf(buffersize)
	defer utils.PutBuf(dbuf)
	dn, err := dec.Read(dbuf)
	if err != nil {
		return
	}
	addr, data, err := ParseAddr(dbuf[:dn])
	if err != nil {
		return
	}
	if lis.c.Ivlen != 0 && !lis.c.Safe {
		var exists bool
		if addr.ts {
			exists = !(lis.c.tcpIvChecker.check(utils.SliceToString(dec.GetIV())))
		} else {
			exists = lis.c.tcpFilterTestAndAdd(dec.GetIV())
		}
		if exists {
			lis.c.Log("receive duplicate iv from", conn.RemoteAddr().String(), ", this means that you maight be attacked!")
			return
		}
	}
	enc, err := utils.NewEncrypter(lis.c.Method, lis.c.Password)
	if err != nil {
		return
	}
	ssConn := &SsConn{Conn: conn, dec: dec, enc: enc, c: lis.c}
	if !addr.nop {
		ssConn.Xu1s()
	}
	conn = ssConn
	if len(data) != 0 {
		conn = &RemainConn{Conn: ssConn, remain: data}
	}
	conn.SetDst(addr)
	c = conn
	return
}

func ListenSocks5(address string, c *Config) (lis net.Listener, err error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}
	lis = NewListener(l, c, []listenHandler{limitAcceptHandler, socksAcceptor})
	return
}

func httpProxyAcceptor(conn Conn, lis *listener) (c Conn) {
	parser := utils.NewHTTPHeaderParser(utils.GetBuf(buffersize))
	defer utils.PutBuf(parser.GetBuf())
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		ok, err := parser.Read(buf[:n])
		if err != nil {
			return
		}
		if ok {
			break
		}
	}
	requestMethod, err := parser.GetFirstLine1()
	if err != nil {
		return
	}
	requestURI, err := parser.GetFirstLine2()
	if err != nil {
		return
	}
	uri := utils.SliceToString(requestURI)
	if bytes.Equal(requestMethod, []byte("CONNECT")) {
		host, port, err := net.SplitHostPort(uri)
		if err != nil {
			return
		}
		_, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if err != nil {
			return
		}
		conn = DecayRemainConn(conn)
		conn.SetDst(&DstAddr{host: host, port: port})
		c = conn
		return
	}
	if bytes.HasPrefix(requestURI, []byte("http://")) {
		requestURI = requestURI[7:]
	}
	it := bytes.IndexByte(requestURI, '/')
	if it < 0 {
		return
	}
	ok := parser.StoreFirstline2(requestURI[it:])
	if !ok {
		return
	}
	hosts, ok := parser.Load([]byte("Host"))
	if !ok || len(hosts) == 0 || len(hosts[0]) == 0 {
		return
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
		return
	}
	proxys, ok := parser.Load([]byte("Proxy-Connection"))
	if ok && len(proxys) > 0 && len(proxys[0]) > 0 {
		parser.Store([]byte("Connection"), proxys[0])
		parser.Delete([]byte("Proxy-Connection"))
	}
	n, err := parser.Encode(buf)
	if err != nil {
		return
	}
	buf = buf[:n]
	rconn, ok := conn.(*RemainConn)
	if !ok {
		rconn = &RemainConn{Conn: conn}
	}
	rconn.remain = append(rconn.remain, buf...)
	conn.SetDst(&DstAddr{host: host, port: port})
	c = conn
	return
}

type Acceptor func(net.Conn) net.Conn

func GetShadowAcceptor(args map[string]interface{}) Acceptor {
	var lis listener
	lis.c = &Config{Safe: true}

	iaddr, ok := args["localaddr"]
	if ok {
		lis.c.Localaddr, _ = iaddr.(string)
	}
	iudp, ok := args["udprelay"]
	if ok {
		lis.c.UDPRelay, _ = iudp.(bool)
	}
	lis.c.Type = "socksproxy"

	var password string
	var method string
	ipass, ok := args["password"]
	if ok {
		password, _ = ipass.(string)
	}
	imethod, ok := args["method"]
	if ok {
		method, _ = imethod.(string)
	}

	defer func() { CheckConfig(lis.c) }()
	if len(password) != 0 {
		lis.c.SSProxy = true
		lis.c.Backends = getConfigs(method, password)
	}
	return func(conn net.Conn) net.Conn {
		return socksAcceptor(newTCPConn2(conn, lis.c), &lis)
	}
}

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
			&Config{Method: method, Password: password},
		}
	} else {
		return []*Config{
			&Config{Method: "aes-128-gcm", Password: password},
			&Config{Method: "aes-192-gcm", Password: password},
			&Config{Method: "aes-256-gcm", Password: password},
			&Config{Method: "chacha20poly1305", Password: password},
		}
	}
}

func socksAcceptor(conn Conn, lis *listener) (c Conn) {
	if lis.c.MITM {
		c = conn
		return
	}
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}
	var halfOK bool
	if lis.c.SSProxy {
		defer func() {
			if halfOK || c != nil {
				return
			}
			rbuf := utils.GetBuf(buffersize)
			defer utils.PutBuf(rbuf)
			ctx, sserr := ParseAddrWithMultipleBackends(buf[:n], getConfigs(lis.c.Method, lis.c.Password))
			if sserr == nil {
				c = ssMultiAcceptHandler2(conn, lis, ctx.addr, n, ctx.data, ctx.dec, ctx.chs)
			} else {
				lis.c.Log("receive invalid header from", conn.RemoteAddr().String(), "errinfo", sserr)
			}
		}()
	}
	ver := buf[0]
	if ver != verSocks4 && ver != verSocks5 && ver != verSocks6 {
		parser := utils.NewHTTPHeaderParser(utils.GetBuf(buffersize))
		defer utils.PutBuf(parser.GetBuf())
		_, err = parser.Read(buf[:n])
		if err == nil {
			halfOK = true
			c = httpProxyAcceptor(&RemainConn{remain: buf[:n], Conn: conn}, lis)
		}
		return
	}
	cmd := buf[1]
	if ver == verSocks4 && cmd == cmdConnect {
		if n < 9 || buf[n-1] != 0 {
			return
		}
		var dstaddr Addr
		if buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0 {
			// socks4a
			var firstNullIdx int
			for firstNullIdx = 8; firstNullIdx < n-1 && buf[firstNullIdx] != 0; firstNullIdx++ {

			}
			if firstNullIdx == n-1 {
				return
			}
			port := strconv.Itoa(int(binary.BigEndian.Uint16(buf[2:4])))
			host := string(buf[firstNullIdx+1 : n-1])
			dstaddr = &DstAddr{host: host, port: port}
		} else {
			addrbuf := make([]byte, lenIPv4+3)
			addrbuf[0] = typeIPv4
			copy(addrbuf[lenIPv4+1:], buf[2:4])
			copy(addrbuf[1:lenIPv4+1], buf[4:4+lenIPv4])
			dstaddr = &SockAddr{header: addrbuf}
		}
		halfOK = true
		buf[0] = verSocks4Resp
		buf[1] = cmdSocks4OK
		_, err = conn.Write(buf[:8])
		if err != nil {
			return
		}
		conn.SetDst(dstaddr)
		c = conn
		return
	}
	if ver == verSocks6 && cmd == cmdConnect {
		addr, data, err := ParseAddr(buf[2:n])
		if err != nil {
			return
		}
		conn.SetDst(addr)
		c = &RemainConn{Conn: conn, remain: data}
		return
	}
	if ver == verSocks5 {
		if n != int(cmd)+2 {
			return
		}
		halfOK = true
		_, err = conn.Write([]byte{5, 0})
		if err != nil {
			return
		}
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		ver = buf[0]
		cmd = buf[1]
		if ver != verSocks5 || (cmd != cmdConnect && cmd != cmdUDP) || (!lis.c.UDPRelay && cmd == cmdUDP) {
			return
		}
		if lis.c.UDPRelay && cmd == cmdUDP {
			addr, err := net.ResolveUDPAddr("udp", lis.c.Localaddr)
			if err != nil {
				return
			}
			copy(buf, []byte{5, 0, 0, 1})
			copy(buf[4:], addr.IP.To4())
			binary.BigEndian.PutUint16(buf[8:], uint16(addr.Port))
			_, err = conn.Write(buf[:10])
			for err == nil {
				_, err = conn.Read(buf)
			}
			return
		}
		addr, _, err := ParseAddr(buf[3:n])
		if err != nil {
			return
		}
		_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		if err != nil {
			return
		}
		conn.SetDst(addr)
		c = conn
		return
	}
	return
}

func ListenRedir(address string, c *Config) (lis net.Listener, err error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}
	lis = NewListener(l, c, []listenHandler{limitAcceptHandler, redirAcceptor})
	return
}

func redirAcceptor(conn Conn, lis *listener) (c Conn) {
	tconn, err := GetNetTCPConn(conn)
	if err != nil {
		lis.c.Log(err)
		return
	}
	target, err := redir.GetOrigDst(tconn)
	if err != nil || len(target) == 0 {
		lis.c.Log(err)
		return
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return
	}
	conn.SetDst(&DstAddr{host: host, port: port})
	c = conn
	return
}

func ListenTCPTun(address string, c *Config) (lis net.Listener, err error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}
	lis = NewListener(l, c, []listenHandler{})
	return
}

func NewTCPDialer() func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
}

func NewSSDialer(c *Config) func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		return DialSSWithOptions(&DialOptions{Target: addr, C: c})
	}
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
