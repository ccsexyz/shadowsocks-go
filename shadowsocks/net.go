package ss

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ccsexyz/shadowsocks-go/redir"
	"github.com/ccsexyz/utils"
)

type listenHandler func(Conn, *listener) Conn

type listener struct {
	net.TCPListener
	c        *Config
	die      chan bool
	connch   chan Conn
	errch    chan error
	handlers []listenHandler
}

func NewListener(lis *net.TCPListener, c *Config, handlers []listenHandler) *listener {
	l := &listener{
		TCPListener: *lis,
		c:           c,
		handlers:    handlers,
		die:         make(chan bool),
		connch:      make(chan Conn, 32),
		errch:       make(chan error, 1),
	}
	go l.acceptor()
	return l
}

func (lis *listener) acceptor() {
	defer lis.Close()
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

func ssMultiAcceptHandler(conn Conn, lis *listener) (c Conn) {
	ssConn := NewSsConn(conn, lis.c)

	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	rbuf := bufPool.Get().([]byte)
	defer bufPool.Put(rbuf)
	addr, data, dec, chs, err := ParseAddrWithMultipleBackends(buf[:n], rbuf, lis.c.Backends)
	if err != nil {
		lis.c.Log("recv an unexpected header from", conn.RemoteAddr().String())
		return
	}
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
	ssConn.dec = dec
	ssConn.c = chs
	if addr.partEncLen > 0 {
		ssConn.partenc = true
		ssConn.partencnum = addr.partEncLen
		ssConn.decnum = n - chs.Ivlen - len(data)
	}
	conn = ssConn
	if len(data) != 0 {
		conn = &RemainConn{Conn: ssConn, remain: data}
	}
	conn.SetDst(addr)
	if addr.snappy {
		conn = NewSnappyConn(conn)
	}
	c = conn
	chs.LogD("choose", chs.Method, chs.Password, addr.Host(), addr.Port())
	return
}

func ssAcceptHandler(conn Conn, lis *listener) (c Conn) {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	n, err := conn.Read(buf)
	if err != nil || n < lis.c.Ivlen+2 {
		return
	}
	dec, err := utils.NewDecrypter(lis.c.Method, lis.c.Password, buf[:lis.c.Ivlen])
	if err != nil {
		return
	}
	dbuf := bufPool.Get().([]byte)
	defer bufPool.Put(dbuf)
	dec.Decrypt(dbuf, buf[lis.c.Ivlen:n])
	addr, data, err := ParseAddr(dbuf[:n-lis.c.Ivlen])
	if err != nil {
		lis.c.Log("recv an unexpected header from", conn.RemoteAddr().String(), " : ", err)
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
	ssConn := NewSsConn(conn, lis.c)
	if addr.partEncLen > 0 {
		ssConn.partenc = true
		ssConn.partencnum = addr.partEncLen
		ssConn.decnum = n - lis.c.Ivlen - len(data)
	}
	ssConn.dec = dec
	if !addr.nop {
		ssConn.Xu1s()
	}
	conn = ssConn
	if len(data) != 0 {
		conn = &RemainConn{Conn: ssConn, remain: data}
	}
	conn.SetDst(addr)
	if addr.snappy {
		conn = NewSnappyConn(conn)
	}
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
	parser := utils.NewHTTPHeaderParser(bufPool.Get().([]byte))
	defer bufPool.Put(parser.GetBuf())
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
	it = strings.Index(dst, ":")
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

func GetSocksAcceptor(args map[string]interface{}) Acceptor {
	var lis listener
	lis.c = &Config{}
	iaddr, ok := args["localaddr"]
	if ok {
		lis.c.Localaddr, _ = iaddr.(string)
	}
	iudp, ok := args["udprelay"]
	if ok {
		lis.c.UDPRelay, _ = iudp.(bool)
	}
	lis.c.Type = "socksproxy"
	CheckConfig(lis.c)
	return func(conn net.Conn) net.Conn {
		return socksAcceptor(newTCPConn2(conn, lis.c), &lis)
	}
}

func GetShadowAcceptor(args map[string]interface{}) Acceptor {
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

	var lis listener
	lis.c = &Config{
		Safe: true,
	}
	defer func() { CheckConfig(lis.c) }()
	if method == "multi" || method == "" {
		lis.c.Type = "multiserver"
		lis.c.Backends = []*Config{
			&Config{Method: "chacha20", Password: password},
			&Config{Method: "chacha20-ietf", Password: password},
			&Config{Method: "aes-128-cfb", Password: password},
			&Config{Method: "aes-192-cfb", Password: password},
			&Config{Method: "aes-256-cfb", Password: password},
			&Config{Method: "salsa20", Password: password},
			&Config{Method: "rc4-md5", Password: password},
			&Config{Method: "plain", Password: password},
		}
		return func(conn net.Conn) net.Conn {
			return ssMultiAcceptHandler(newTCPConn2(conn, lis.c), &lis)
		}
	}
	lis.c.Method = method
	lis.c.Password = password
	return func(conn net.Conn) net.Conn {
		return ssAcceptHandler(newTCPConn2(conn, lis.c), &lis)
	}
}

func socksAcceptor(conn Conn, lis *listener) (c Conn) {
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}
	ver := buf[0]
	if ver != verSocks4 && ver != verSocks5 && ver != verSocks6 {
		c = httpProxyAcceptor(&RemainConn{remain: buf[:n], Conn: conn}, lis)
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

func DialMultiSS(target string, configs []*Config) (conn Conn, err error) {
	die := make(chan bool)
	num := len(configs)
	errch := make(chan error, num)
	conch := make(chan Conn)
	for _, v := range configs {
		go func(v *Config) {
			rconn, err := dialSS(target, v)
			if err != nil {
				select {
				case <-die:
				case errch <- fmt.Errorf("cannot connect to %s : %s", v.Remoteaddr, err.Error()):
				}
				return
			}
			select {
			case <-die:
				rconn.Close()
			case conch <- rconn:
			}
		}(v)
	}
	for i := 0; i < num; i++ {
		select {
		case conn = <-conch:
			close(die)
			i = num
		case <-errch:
		}
	}
	if conn == nil {
		err = fmt.Errorf("no available backends")
	}
	return
}

func DialSS(target string, c *Config) (conn Conn, err error) {
	var direct, proxy bool
	var ip net.IP

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return
	}

	ip = net.ParseIP(host)

	if ip != nil && c.chnListCtx != nil {
		if c.chnListCtx.testIP(ip) {
			c.LogD("host", host, "hit chn route")
			direct = true
		} else {
			c.LogD("host", host, "miss chn route")
			proxy = true
		}
	} else {
		if c.autoProxyCtx == nil {
			proxy = true
		} else if c.autoProxyCtx.checkIfByPass(host) {
			c.LogD("host", host, "hit bypass list")
			direct = true
		} else if c.autoProxyCtx.checkIfProxy(host) {
			c.LogD("host", host, "hit proxy list")
			proxy = true
		} else if host == "localhost" {
			direct = true
		} else if !strings.ContainsRune(host, '.') {
			proxy = true
		}
	}

	if direct {
		return DialTCPConn(target, c)
	} else if proxy {
		return dialSS(target, c)
	}

	die := make(chan bool)
	num := 2
	errch := make(chan error, 2)
	conch := make(chan Conn)

	type dialer func(string, *Config) (Conn, error)
	work := func(d dialer, direct bool) {
		rconn, err := d(target, c)
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
					c.autoProxyCtx.markHostByPass(host)
					c.LogD("add", host, "to bypass list")
				} else {
					c.autoProxyCtx.markHostNeedProxy(host)
					c.LogD("add", host, "to proxy list")
				}
			}
		}
	}

	go work(dialSS, false)
	go work(DialTCPConn, true)

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

func dialSS(target string, c *Config) (conn Conn, err error) {
	if len(target) > 255 {
		err = fmt.Errorf("target length is too long")
		return
	}
	if len(c.Backends) != 0 {
		return DialMultiSS(target, c.Backends)
	}
	if c.Mux {
		return DialMux(target, c)
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return
	}
	var buf [512]byte
	hdrlen := PutHeader(buf[:], host, portNum)
	return DialSSWithRawHeader(buf[:hdrlen], c)
}

func DialSSWithRawHeader(header []byte, c *Config) (conn Conn, err error) {
	if c.Obfs {
		conn, err = DialObfs(c.Remoteaddr, c)
	} else {
		conn, err = DialTCP(c.Remoteaddr, c)
	}
	if err != nil {
		return
	}
	if len(c.limiters) != 0 || c.LimitPerConn != 0 {
		limiters := make([]*Limiter, len(c.limiters))
		copy(limiters, c.limiters)
		if c.LimitPerConn != 0 {
			limiters = append(limiters, NewLimiter(c.LimitPerConn))
		}
		conn = &LimitConn{
			Conn:      conn,
			Rlimiters: limiters,
		}
	}
	C := NewSsConn(conn, c)
	conn = C
	if c.Nonop {
		rconn := &RemainConn{
			Conn:    conn,
			wremain: make([]byte, len(header)),
		}
		copy(rconn.wremain, header)
		conn = rconn
	} else {
		var port uint16
		if len(header) > 2 {
			port = binary.BigEndian.Uint16(header[len(header)-2:])
		}
		if c.PartEnc || (c.PartEncHTTPS && len(header) > 2 && port == 443) {
			C.partenc = true
			C.partencnum = 16384
			header = append([]byte{typePartEnc, 0x10}, header...)
		}
		useSnappy := (c.Snappy && port != 443)
		if useSnappy {
			header = append([]byte{typeSnappy}, header...)
		}
		noplen := rand.Intn(4)
		noplen += int(crc32.Checksum(header, c.crctbl) % (128 - (lenTs + 5)))
		buf := make([]byte, 1024)
		buf[0] = typeNop
		buf[1] = byte(noplen)
		buf[noplen+2] = typeTs
		binary.BigEndian.PutUint64(buf[noplen+3:], uint64(time.Now().Unix()))
		copy(buf[noplen+2+1+lenTs:], header)
		_, err = conn.Write(buf[:noplen+2+1+lenTs+len(header)])
		if err != nil {
			conn.Close()
			return
		}
		if useSnappy {
			conn = NewSnappyConn(conn)
		}
	}
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
		return DialSS(addr, c)
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
