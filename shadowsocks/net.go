package shadowsocks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ccsexyz/mux"
	"github.com/ccsexyz/shadowsocks-go/redir"
	"github.com/ccsexyz/utils"
)

type ListenHandler func(Conn, *listener) Conn

type listener struct {
	net.TCPListener
	c        *Config
	die      chan bool
	connch   chan net.Conn
	errch    chan error
	handlers []ListenHandler
}

func NewListener(lis *net.TCPListener, c *Config, handlers []ListenHandler) *listener {
	l := &listener{
		TCPListener: *lis,
		c:           c,
		handlers:    handlers,
		die:         make(chan bool),
		connch:      make(chan net.Conn, 32),
		errch:       make(chan error, 1),
	}
	go l.acceptor()
	return l
}

func (lis *listener) acceptor() {
	defer lis.Close()
	for {
		conn, err := lis.TCPListener.Accept()
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
		if len(lis.handlers) == 0 {
			conn.Close()
			continue
		}
		go lis.handleNewConn(Newsconn(conn))
	}
}

func (lis *listener) handleNewConn(conn Conn) {
	conn.SetReadDeadline(time.Now().Add(time.Second * 4))
	for _, handler := range lis.handlers {
		conn = handler(conn, lis)
		if conn == nil {
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
	select {
	case <-lis.die:
		err = <-lis.errch
		if err == nil {
			err = fmt.Errorf("cannot accept from closed listener")
		}
	case conn = <-lis.connch:
	}
	return
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
	var handlers []ListenHandler
	handlers = append(handlers, limitAcceptHandler)
	if c.Obfs {
		handlers = append(handlers, obfsAcceptHandler)
	}
	handlers = append(handlers, ssAcceptHandler)
	if c.Mux {
		handlers = append(handlers, muxAcceptHandler)
	}
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
	var handlers []ListenHandler
	handlers = append(handlers, limitAcceptHandler)
	if c.Obfs {
		handlers = append(handlers, obfsAcceptHandler)
	}
	handlers = append(handlers, ssMultiAcceptHandler)
	if c.Mux {
		handlers = append(handlers, muxAcceptHandler)
	}
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
	C := NewSsConn(conn, nil)
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()

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
	if chs.Ivlen != 0 {
		exists := chs.tcpFilterTestAndAdd(dec.GetIV())
		if exists {
			lis.c.Log("receive duplicate iv from", conn.RemoteAddr().String(), ", this means that you maight be attacked!")
			return
		}
	}
	C.dec = dec
	C.c = chs
	if addr.partEncLen > 0 {
		C.partenc = true
		C.partencnum = addr.partEncLen
		C.decnum = n - chs.Ivlen - len(data)
	}
	conn = C
	if len(data) != 0 {
		conn = &RemainConn{Conn: C, remain: data}
	}
	conn = NewDstConn(conn, addr)
	if addr.snappy {
		conn = NewSnappyConn(conn)
	}
	c = conn
	chs.LogD("choose", chs.Method, chs.Password, addr.Host(), addr.Port())
	return
}

func ssAcceptHandler(conn Conn, lis *listener) (c Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
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
	if lis.c.Ivlen != 0 {
		exists := lis.c.tcpFilterTestAndAdd(dec.GetIV())
		if exists {
			lis.c.Log("receive duplicate iv from", conn.RemoteAddr().String(), ", this means that you maight be attacked!")
			return
		}
	}
	C := NewSsConn(conn, lis.c)
	if addr.partEncLen > 0 {
		C.partenc = true
		C.partencnum = addr.partEncLen
		C.decnum = n - lis.c.Ivlen - len(data)
	}
	C.dec = dec
	if !addr.nop {
		C.Xu1s()
	}
	conn = C
	if len(data) != 0 {
		conn = &RemainConn{Conn: C, remain: data}
	}
	conn = NewDstConn(conn, addr)
	if addr.snappy {
		conn = NewSnappyConn(conn)
	}
	c = conn
	return
}

func muxAcceptHandler(conn Conn, lis *listener) (c Conn) {
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	dstcon, err := GetDstConn(conn)
	if err != nil {
		return
	}
	if dstcon.GetDst() != muxaddr {
		c = conn
		conn = nil
		return
	}
	mux, err := mux.NewMux(dstcon.Conn)
	if err != nil {
		return
	}
	conn = nil
	defer mux.Close()
	for {
		muxconn, err := mux.AcceptMux()
		if err != nil {
			return
		}
		go lis.muxConnHandler(&MuxConn{conn: dstcon.Conn, Conn: muxconn})
	}
	return
}

func (lis *listener) muxConnHandler(conn Conn) {
	buf := make([]byte, 512)
	var err error
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
		}
	}()
	_, err = io.ReadFull(conn, buf[:1])
	if err != nil {
		return
	}
	addrlen := int(buf[0])
	_, err = io.ReadFull(conn, buf[:addrlen])
	if err != nil {
		return
	}
	var dst DstAddr
	dst.host, dst.port, err = net.SplitHostPort(string(buf[:addrlen]))
	if err != nil {
		return
	}
	conn = NewDstConn(conn, &dst)
	select {
	case lis.connch <- conn:
	case <-lis.die:
		conn.Close()
	}
	conn = nil
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
	lis = NewListener(l, c, []ListenHandler{limitAcceptHandler, socksAcceptor})
	return
}

func httpProxyAcceptor(conn Conn, lis *listener) (c Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
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
	uri := SliceToString(requestURI)
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
		c = NewDstConn(conn, &DstAddr{host: host, port: port})
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
	c = NewDstConn(rconn, &DstAddr{host: host, port: port})
	return
}

func SocksAcceptor(conn net.Conn) (c net.Conn) {
	C := Newsconn(conn)
	var lis listener
	lis.c = &Config{}
	return socksAcceptor(C, &lis)
}

func socksAcceptor(conn Conn, lis *listener) (c Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}
	ver := buf[0]
	if ver != verSocks4 && ver != verSocks5 {
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
		c = NewDstConn(conn, dstaddr)
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
		c = NewDstConn(conn, addr)
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
	lis = NewListener(l, c, []ListenHandler{limitAcceptHandler, redirAcceptor})
	return
}

func redirAcceptor(conn Conn, lis *listener) (c Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	tconn, err := GetTCPConn(conn)
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
	c = NewDstConn(conn, &DstAddr{host: host, port: port})
	return
}

func DialMultiSS(target string, configs []*Config) (conn net.Conn, err error) {
	die := make(chan bool)
	num := len(configs)
	errch := make(chan error, num)
	conch := make(chan net.Conn)
	for _, v := range configs {
		go func(v *Config) {
			var rconn net.Conn
			var err error
			if len(v.Remoteaddr) != 0 {
				rconn, err = DialSS(target, v.Remoteaddr, v)
			} else {
				rconn, err = net.Dial("tcp", target)
			}
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

func DialMux(target, service string, c *Config) (conn Conn, err error) {
	conn, err = c.muxDialer.Dial(service, c)
	if err != nil {
		return
	}
	buf := make([]byte, len(target)+1)
	buf[0] = byte(len(target))
	copy(buf[1:], []byte(target))
	buf = buf[:1+int(buf[0])]
	_, err = conn.Write(buf)
	if err != nil {
		conn.Close()
		conn = nil
	}
	return
}

func DialSS(target, service string, c *Config) (conn Conn, err error) {
	if len(target) > 255 {
		err = fmt.Errorf("target length is too long")
		return
	}
	if c.Mux {
		return DialMux(target, service, c)
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
	return DialSSWithRawHeader(buf[:hdrlen], service, c)
}

func DialSSWithRawHeader(header []byte, service string, c *Config) (conn Conn, err error) {
	if c.Obfs {
		conn, err = DialObfs(service, c)
	} else {
		conn, err = Dial("tcp", service)
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
		port := binary.BigEndian.Uint16(header[len(header)-2:])
		if c.PartEnc || (c.PartEncHTTPS && len(header) > 2 && port == 443) {
			C.partenc = true
			C.partencnum = 4096
			header = append([]byte{typePartEnc, 0x4}, header...)
		}
		useSnappy := (c.Snappy && port != 443)
		if useSnappy {
			header = append([]byte{typeSnappy}, header...)
		}
		noplen := rand.Intn(128 - (lenTs + 1))
		buf := make([]byte, 1024)
		buf[0] = typeNop
		buf[1] = byte(noplen)
		copy(buf[noplen+2:], header)
		_, err = conn.Write(buf[:noplen+2+len(header)])
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
	lis, err = net.Listen("tcp", address)
	return
}

func NewTCPDialer() func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
}

func NewSSDialer(c *Config) func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		return DialSS(addr, c.Remoteaddr, c)
	}
}

type MuxDialer struct {
	lock    sync.Mutex
	muxs    []*muxDialerInfo
	timeout time.Duration
}

type muxDialerInfo struct {
	mux *mux.Mux
	ts  time.Time
}

func (md *MuxDialer) Dial(service string, c *Config) (conn Conn, err error) {
	md.lock.Lock()
	muxs := make([]*muxDialerInfo, len(md.muxs))
	copy(muxs, md.muxs)
	timeout := md.timeout * 1414 / 1000
	md.lock.Unlock()
	n := len(muxs)
	die := make(chan bool)
	errch := make(chan error, n)
	expirech := make(chan error, n)
	connch := make(chan Conn)
	timeoutch := time.After(timeout)
	start := time.Now()
	for _, v := range muxs {
		go func(v *muxDialerInfo) {
			if start.After(v.ts) {
				if v.mux.NumOfConns() == 0 {
					v.mux.Close()
					md.lock.Lock()
					nmuxs := len(md.muxs)
					for i, m := range md.muxs {
						if m == v {
							md.muxs[i] = md.muxs[nmuxs-1]
							md.muxs = md.muxs[:nmuxs-1]
							break
						}
					}
					md.lock.Unlock()
				}
				select {
				case <-die:
				case expirech <- fmt.Errorf("connection %v->%v is expired", v.mux.LocalAddr(), v.mux.RemoteAddr()):
				}
				return
			}
			mconn, err := v.mux.Dial()
			if err != nil {
				v.mux.Close()
				md.lock.Lock()
				nmuxs := len(md.muxs)
				for i, m := range md.muxs {
					if m == v {
						md.muxs[i] = md.muxs[nmuxs-1]
						md.muxs = md.muxs[:nmuxs-1]
						break
					}
				}
				md.lock.Unlock()
				select {
				case <-die:
				case errch <- err:
				}
				return
			}
			select {
			case connch <- mconn:
			case <-die:
				mconn.Close()
			}
		}(v)
	}
	f := func() {
		ssconn, err := DialSSWithRawHeader([]byte{typeMux}, service, c)
		if err == nil {
			var smux *mux.Mux
			smux, err = mux.NewMux(ssconn)
			if err == nil {
				var mconn Conn
				mconn, err = smux.Dial()
				if err == nil {
					select {
					case <-die:
					case connch <- mconn:
						md.lock.Lock()
						md.muxs = append(md.muxs, &muxDialerInfo{mux: smux, ts: time.Now().Add(time.Second * 6)})
						md.lock.Unlock()
						return
					}
					mconn.Close()
				}
				smux.Close()
			}
			ssconn.Close()
		}
		select {
		case <-die:
		case errch <- err:
		}
	}
	fstarted := false
	it := 0
out:
	for {
		select {
		case err = <-errch:
			it++
			if it >= n {
				md.lock.Lock()
				nmuxs := len(md.muxs)
				md.lock.Unlock()
				if nmuxs == 0 && !fstarted {
					n++
					fstarted = true
					go f()
				} else {
					break out
				}
			}
		case err = <-expirech:
			if fstarted {
				n--
			} else {
				fstarted = true
				go f()
			}
		case <-timeoutch:
			if fstarted {
				continue out
			}
			n++
			fstarted = true
			go f()
		case conn = <-connch:
			err = nil
			close(die)
			delay := time.Now().Sub(start)
			md.lock.Lock()
			if md.timeout == 0 {
				md.timeout = delay
			} else if delay != 0 {
				md.timeout = (md.timeout*16 + delay) / 17
			}
			md.lock.Unlock()
			break out
		}
	}
	return
}

func DialUDP(c *Config) (conn Conn, err error) {
	rconn, err := net.Dial("udp", c.Remoteaddr)
	if err != nil {
		return
	}
	conn = NewUDPConn(rconn.(*net.UDPConn), c)
	return
}
