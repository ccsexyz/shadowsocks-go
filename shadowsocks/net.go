package shadowsocks

import (
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
)

type ListenHandler func(net.Conn, *listener) net.Conn

type Dialer func() (net.Conn, error)

type listener struct {
	net.TCPListener
	c         *Config
	die       chan bool
	connch    chan net.Conn
	errch     chan error
	handlers  []ListenHandler
	IvMap     map[string]bool
	IvMapLock sync.Mutex
}

func NewListener(lis *net.TCPListener, c *Config, handlers []ListenHandler) *listener {
	l := &listener{
		TCPListener: *lis,
		c:           c,
		handlers:    handlers,
		die:         make(chan bool),
		connch:      make(chan net.Conn, 32),
		IvMap:       make(map[string]bool),
		errch:       make(chan error, 1),
	}
	go l.acceptor()
	go l.ivMapCleaner()
	return l
}

func (lis *listener) acceptor() {
	defer lis.Close()
	for {
		conn, err := lis.TCPListener.Accept()
		if err != nil {
			lis.errch <- err
			return
		}
		if len(lis.handlers) == 0 {
			conn.Close()
			continue
		}
		go lis.handleNewConn(conn)
	}
}

func (lis *listener) handleNewConn(conn net.Conn) {
	for _, handler := range lis.handlers {
		conn = handler(conn, lis)
		if conn == nil {
			return
		}
	}
	select {
	case <-lis.die:
		conn.Close()
	case lis.connch <- conn:
	}
}

func (lis *listener) ivMapCleaner() {
	ticker := time.NewTicker(time.Minute)
	flag := false
	for _ = range ticker.C {
		lis.IvMapLock.Lock()
		lenIvMap := len(lis.IvMap)
		if flag && lenIvMap < ivmapLowWaterLevel {
			flag = false
		} else if !flag && lenIvMap > ivmapHighWaterLevel {
			flag = true
		}
		if !flag {
			lis.IvMapLock.Unlock()
			continue
		}
		lenIvMap /= 10
		for k := range lis.IvMap {
			lenIvMap--
			delete(lis.IvMap, k)
			if lenIvMap < 0 {
				break
			}
		}
		lis.IvMapLock.Unlock()
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
	if c.Delay {
		handlers = append(handlers, delayAcceptHandler)
	}
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
	if c.Delay {
		handlers = append(handlers, delayAcceptHandler)
	}
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
			lis.IvMapLock.Lock()
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
			lis.IvMapLock.Unlock()
		}
	}(lis.(*listener))
	return
}

func ssMultiAcceptHandler(conn net.Conn, lis *listener) (c net.Conn) {
	C := NewConn(conn, nil)
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	// timer := time.AfterFunc(time.Second*4, func() {
	// 	conn.Close()
	// })
	buf := C.wbuf
	n, err := conn.Read(buf)
	// if timer != nil {
	// 	timer.Stop()
	// 	timer = nil
	// }
	if err != nil {
		return
	}
	addr, data, dec, chs, err := ParseAddrWithMultipleBackends(buf[:n], C.rbuf, lis.c.Backends)
	if err != nil {
		return
	}
	if chs.Ivlen != 0 {
		iv := string(dec.GetIV())
		lis.IvMapLock.Lock()
		_, ok := lis.IvMap[iv]
		if !ok {
			lis.IvMap[iv] = true
			*(chs.Any.(*int))++
		}
		lis.IvMapLock.Unlock()
		if ok {
			lis.c.Log("receive duplicate iv from %s, this means that you maight be attacked!", conn.RemoteAddr().String())
			return
		}
	}
	C.dec = dec
	C.c = chs
	conn = C
	if len(data) != 0 {
		conn = &RemainConn{Conn: C, remain: data}
	}
	conn = NewDstConn(conn, addr)
	c = conn
	chs.LogD("choose", chs.Method, chs.Password, addr.Host(), addr.Port())
	return
}

func ssAcceptHandler(conn net.Conn, lis *listener) (c net.Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	buf := make([]byte, buffersize)
	n, err := conn.Read(buf)
	if err != nil || n < lis.c.Ivlen+2 {
		return
	}
	dec, err := NewDecrypter(lis.c.Method, lis.c.Password, buf[:lis.c.Ivlen])
	if err != nil {
		return
	}
	dbuf := make([]byte, buffersize)
	dec.Decrypt(dbuf, buf[lis.c.Ivlen:n])
	addr, data, err := ParseAddr(dbuf[:n-lis.c.Ivlen])
	if err != nil {
		lis.c.Log("recv a unexpected header from %s.", conn.RemoteAddr().String())
		return
	}
	if lis.c.Ivlen != 0 {
		iv := string(dec.GetIV())
		lis.IvMapLock.Lock()
		_, ok := lis.IvMap[iv]
		if !ok {
			lis.IvMap[iv] = true
		}
		lis.IvMapLock.Unlock()
		if ok {
			lis.c.Log("receive duplicate iv from %s, this means that you maight be attacked!", conn.RemoteAddr().String())
			return
		}
	}
	C := NewConn(conn, lis.c)
	C.dec = dec
	C.Xu1s()
	conn = C
	if len(data) != 0 {
		copy(C.rbuf, data)
		conn = &RemainConn{Conn: C, remain: C.rbuf[:len(data)]}
	}
	conn = NewDstConn(conn, addr)
	c = conn
	return
}

func muxAcceptHandler(conn net.Conn, lis *listener) (c net.Conn) {
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
	for {
		muxconn, err := mux.Accept()
		if err != nil {
			return
		}
		go lis.muxConnHandler(&MuxConn{conn: dstcon.Conn, Conn: muxconn})
	}
	return
}

func (lis *listener) muxConnHandler(conn net.Conn) {
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

func httpProxyAcceptor(conn net.Conn, lis *listener) (c net.Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	parser := newHTTPRequestParser()
	for {
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		it := 0
		ok := false
		for ; it < n && !ok && err == nil; it++ {
			ok, err = parser.read(buf[it])
		}
		if err != nil {
			return
		}
		if ok {
			break
		}
	}
	if parser.requestMethod == "CONNECT" {
		host, port, err := net.SplitHostPort(parser.requestURI)
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
	parser.requestURI = strings.Replace(parser.requestURI, "http://", "", 1)
	it := strings.Index(parser.requestURI, "/")
	if it < 0 {
		return
	}
	parser.requestURI = parser.requestURI[it:]
	dst, ok := parser.headers["Host"]
	if !ok {
		return
	}
	it = strings.Index(dst, ":")
	if it < 0 {
		dst = dst + ":80"
	}
	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		return
	}
	if v, ok := parser.headers["Proxy-Connection"]; ok {
		parser.headers["Connection"] = v
		delete(parser.headers, "Proxy-Connection")
	}
	rconn, ok := conn.(*RemainConn)
	if !ok {
		rconn = &RemainConn{Conn: conn}
	}
	rconn.remain = append(rconn.remain, []byte(parser.marshal())...)
	c = NewDstConn(rconn, &DstAddr{host: host, port: port})
	return
}

func socksAcceptor(conn net.Conn, lis *listener) (c net.Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	buf := make([]byte, 512)
	n, err := io.ReadFull(conn, buf[:2])
	if err != nil {
		return
	}
	if buf[0] != 5 {
		c = httpProxyAcceptor(&RemainConn{remain: buf[:n], Conn: conn}, lis)
		return
	}
	nmethods := buf[1]
	if nmethods != 0 {
		io.ReadFull(conn, buf[:int(nmethods)])
	}
	_, err = conn.Write([]byte{5, 0})
	if err != nil {
		return
	}
	n, err = conn.Read(buf)
	if err != nil {
		return
	}
	cmd := buf[1]
	if buf[0] != 5 || (cmd != 1 && cmd != 3) || (!lis.c.UDPRelay && cmd == 3) {
		return
	}
	if lis.c.UDPRelay && cmd == 3 {
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

func redirAcceptor(conn net.Conn, lis *listener) (c net.Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	target, err := redir.GetOrigDst(conn)
	if err != nil || len(target) == 0 {
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

func DialMux(target, service string, c *Config) (conn net.Conn, err error) {
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

func DialSS(target, service string, c *Config) (conn net.Conn, err error) {
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

func DialSSWithRawHeader(header []byte, service string, c *Config) (conn net.Conn, err error) {
	if c.Obfs {
		conn, err = DialObfs(service, c)
	} else {
		conn, err = net.Dial("tcp", service)
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
	if c.Delay {
		conn = NewDelayConn(conn)
	}
	conn = NewConn(conn, c)
	if c.Nonop {
		rconn := &RemainConn{
			Conn:   conn,
			remain: make([]byte, len(header)),
		}
		copy(rconn.remain, header)
		conn = rconn
	} else {
		noplen := rand.Intn(128 - (lenTs + 1))
		buf := make([]byte, 1024)
		buf[0] = typeNop
		buf[1] = byte(noplen)
		buf[noplen+2] = typeTs
		binary.BigEndian.PutUint64(buf[noplen+3:], uint64(time.Now().Unix()))
		copy(buf[noplen+2+1+lenTs:], header)
		_, err = conn.Write(buf[:noplen+2+1+lenTs+len(header)])
		if err != nil {
			conn.Close()
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

func DialUDPOverTCP(target, service string, c *Config) (conn net.Conn, err error) {
	conn, err = DialSS(Udprelayaddr, service, c)
	if err != nil {
		return
	}
	var buf [512]byte
	buf[0] = byte(len(target))
	copy(buf[1:], []byte(target))
	_, err = conn.Write(buf[:1+len(target)])
	if err != nil {
		conn.Close()
		conn = nil
		return
	}
	conn = NewConn2(conn)
	return
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

func (md *MuxDialer) Dial(service string, c *Config) (conn net.Conn, err error) {
	md.lock.Lock()
	muxs := make([]*muxDialerInfo, len(md.muxs))
	copy(muxs, md.muxs)
	timeout := md.timeout * 1414 / 1000
	md.lock.Unlock()
	n := len(muxs)
	die := make(chan bool)
	errch := make(chan error, n)
	expirech := make(chan error, n)
	connch := make(chan net.Conn)
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
				var mconn net.Conn
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
