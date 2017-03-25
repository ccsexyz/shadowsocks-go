package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ccsexyz/shadowsocks-go/redir"
)

type ListenHandler func(net.Conn, *listener) net.Conn

type listener struct {
	net.TCPListener
	c         *Config
	die       chan bool
	connch    chan net.Conn
	err       error
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
			lis.err = err
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
		err = lis.err
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
	if c.Delay {
		handlers = append(handlers, delayAcceptHandler)
	}
	if c.Obfs {
		handlers = append(handlers, obfsAcceptHandler)
	}
	handlers = append(handlers, ssAcceptHandler)
	lis = NewListener(l, c, handlers)
	return
}

type hitsCounter struct {
	hits int64
	c    *Config
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
	var h []hitsCounter
	for _, v := range c.Backends {
		h = append(h, hitsCounter{hits: 0, c: v})
	}
	c.Any = h
	var handlers []ListenHandler
	if c.Delay {
		handlers = append(handlers, delayAcceptHandler)
	}
	if c.Obfs {
		handlers = append(handlers, obfsAcceptHandler)
	}
	handlers = append(handlers, ssMultiAcceptHandler)
	lis = NewListener(l, c, handlers)
	go func(lis *listener) {
		ticker := time.NewTicker(30 * time.Second)
		for {
			select {
			case <-lis.die:
				return
			case <-ticker.C:
			}
			h = c.Any.([]hitsCounter)
			h2 := make([]hitsCounter, len(h))
			copy(h2, h)
			sort.SliceStable(h2, func(i, j int) bool {
				return h2[i].hits > h2[j].hits
			})
			lis.c.Any = h2
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
	timer := time.AfterFunc(time.Second*4, func() {
		conn.Close()
	})
	buf := C.wbuf
	n, err := conn.Read(buf)
	if timer != nil {
		timer.Stop()
		timer = nil
	}
	if err != nil {
		return
	}
	rbuf := C.rbuf
	var dec Decrypter
	lis.IvMapLock.Lock()
	h := lis.c.Any.([]hitsCounter)
	lis.IvMapLock.Unlock()
	for _, vh := range h {
		v := vh.c
		if n <= v.Ivlen {
			continue
		}
		dec, err = NewDecrypter(v.Method, v.Password, buf[:v.Ivlen])
		if err != nil {
			continue
		}
		dec.Decrypt(rbuf, buf[v.Ivlen:n])
		host, port, data := ParseAddr(rbuf[:n-v.Ivlen])
		if len(host) == 0 {
			continue
		}
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
		C.dec = dec
		C.c = v
		conn = &RemainConn{Conn: C, remain: data}
		conn = NewDstConn(conn, net.JoinHostPort(host, strconv.Itoa(port)))
		atomic.AddInt64(&vh.hits, 1)
		c = conn
		return
	}
	return
}

func ssAcceptHandler(conn net.Conn, lis *listener) (c net.Conn) {
	conn = NewConn(conn, lis.c)
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	buf := make([]byte, buffersize)
	n, err := conn.Read(buf)
	if err != nil || n < lis.c.Ivlen + 2 {
		return
	}
	dec, err := NewDecrypter(lis.c.Method, lis.c.Password, buf[:lis.c.Ivlen])
	if err != nil {
		return
	}
	dbuf := make([]byte, buffersize)
	dec.Decrypt(dbuf, buf[lis.c.Ivlen:n])
	host, port, data := ParseAddr(dbuf[:n-lis.c.Ivlen])
	if len(host) == 0 {
		lis.c.Log("recv a unexpected header from %s.", conn.RemoteAddr().String())
		return
	}
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
	C := NewConn(conn, lis.c)
	C.dec = dec
	C.Xu1s()
	conn = &RemainConn{Conn: C, remain: data}
	conn = NewDstConn(conn, net.JoinHostPort(host, strconv.Itoa(port)))
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
	lis = NewListener(l, c, []ListenHandler{socksAcceptor})
	return
}

func socksAcceptor(conn net.Conn, lis *listener) (c net.Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	buf := make([]byte, 512)
	_, err := io.ReadFull(conn, buf[:2])
	if err != nil || buf[0] != 5 {
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
	n, err := conn.Read(buf)
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
	host, port, _ := ParseAddr(buf[3:n])
	if len(host) == 0 {
		return
	}
	_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return
	}
	c = NewDstConn(conn, net.JoinHostPort(host, strconv.Itoa(port)))
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
	lis = NewListener(l, c, []ListenHandler{redirAcceptor})
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
	c = NewDstConn(conn, target)
	return
}

func DialMultiSS(target string, configs []*Config) (conn net.Conn, err error) {
	die := make(chan bool)
	num := len(configs)
	errch := make(chan error, num)
	conch := make(chan net.Conn, num)
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

func DialSS(target, service string, c *Config) (conn net.Conn, err error) {
	if len(target) > 255 {
		err = fmt.Errorf("target length is too long")
		return
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
	if c.Delay {
		conn = NewDelayConn(conn)
	}
	conn = NewConn(conn, c)
	if c.Nonop {
		rconn := &RemainConn{
			Conn: conn,
			remain: make([]byte, len(header)),
		}
		copy(rconn.remain, header)
		conn = rconn
	} else {
		noplen := int(src.Int63() % 128)
		buf := make([]byte, 1024)
		buf[0] = typeNop
		buf[1] = byte(noplen)
		copy(buf[noplen+2:], header)
		_, err = conn.Write(buf[:noplen+2+len(header)])
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
