package utils

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// AddrCtx carries a ctx inteface and can sotre some control message
type AddrCtx struct {
	net.Addr
	Ctx interface{}
}

// UDPServerCtx is the control centor of the udp server
type UDPServerCtx struct {
	Mtu     int
	Expires int

	once     sync.Once
	connsMap *sync.Map
	die      chan bool
	cm       sync.Mutex
}

func (ctx *UDPServerCtx) init() {
	ctx.once.Do(func() {
		ctx.die = make(chan bool)
		ctx.connsMap = &sync.Map{}
	})
}

func (ctx *UDPServerCtx) close() {
	ctx.cm.Lock()
	defer ctx.cm.Unlock()
	select {
	default:
	case <-ctx.die:
		return
	}
	close(ctx.die)
}

// runUDPServer runs the udp server
// conn is the underlying packet connection
// handle is the processor of new connection
func (ctx *UDPServerCtx) runUDPServer(conn net.PacketConn, handle func(*SubConn)) {
	defer conn.Close()
	ctx.init()
	defer ctx.close()
	buf := make([]byte, ctx.Mtu)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Println(conn.LocalAddr(), err)
			return
		}
		if addr == nil {
			continue
		}
		addrstr := addr.String()
		b := buf[:n]
		v, ok := ctx.connsMap.Load(addrstr)
		if !ok {
			subconn := newSubConn(conn, ctx, addr)
			ctx.connsMap.Store(addrstr, subconn)
			v = subconn
			go handle(subconn)
		}
		subconn := v.(*SubConn)
		subconn.input(b)
	}
}

// RunUDPServer runs the udp server
func (ctx *UDPServerCtx) RunUDPServer(conn net.PacketConn, create func(*SubConn) (net.Conn, net.Conn, error)) {
	ctx.runUDPServer(conn, func(subconn *SubConn) {
		defer subconn.Close()
		c1, c2, err := create(subconn)
		if err != nil {
			return
		}
		defer c1.Close()
		defer c2.Close()
		PipeForUDPServer(c1, c2, ctx)
	})
}

// NewUDPListener simplely calls the net.ListenUDP and create a udp listener
func NewUDPListener(address string) (conn *net.UDPConn, err error) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err == nil {
		conn, err = net.ListenUDP("udp", laddr)
	}
	return
}

// PipeForUDPServer is a simple pipe loop for udp server
func PipeForUDPServer(c1, c2 net.Conn, ctx *UDPServerCtx) {
	c1die := make(chan bool)
	c2die := make(chan bool)
	f := func(dst, src net.Conn, die chan bool) {
		defer close(die)
		var n, nw int
		var err error
		buf := make([]byte, ctx.Mtu)
		for err == nil {
			src.SetReadDeadline(time.Now().Add(time.Second * time.Duration(ctx.Expires)))
			n, err = src.Read(buf)
			if n > 0 || err == nil {
				nw, err = dst.Write(buf[:n])
				if err == nil && nw != n {
					err = io.ErrShortWrite
				}
			}
		}
	}
	go f(c1, c2, c1die)
	go f(c2, c1, c2die)
	select {
	case <-c1die:
	case <-c2die:
	}
}

const (
	defaultSubUDPMTU     = 65535
	defaultSubUDPExpires = 60
)

func newUDPServerCtx() *UDPServerCtx {
	return &UDPServerCtx{
		Expires: defaultSubUDPExpires,
		Mtu:     defaultSubUDPMTU,
	}
}

// SubUDPListener implements net.Listener and acts like tcp net.Listener
type SubUDPListener struct {
	conn   net.PacketConn
	ctx    *UDPServerCtx
	connch chan *SubConn
	once   sync.Once
}

// ListenSubUDP returns net.Listener
func ListenSubUDP(network, address string) (net.Listener, error) {
	return ListenSubUDPWithCtx(network, address, newUDPServerCtx())
}

// ListenSubUDPWithConn returns net.Listener
func ListenSubUDPWithConn(conn net.PacketConn) (net.Listener, error) {
	return ListenSubUDPWithConnAndCtx(conn, newUDPServerCtx())
}

// ListenSubUDPWithCtx returns net.Listener
func ListenSubUDPWithCtx(network, address string, ctx *UDPServerCtx) (net.Listener, error) {
	laddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	return ListenSubUDPWithConnAndCtx(conn, ctx)
}

// ListenSubUDPWithConnAndCtx returns net.Listener
func ListenSubUDPWithConnAndCtx(conn net.PacketConn, ctx *UDPServerCtx) (net.Listener, error) {
	listener := &SubUDPListener{
		conn:   conn,
		ctx:    ctx,
		connch: make(chan *SubConn, 16),
	}
	return listener, nil
}

// Close close listener and destroy everything
func (listener *SubUDPListener) Close() error {
	if listener.conn != nil {
		listener.conn.Close()
	}
	if listener.ctx != nil {
		listener.ctx.close()
	}
	return nil
}

// Accept accepts a new net.Conn from listner
func (listener *SubUDPListener) Accept() (net.Conn, error) {
	conn, err := listener.AcceptSub()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// AcceptSub accepts a new subconn from listner
func (listener *SubUDPListener) AcceptSub() (*SubConn, error) {
	listener.once.Do(func() {
		listener.ctx.init()
		go listener.runServer()
	})
	select {
	case <-listener.ctx.die:
		return nil, errors.New("acccept from closed listener")
	case subconn := <-listener.connch:
		return subconn, nil
	}
}

// Addr returns the local address of underlying packet connection
func (listener *SubUDPListener) Addr() net.Addr {
	return listener.conn.LocalAddr()
}

func (listener *SubUDPListener) handleNewConn(conn *SubConn) {
	select {
	case <-listener.ctx.die:
		conn.Close()
	case listener.connch <- conn:
	}
}

func (listener *SubUDPListener) runServer() {
	listener.ctx.runUDPServer(listener.conn, listener.handleNewConn)
}

var httpProxyTransport = &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		itarget := ctx.Value("target")
		if itarget != nil {
			target, ok := itarget.(string)
			if ok {
				addr = target
			}
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, addr)
	},
}

func rejectRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func getRequestURL(r *http.Request) string {
	return "http://" + r.Host + r.URL.String()
}

func HttpProxyTo(w http.ResponseWriter, r *http.Request, target string) {
	r2, err := http.NewRequest(r.Method, getRequestURL(r), r.Body)
	if err != nil {
		writeErrorPage(w, err)
		return
	}
	r2 = r2.WithContext(context.WithValue(context.Background(), "target", target))
	for key, values := range r.Header {
		for _, value := range values {
			r2.Header.Add(key, value)
		}
	}
	hc := new(http.Client)
	hc.CheckRedirect = rejectRedirect
	hc.Transport = httpProxyTransport

	resp, err := hc.Do(r2)
	if err != nil {
		writeErrorPage(w, err)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println(err)
	}
}

func writeErrorPage(w http.ResponseWriter, err error) {
	if err != nil {
		w.Header().Set("X-Error-Info", err.Error())
	}
	w.WriteHeader(http.StatusGatewayTimeout)
}
