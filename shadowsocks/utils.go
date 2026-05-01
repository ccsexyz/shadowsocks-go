package ss

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/domain"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

const (
	defaultMethod          = domain.DefaultMethod
	defaultPassword        = domain.DefaultPassword
	defaultTimeout         = domain.DefaultTimeout
	buffersize             = domain.BufferSize
	httpbuffersize         = domain.HTTPBufferSize
	verSocks4Resp          = domain.VerSocks4Resp
	verSocks4              = domain.VerSocks4
	verSocks5              = domain.VerSocks5
	verSocks6              = domain.VerSocks6
	cmdConnect             = domain.CmdConnect
	cmdUDP                 = domain.CmdUDP
	cmdSocks4OK            = domain.CmdSocks4OK
	typeIPv4               = domain.TypeIPv4
	typeTs                 = domain.TypeTs  // timestamp
	typeNop                = domain.TypeNop // [nop 1 byte] [noplen 1 byte (< 128)] [zero data, noplen byte]
	lenIPv4                = domain.LenIPv4
	lenTs                  = domain.LenTs
	defaultObfsHost        = domain.DefaultObfsHost
	defaultFilterCapacity  = domain.DefaultFilterCapacity
	defaultFilterFalseRate = domain.DefaultFilterFalseRate
)

var (
	bufPool *sync.Pool
)

func init() {
	bufPool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, buffersize)
		},
	}
}

type cb func()

var (
	errInvalidHeader = fmt.Errorf("invalid header")
)

func ParseAddr(b []byte) (*domain.SockAddr, []byte, error) {
	return domain.ParseAddr(b)
}

func DupBuffer(b []byte) []byte {
	return domain.DupBuffer(b)
}

func IsTimeoutError(err error) bool {
	return domain.IsTimeoutError(err)
}

func CheckConn(conn net.Conn) bool {
	return domain.CheckConn(conn)
}

var (
	PutHeader = domain.PutHeader
	GetHeader = domain.GetHeader
)

type parseContext struct {
	iv   []byte
	data []byte
	addr *SockAddr
	dec  crypto.CipherStream
	cb   crypto.CipherBlock
	chs  *Config

	cliCipher *crypto.TcpCipher2022
	cliSalt   []byte
}

func ParseAddrWithMultipleBackendsForUDP(b []byte, configs []*Config) (*parseContext, error) {
	ctxs := make([]*parseContext, 0, len(configs))

	b2 := make([]byte, len(b))

	for i, cfg := range configs {
		_ = i
		cb, err := crypto.NewCipherBlock(cfg.Method, cfg.Password)
		if err != nil {
			continue
		}

		p, iv, err := cb.Decrypt(b2, b)
		if err != nil {
			continue
		}

		var addr *SockAddr
		var data []byte

		// Try SIP022 format first, then fall back to legacy ATYP format
		sipHdr, _, _, payload, perr := crypto.ParseSIP022(p)
		if perr == nil {
			addr = &SockAddr{Hdr: DupBuffer(sipHdr)}
			data = payload
		} else {
			addr, data, err = ParseAddr(p)
			if err != nil {
				continue
			}
		}

		ctx := new(parseContext)
		ctx.data = data
		ctx.addr = addr
		ctx.cb = cb
		ctx.chs = cfg
		ctx.iv = iv

		ctxs = append(ctxs, ctx)
	}

	if len(ctxs) == 0 {
		log.Printf("udp multi: all %d backends failed to decrypt (packet len=%d)", len(configs), len(b))
		return nil, errInvalidHeader
	}

	return ctxs[0], nil
}

func ParseAddrWithMultipleBackends(b []byte, configs []*Config) (*parseContext, error) {
	ctxs := make([]*parseContext, 0, len(configs))
	var errs []string

	for i, cfg := range configs {
		if crypto.IsAEAD2022(cfg.Method) {
			ctx, err := tryDecodeAead2022(b, cfg)
			if err != nil {
				errs = append(errs, fmt.Sprintf("backend[%d] 2022 %s: %v", i, cfg.Method, err))
				continue
			}
			ctxs = append(ctxs, ctx)
			continue
		}
		dec, err := crypto.NewDecrypter(cfg.Method, cfg.Password)
		if err != nil {
			errs = append(errs, fmt.Sprintf("backend[%d] %s: NewDecrypter: %v", i, cfg.Method, err))
			continue
		}

		_, err = dec.Write(b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("backend[%d] %s: dec.Write: %v", i, cfg.Method, err))
			continue
		}

		buf, err := io.ReadAll(dec)
		if err != nil {
			errs = append(errs, fmt.Sprintf("backend[%d] %s: dec.Read: %v", i, cfg.Method, err))
			continue
		}

		addr, data, err := ParseAddr(buf)
		if err != nil {
			errs = append(errs, fmt.Sprintf("backend[%d] %s: ParseAddr: %v (decrypted=%d bytes: %x)", i, cfg.Method, err, len(buf), safeHeadHex(buf, 64)))
			continue
		}

		ctx := new(parseContext)
		ctx.data = data
		ctx.addr = addr
		ctx.dec = dec
		ctx.chs = cfg

		ctxs = append(ctxs, ctx)
	}

	if len(ctxs) == 0 {
		detail := strings.Join(errs, "; ")
		return nil, fmt.Errorf("invalid header: all %d backend(s) failed: [%s] (input=%d bytes: %x)", len(configs), detail, len(b), safeHeadHex(b, 64))
	}

	return ctxs[0], nil
}

func safeHeadHex(b []byte, n int) []byte {
	if len(b) > n {
		return []byte(fmt.Sprintf("%x", b[:n]))
	}
	return []byte(fmt.Sprintf("%x", b))
}

// IsTimeoutError checks if the error is a timeout error.

func Pipe(c1, c2 net.Conn, c *Config) {
	defer c1.Close()
	defer c2.Close()
	c1die := make(chan bool)
	c2die := make(chan bool)
	var alive utils.AtomicFlag
	var timeout int
	if c != nil && c.Timeout > 0 {
		timeout = c.Timeout
	}
	f := func(dst, src net.Conn, die chan bool, buf []byte) {
		defer close(die)
		defer utils.PutBuf(buf)
		var n int
		var err error
		for err == nil {
			if timeout > 0 {
				src.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
			}
			n, err = src.Read(buf)
			if err != nil {
				c.LogD("pipe read error:", err, "from", src.RemoteAddr(), "to", src.LocalAddr())
			}
			if n > 0 || err == nil {
				if timeout > 0 {
					dst.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
					alive.Set(true)
				}
				_, err = dst.Write(buf[:n])
				if err != nil {
					c.LogD("pipe write error:", err, "from", src.LocalAddr(), "to", dst.RemoteAddr())
				}
			}
			if err != nil && IsTimeoutError(err) && alive.Test() {
				alive.Set(false)
				c.LogD("pipe read error:", err, "from", src.RemoteAddr(), "to", src.LocalAddr())
				err = nil
			}
		}
	}
	go f(c1, c2, c1die, utils.GetBuf(buffersize))
	go f(c2, c1, c2die, utils.GetBuf(buffersize))
	select {
	case <-c1die:
	case <-c2die:
	}
	return
}

type Limiter struct {
	limit      int
	nbytes     int
	last       int64
	totalBytes int64
	lock       sync.Mutex
}

func NewLimiter(limit int) *Limiter {
	return &Limiter{limit: limit, last: time.Now().UnixNano(), nbytes: limit}
}

func (l *Limiter) Update(nbytes int) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.totalBytes += int64(nbytes)
	if l.limit == 0 {
		return
	}
	ns := time.Now().UnixNano()
	if l.last == 0 {
		l.last = ns
		l.nbytes = l.limit
	}
	l.nbytes -= nbytes
	for l.nbytes <= 0 {
		nextNs := l.last + int64(1000000000)
		if nextNs > ns {
			time.Sleep(time.Nanosecond * time.Duration(nextNs-ns))
		}
		l.last = ns
		l.nbytes += l.limit
	}
}

func (l *Limiter) GetLimit() int {
	return l.limit
}

func (l *Limiter) SetLimit(limit int) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.limit = limit
}

func (l *Limiter) GetTotalBytes() int64 {
	return l.totalBytes
}

func GetInnerConn(conn net.Conn) (c net.Conn, err error) {
	u, ok := conn.(Unwrapper)
	if !ok {
		return nil, fmt.Errorf("unexpected conn with type %T", conn)
	}
	return u.Unwrap(), nil
}

func GetNetTCPConn(conn net.Conn) (c *net.TCPConn, err error) {
	t, err := GetTCPConn(conn)
	if err != nil {
		return
	}
	c, ok := t.Conn.(*net.TCPConn)
	if !ok {
		err = fmt.Errorf("unexpected conn with type %T", conn)
		return
	}
	return
}

func GetTCPConn(conn net.Conn) (c *BaseConn, err error) {
	c, ok := conn.(*BaseConn)
	if !ok {
		conn, err = GetInnerConn(conn)
		if err != nil {
			return
		}
		c, err = GetTCPConn(conn)
	}
	return
}

func GetSsConn(conn net.Conn) (c *CryptoConn, err error) {
	c, ok := conn.(*CryptoConn)
	if !ok {
		conn, err = GetInnerConn(conn)
		if err != nil {
			return
		}
		c, err = GetSsConn(conn)
	}
	return
}

func GetConn(conn net.Conn) (c Conn) {
	var ok bool
	c, ok = conn.(Conn)
	if !ok {
		c = newBaseConn(conn, nil)
	}
	return
}

// CheckConn Check the Conn whether is still alive

type Addr = domain.Addr
type SockAddr = domain.SockAddr
type DstAddr = domain.DstAddr

func checkAddrType(address string) (isDomain, isV4 bool, host string, port int) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return
	}

	ip := net.ParseIP(host)
	if ip == nil {
		isDomain = true
		return
	}

	isV4 = ip.To4() != nil
	return
}

func isAddrDualStack(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		ips, err := net.LookupIP(host)
		if err == nil {
			var hasV4, hasV6 bool

			for _, ip := range ips {
				if ip.To4() != nil {
					hasV4 = true
				} else if ip.To16() != nil {
					hasV6 = true
				}

				if hasV4 && hasV6 {
					return true
				}
			}
		}
	}

	return false
}

func DialTCP(address string, cfg *cfg) (*BaseConn, error) {
	if strings.HasPrefix(address, "@") {
		conn, err := DialVirtual(address)
		if err != nil {
			return nil, err
		}
		return newBaseConn(conn, cfg), nil
	}

	var protocol string
	dialCtx := context.Background()

	if cfg.NoIPv4 {
		protocol = "tcp6"
	} else if cfg.NoIPv6 {
		protocol = "tcp4"
	} else if cfg.PreferIPv4 && isAddrDualStack(address) {
		protocol = "tcp4"
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		dialCtx = ctx
	} else {
		protocol = "tcp"
	}

	var d net.Dialer
	netconn, err := d.DialContext(dialCtx, protocol, address)

	if err != nil && protocol == "tcp4" && !cfg.NoIPv6 && cfg.PreferIPv4 && isAddrDualStack(address) {
		netconn, err = d.DialContext(context.Background(), "tcp", address)
	}
	if err != nil {
		return nil, err
	}

	return newBaseConn(netconn, cfg), nil
}

func DialTCPConn(address string, cfg *cfg) (Conn, error) {
	conn, err := DialTCP(address, cfg)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

const ivCheckerBuckets = 4

type ivChecker struct {
	buckets [ivCheckerBuckets]map[string]bool
	head    int
	expires time.Time
	lock    sync.Mutex
	once    sync.Once
}

func (c *ivChecker) ensureInit() {
	c.once.Do(func() {
		for i := range ivCheckerBuckets {
			c.buckets[i] = make(map[string]bool)
		}
		c.expires = time.Now().Add(time.Second * time.Duration(domain.IvExpireSecond))
	})
}

func (c *ivChecker) rotate() {
	if !time.Now().After(c.expires) {
		return
	}
	c.head = (c.head + 1) % ivCheckerBuckets
	c.buckets[c.head] = make(map[string]bool)
	c.expires = time.Now().Add(time.Second * time.Duration(domain.IvExpireSecond))
}

func (c *ivChecker) check(iv string) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.ensureInit()
	c.rotate()

	for i := range ivCheckerBuckets {
		if c.buckets[i][iv] {
			return false
		}
	}
	c.buckets[c.head][iv] = true
	return true
}

func newAutoProxy() *autoProxy {
	return &autoProxy{
		byPassDmRoot: utils.NewDomainRoot(),
		proxyDmRoot:  utils.NewDomainRoot(),
	}
}

type autoProxy struct {
	byPassDmRoot *utils.DomainRoot
	proxyDmRoot  *utils.DomainRoot
	lock         sync.RWMutex
}

func (ap *autoProxy) loadByPassList(bypassList string) (err error) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	f, err := os.Open(bypassList)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ap.byPassDmRoot.Put(scanner.Text())
	}
	err = scanner.Err()
	return
}

func (ap *autoProxy) loadPorxyList(proxyList string) (err error) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	f, err := os.Open(proxyList)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ap.proxyDmRoot.Put(scanner.Text())
	}
	err = scanner.Err()
	return
}

func (ap *autoProxy) getByPassHosts() []string {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	hosts := ap.byPassDmRoot.Get()
	return hosts
}

func (ap *autoProxy) getProxyHosts() []string {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	hosts := ap.proxyDmRoot.Get()
	return hosts
}

func (ap *autoProxy) markHostNeedProxy(host string) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	ap.proxyDmRoot.Put(host)
}

func (ap *autoProxy) markHostByPass(host string) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	ap.byPassDmRoot.Put(host)
}

func (ap *autoProxy) checkIfProxy(host string) bool {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	return ap.proxyDmRoot.Test(host)
}

func (ap *autoProxy) checkIfByPass(host string) bool {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	return ap.byPassDmRoot.Test(host)
}

type chnRouteList struct {
	tree *utils.IPTree
	lock sync.RWMutex
}

func (route *chnRouteList) load(path string) (err error) {
	route.lock.Lock()
	defer route.lock.Unlock()
	if route.tree == nil {
		route.tree = utils.NewIPTree()
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		route.tree.Insert(scanner.Text())
	}
	err = scanner.Err()
	return
}

func (route *chnRouteList) testIP(ip net.IP) bool {
	route.lock.RLock()
	defer route.lock.RUnlock()
	return route.tree.TestIP(ip)
}

type bytesFilter interface {
	Close() error
	TestAndAdd([]byte) bool
}
