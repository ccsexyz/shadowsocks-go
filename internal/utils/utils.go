package utils

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const defaultMethod = "aes-256-cfb"

func PutRandomBytes(b []byte) {
	binary.Read(rand.Reader, binary.BigEndian, b)
}

func GetRandomBytes(len int) []byte {
	if len <= 0 {
		return nil
	}
	data := make([]byte, len)
	PutRandomBytes(data)
	return data
}

type ExitCleaner struct {
	lock   sync.Mutex
	runner []func()
	once   sync.Once
}

func (c *ExitCleaner) Push(f func()) int {
	c.lock.Lock()
	defer c.lock.Unlock()
	n := len(c.runner)
	c.runner = append(c.runner, f)
	return n
}

func (c *ExitCleaner) Exit() {
	flag := true
	c.once.Do(func() { flag = false })
	if flag {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	for i := len(c.runner) - 1; i >= 0; i-- {
		f := c.runner[i]
		if f == nil {
			continue
		}
		f()
	}
}

func (c *ExitCleaner) Delete(index int) func() {
	c.lock.Lock()
	defer c.lock.Unlock()
	if index > len(c.runner) || index < 0 {
		return nil
	}
	f := c.runner[index]
	if index == 0 {
		c.runner = c.runner[1:]
	} else if index == len(c.runner)-1 {
		c.runner = c.runner[:index]
	} else {
		runner1 := c.runner[:index]
		runner2 := c.runner[index+1:]
		c.runner = append(runner1, runner2...)
	}
	return f
}

func SliceToString(b []byte) (s string) {
	pbytes := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	pstring := (*reflect.StringHeader)(unsafe.Pointer(&s))
	pstring.Data = pbytes.Data
	pstring.Len = pbytes.Len
	return
}

func StringToSlice(s string) (b []byte) {
	pbytes := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	pstring := (*reflect.StringHeader)(unsafe.Pointer(&s))
	pbytes.Data = pstring.Data
	pbytes.Len = pstring.Len
	pbytes.Cap = pstring.Len
	return
}

type Die struct {
	RWLock
	ch  chan bool
	die bool
}

func (d *Die) Ch() (ch <-chan bool) {
	d.RunInLock(func() {
		if d.ch == nil {
			d.ch = make(chan bool)
		}
		ch = d.ch
	})
	return
}

func (d *Die) Die(f func()) {
	var die bool

	d.RunInLock(func() {
		die = d.die
		if !d.die {
			d.die = true
		}
		if d.ch == nil {
			d.ch = make(chan bool)
		}
	})

	if die {
		return
	}

	close(d.ch)

	if f != nil {
		f()
	}
}

func (d *Die) IsDead() (dead bool) {
	d.RunInRLock(func() {
		dead = d.die
	})
	return
}

type Lock struct {
	sync.Mutex
}

func (l *Lock) RunInLock(f func()) {
	l.Lock()
	defer l.Unlock()
	if f != nil {
		f()
	}
}

type RWLock struct {
	sync.RWMutex
}

func (l *RWLock) RunInLock(f func()) {
	l.Lock()
	defer l.Unlock()
	if f != nil {
		f()
	}
}

func (l *RWLock) RunInRLock(f func()) {
	l.RLock()
	defer l.RUnlock()
	if f != nil {
		f()
	}
}

type Locker interface {
	RunInLock(f func())
}

type RWLocker interface {
	Locker
	RunInRLock(f func())
}

type Expires struct {
	E time.Time
	L RWLock
}

func (e *Expires) isExpired() bool {
	return time.Now().After(e.E)
}

func (e *Expires) IsExpired() bool {
	e.L.RLock()
	defer e.L.RUnlock()
	return e.isExpired()
}

func (e *Expires) update(d time.Duration) {
	e.E = time.Now().Add(d)
}

func (e *Expires) Update(d time.Duration) {
	e.L.Lock()
	e.update(d)
	e.L.Unlock()
}

func (e *Expires) IsExpiredAndUpdate(d time.Duration) bool {
	expired := e.IsExpired()
	if !expired {
		return expired
	}
	e.L.Lock()
	defer e.L.Unlock()
	expired = e.isExpired()
	if expired {
		e.update(d)
		return true
	}
	return false
}

var domainNodePool = &sync.Pool{New: func() interface{} {
	return &domainNode{
		nodes: make(map[string]*domainNode),
	}
}}

// DomainRoot is a simple trie tree
type DomainRoot struct {
	node      *domainNode
	nodesPool sync.Pool
}

type domainNode struct {
	hit    bool
	any    bool
	domain string
	nodes  map[string]*domainNode
}

// NewDomainRoot returns a new domainroot and init it
func NewDomainRoot() *DomainRoot {
	return &DomainRoot{node: &domainNode{nodes: make(map[string]*domainNode)}}
}

func reverse(ss []string) {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
}

func (node *domainNode) markAny() {
	node.any = true
	node.hit = true
	for k, v := range node.nodes {
		v.markAny()
		delete(node.nodes, k)
	}
	node.nodes = nil
}

// Put put a new host into domainroot
func (root *DomainRoot) Put(host string) {
	domains := strings.Split(host, ".")
	if len(domains) < 2 {
		return
	}
	reverse(domains)
	node := root.node
	for it, domain := range domains {
		if len(domain) == 0 {
			continue
		}
		if node.any {
			return
		}
		if domain == "*" {
			node.markAny()
			return
		}
		v, ok := node.nodes[domain]
		if ok {
			if v.any {
				return
			}
			if len(v.nodes) > 10 && it > 0 {
				v.markAny()
				return
			}
			node = v
			continue
		}
		v = &domainNode{
			domain: domain,
			nodes:  make(map[string]*(domainNode)),
		}
		node.nodes[domain] = v
		node = v
	}
	node.hit = true
}

func (root *DomainRoot) Test(host string) bool {
	domains := strings.Split(host, ".")
	if len(domains) < 2 {
		return false
	}
	reverse(domains)
	node := root.node
	for _, domain := range domains {
		if len(domain) == 0 {
			continue
		}
		if node.any {
			return true
		}
		v, ok := node.nodes[domain]
		if !ok {
			return false
		}
		node = v
	}
	return node.hit
}

func (root *DomainRoot) Get() (hosts []string) {
	var domains []string
	var f func(*domainNode)

	f = func(node *domainNode) {
		if len(node.domain) != 0 {
			domains = append([]string{node.domain}, domains...)
			if node.any {
				host := strings.Join(domains, ".")
				host = "*." + host
				hosts = append(hosts, host)
			} else if node.hit {
				host := strings.Join(domains, ".")
				hosts = append(hosts, host)
			}
		}
		for _, v := range node.nodes {
			f(v)
		}
		if len(node.domain) != 0 {
			domains = domains[1:]
		}
	}

	f(root.node)

	return
}

func SplitHostAndPort(hostport string) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return
	}
	port, err = strconv.Atoi(portStr)
	return
}

func SplitIPAndPort(ipport string) (ip net.IP, port int, err error) {
	ipstr, port, err := SplitHostAndPort(ipport)
	if err != nil {
		return
	}
	ip = net.ParseIP(ipstr)
	return
}

func PipeUDPOverTCP(udpconn net.Conn, tcpconn net.Conn, bufpool *sync.Pool, timeout time.Duration, pseudo []byte) {
	die1 := make(chan struct{})
	die2 := make(chan struct{})

	ubuf := bufpool.Get().([]byte)
	defer bufpool.Put(ubuf)
	tbuf := bufpool.Get().([]byte)
	defer bufpool.Put(tbuf)

	trySetTimeout := func(conn net.Conn, isRead bool) {
		if timeout.Nanoseconds() == 0 {
			return
		}
		expires := time.Now().Add(timeout)
		if isRead {
			conn.SetReadDeadline(expires)
		} else {
			conn.SetWriteDeadline(expires)
		}
	}

	pseudoLen := copy(tbuf, pseudo)

	go func() {
		var szoff, left int
		if pseudoLen < 2 {
			left = 2 - pseudoLen
		} else {
			szoff = pseudoLen - 2
		}
		defer close(die1)
		for {
			trySetTimeout(udpconn, true)
			n, err := udpconn.Read(ubuf[left:])
			if err != nil {
				return
			}
			n -= pseudoLen
			binary.BigEndian.PutUint16(ubuf[szoff:], uint16(n))
			trySetTimeout(tcpconn, false)
			_, err = tcpconn.Write(ubuf[szoff : szoff+n+2])
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer close(die2)
		buf := tbuf[pseudoLen:]
		for {
			trySetTimeout(tcpconn, true)
			_, err := io.ReadFull(tcpconn, buf[:2])
			if err != nil {
				return
			}
			sz := int(binary.BigEndian.Uint16(buf[:2]))
			if sz > len(buf) {
				return
			}
			_, err = io.ReadFull(tcpconn, buf[:sz])
			if err != nil {
				return
			}
			trySetTimeout(udpconn, false)
			_, err = udpconn.Write(tbuf[:pseudoLen+sz])
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-die1:
	case <-die2:
	}
}
