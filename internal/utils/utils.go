package utils

import (
	"crypto/rand"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

func PutRandomBytes(b []byte) {
	rand.Read(b)
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
	for _, domain := range domains {
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
