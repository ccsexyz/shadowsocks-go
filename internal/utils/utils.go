package utils

import (
	"crypto/rand"
	"net"
	"slices"
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

func SliceToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func StringToSlice(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
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
	slices.Reverse(domains)
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
	slices.Reverse(domains)
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
