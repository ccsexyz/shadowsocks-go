package ss

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

func init() {
	utils.VirtualDialer = func(network, addr string) (net.Conn, error) {
		return DialVirtual(addr)
	}
}

type virtualAddr struct{ name string }

func (a *virtualAddr) Network() string { return "virtual" }
func (a *virtualAddr) String() string  { return a.name }

type virtualListener struct {
	ch      chan net.Conn
	addr    *virtualAddr
	die     chan struct{}
	once    sync.Once
	accepts int64
}

func (vl *virtualListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-vl.ch:
		if !ok {
			return nil, fmt.Errorf("virtual listener closed")
		}
		atomic.AddInt64(&vl.accepts, 1)
		return conn, nil
	case <-vl.die:
		return nil, fmt.Errorf("virtual listener closed")
	}
}

func (vl *virtualListener) Close() error {
	vl.once.Do(func() { close(vl.die) })
	return nil
}

func (vl *virtualListener) Addr() net.Addr { return vl.addr }

type virtualEntry struct {
	listener  *virtualListener
	createdAt time.Time
	source    string
}

var virtualServices sync.Map // name → *virtualEntry

func RegisterVirtual(name string, source string) (net.Listener, error) {
	name = strings.ToLower(name)
	vl := &virtualListener{
		ch:   make(chan net.Conn, 32),
		addr: &virtualAddr{name: name},
		die:  make(chan struct{}),
	}
	entry := &virtualEntry{listener: vl, createdAt: time.Now(), source: source}
	if _, loaded := virtualServices.LoadOrStore(name, entry); loaded {
		return nil, fmt.Errorf("virtual service %s already registered", name)
	}
	return vl, nil
}

func RegisterVirtualForce(name string, source string) net.Listener {
	name = strings.ToLower(name)
	vl := &virtualListener{
		ch:   make(chan net.Conn, 32),
		addr: &virtualAddr{name: name},
		die:  make(chan struct{}),
	}
	entry := &virtualEntry{listener: vl, createdAt: time.Now(), source: source}
	old, loaded := virtualServices.Swap(name, entry)
	if loaded {
		oldEntry := old.(*virtualEntry)
		oldEntry.listener.Close()
		drainVirtualListener(oldEntry.listener)
	}
	return vl
}

func drainVirtualListener(vl *virtualListener) {
	for {
		select {
		case conn := <-vl.ch:
			conn.Close()
		default:
			return
		}
	}
}

func UnregisterVirtual(name string) {
	name = strings.ToLower(name)
	v, ok := virtualServices.LoadAndDelete(name)
	if ok {
		v.(*virtualEntry).listener.Close()
	}
}

func DialVirtual(name string) (net.Conn, error) {
	name = strings.ToLower(name)
	v, ok := virtualServices.Load(name)
	if !ok {
		return nil, fmt.Errorf("virtual service %s not found", name)
	}
	entry := v.(*virtualEntry)
	vl := entry.listener

	c1, c2 := net.Pipe()
	select {
	case vl.ch <- c1:
		return c2, nil
	case <-vl.die:
		c1.Close()
		c2.Close()
		return nil, fmt.Errorf("virtual service %s closed", name)
	}
}

type VirtualServiceInfo struct {
	Name        string `json:"name"`
	Source      string `json:"source"`
	CreatedAt   int64  `json:"createdAt"`
	AcceptCount int64  `json:"acceptCount"`
}

func ListVirtualServices() []VirtualServiceInfo {
	var result []VirtualServiceInfo
	virtualServices.Range(func(key, value any) bool {
		entry := value.(*virtualEntry)
		result = append(result, VirtualServiceInfo{
			Name:        key.(string),
			Source:      entry.source,
			CreatedAt:   entry.createdAt.Unix(),
			AcceptCount: atomic.LoadInt64(&entry.listener.accepts),
		})
		return true
	})
	return result
}
