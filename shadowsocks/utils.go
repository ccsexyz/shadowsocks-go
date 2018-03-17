package ss

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"runtime"
	"strconv"
	"sync/atomic"

	"github.com/ccsexyz/utils"
	"fmt"
)

const (
	typeIPv4   = 0x1
	typeDomain = 0x3
	typeIPv6   = 0x4
	lenIPv4    = 0x4
	lenIPv6    = 0x10

	bufferSize    = 4096
	minHeaderSize = 7
)

type Addr interface {
	Host() string
	Port() string
	Header() []byte
	String() string
}

type DstAddr struct {
	host     string
	port     string
	hostport string
	header   []byte
}

func NewDstAddr(hostport string) DstAddr {
	return DstAddr{hostport: hostport}
}

func (d *DstAddr) initHostPort() {
	if len(d.hostport) != 0 {
		d.host, d.port, _ = net.SplitHostPort(d.hostport)
		return
	}
	if len(d.host) != 0 && len(d.port) != 0 {
		d.hostport = net.JoinHostPort(d.host, d.port)
	} else if len(d.header) != 0 {
		atyp := d.header[0]
		if atyp == typeIPv4 {
			d.host = net.IP(d.header[1 : lenIPv4+1]).String()
			d.port = strconv.Itoa(int(binary.BigEndian.Uint16(d.header[lenIPv4+1:])))
		} else if atyp == typeIPv6 {
			d.host = net.IP(d.header[1 : lenIPv6+1]).String()
			d.port = strconv.Itoa(int(binary.BigEndian.Uint16(d.header[lenIPv6+1:])))
		} else if atyp == typeDomain {
			d.host = utils.SliceToString(d.header[2 : 2+int(d.header[1])])
			d.port = strconv.Itoa(int(binary.BigEndian.Uint16(d.header[int(d.header[1])+2:])))
		} else {
			return
		}
		d.initHostPort()
	}
}

func (d *DstAddr) Host() string {
	if len(d.host) == 0 {
		d.initHostPort()
	}
	return d.host
}

func (d *DstAddr) Port() string {
	if len(d.port) == 0 {
		d.initHostPort()
	}
	return d.port
}

func (d *DstAddr) String() string {
	if len(d.hostport) == 0 {
		d.initHostPort()
	}
	return d.hostport
}

func (d *DstAddr) Header() []byte {
	if len(d.header) == 0 {
		host := d.Host()
		port, _ := strconv.Atoi(d.Port())
		d.header = make([]byte, len(host)+4)
		d.header[0] = typeDomain
		d.header[1] = byte(len(host))
		copy(d.header[2:], host)
		binary.BigEndian.PutUint16(d.header[len(d.header)-2:], uint16(port))
	}
	return d.header
}

var (
	errInvalidHeader = errors.New("Invalid Header")
)

func ParseAddr(b []byte) (addr DstAddr, n int, err error) {
	if len(b) < minHeaderSize {
		err = errInvalidHeader
		return
	}
	var dn int
	atyp := b[0]
	if atyp == typeIPv4 {
		dn = lenIPv4 + 2 + 1
	} else if atyp == typeIPv6 {
		dn = lenIPv6 + 2 + 1
	} else if atyp == typeDomain {
		dn = int(b[1]) + 2 + 1 + 1
		if len(b) < dn || dn == 0 {
			err = errInvalidHeader
			return
		}
		for _, v := range b[2 : dn-2] {
			if !((v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z') || (v >= '0' && v <= '9') || v == '.' || v == '-' || v == '_') {
				err = errInvalidHeader
				return
			}
		}
	} else {
		err = errInvalidHeader
		return
	}
	if len(b) < dn {
		err = errInvalidHeader
		return
	}
	n = dn
	header := utils.CopyBuffer(b[:n])
	addr = DstAddr{header: header}
	return
}

const (
	spinInit = iota
	spinInLock
)

type Spin struct {
	i uint32
}

func (s *Spin) Run(f func()) {
	for !atomic.CompareAndSwapUint32(&s.i, spinInit, spinInLock) {
		runtime.Gosched()
	}

	defer func() {
		if !atomic.CompareAndSwapUint32(&s.i, spinInLock, spinInit) {
			log.Fatal()
		}
	}()
	if f != nil {
		f()
	}
}

type bytesFilter interface {
	Close() error
	TestAndAdd([]byte) bool
}

type nullFilterImpl struct{}

func newNullFilter() bytesFilter {
	return &nullFilterImpl{}
}

func (r *nullFilterImpl) Close() error { return nil }

func (r *nullFilterImpl) TestAndAdd(_ []byte) bool { return false }

func GetInnerConn(conn net.Conn) (c net.Conn, err error) {
	defer func() {
		if c == nil {
			err = fmt.Errorf("unexpected conn with type %T", conn)
		}
	}()
	switch i := conn.(type) {
	case *baseConn:
		c = i.Conn
	case *netConn:
		c = i.Conn
	case *ShadowSocksConn:
		c = i.Conn
	case *RemainConn:
		c = i.Conn
	case *AEADShadowSocksConn:
		c = i.Conn
	}
	return
}

func GetNetTCPConn(conn net.Conn) (c *net.TCPConn, err error) {
	c, ok := conn.(*net.TCPConn)
	if !ok {
		conn, err = GetInnerConn(conn)
		if err != nil {
			return
		}
		c, err = GetNetTCPConn(conn)
	}
	return
}