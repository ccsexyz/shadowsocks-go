package domain

import (
	"encoding/binary"
	"net"
	"strconv"
)

type Addr interface {
	Host() string
	Port() string
	Header() []byte
	String() string
}

type SockAddr struct {
	Hdr []byte
	Nop bool
	Ts  bool
}

func (s *SockAddr) String() string {
	return net.JoinHostPort(s.Host(), s.Port())
}

func (s *SockAddr) Host() string {
	b := s.Hdr
	switch b[0] {
	default:
		return string(b[2 : 2+int(b[1])])
	case TypeIPv4:
		return net.IP(b[1 : LenIPv4+1]).String()
	case TypeIPv6:
		return net.IP(b[1 : LenIPv6+1]).String()
	case TypeMux:
		return MuxHost
	}
}

func (s *SockAddr) Port() string {
	return strconv.Itoa(s.PortNum())
}

func (s *SockAddr) PortNum() int {
	var off int
	b := s.Hdr
	switch b[0] {
	default:
		off = int(b[1]) + 2
	case TypeIPv4:
		off = LenIPv4 + 1
	case TypeIPv6:
		off = LenIPv6 + 1
	case TypeMux:
		return MuxPort
	}
	return int(binary.BigEndian.Uint16(b[off:]))
}

func (s *SockAddr) Header() []byte {
	return s.Hdr
}

type DstAddr struct {
	dst string
	prt string
	hdr []byte
}

func NewDstAddr(host, port string) *DstAddr {
	return &DstAddr{dst: host, prt: port}
}

func (d *DstAddr) Host() string {
	return d.dst
}

func (d *DstAddr) Port() string {
	return d.prt
}

func (d *DstAddr) String() string {
	if len(d.prt) == 0 {
		return d.dst
	}
	return net.JoinHostPort(d.dst, d.prt)
}

func (d *DstAddr) Header() []byte {
	if d.hdr == nil {
		port, _ := strconv.Atoi(d.prt)
		d.hdr, _ = GetHeader(d.dst, port)
	}
	return d.hdr
}
