package shadowsocks

import (
	"crypto/rand"
	"encoding/binary"
	"net"
)

const (
	defaultMethod       = "aes-256-cfb"
	defaultPassword     = "you should have a password"
	buffersize          = 4096
	typeIPv4            = 1
	typeDm              = 3
	typeIPv6            = 4
	typeNop             = 0x90 // [nop 1 byte] [noplen 1 byte (< 128)] [random data noplen byte]
	lenIPv4             = 4
	lenIPv6             = 16
	ivmapHighWaterLevel = 100000
	ivmapLowWaterLevel  = 10000
)

func getRandBytes(len int) []byte {
	if len <= 0 {
		return nil
	}
	data := make([]byte, len)
	binary.Read(rand.Reader, binary.BigEndian, data)
	return data
}

func ParseAddr(b []byte) (host string, port int, data []byte) {
	n := len(b)
	if n < 1 {
		return
	}
	atyp := b[0]
	for atyp == typeNop {
		noplen := int(b[1])
		if noplen >= 128 || n < noplen+2+1 {
			return
		}
		b = b[noplen+2:]
		n = len(b)
		atyp = b[0]
	}
	switch atyp {
	default:
		return
	case typeIPv4:
		data = b[lenIPv4+2+1:]
		host = net.IP(b[1 : lenIPv4+1]).String()
		port = int(binary.BigEndian.Uint16(b[lenIPv4+1:]))
	case typeIPv6:
		if n < lenIPv6+2+1 {
			return
		}
		data = b[lenIPv6+2+1:]
		host = net.IP(b[1 : 1+lenIPv6]).String()
		port = int(binary.BigEndian.Uint16(b[lenIPv6+1:]))
	case typeDm:
		dmlen := int(b[1])
		if n < dmlen+1+2+1 {
			return
		}
		data = b[dmlen+1+2+1:]
		host = string(b[2 : 2+dmlen])
		port = int(binary.BigEndian.Uint16(b[dmlen+2:]))
	}
	return
}

func Pipe(c1, c2 net.Conn) {
	c1die := make(chan bool)
	c2die := make(chan bool)
	f := func(dst, src net.Conn, die chan bool, buf []byte) {
		defer close(die)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				_, err := dst.Write(buf[:n])
				if err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go f(c1, c2, c1die, make([]byte, buffersize))
	go f(c2, c1, c2die, make([]byte, buffersize))
	select {
	case <-c1die:
	case <-c2die:
	}
}
