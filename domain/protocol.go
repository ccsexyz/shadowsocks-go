package domain

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode"
)

var IvExpireSecond int64 = 30

func DupBuffer(b []byte) (b2 []byte) {
	l := len(b)
	if l != 0 {
		b2 = make([]byte, l)
		copy(b2, b)
	}
	return
}

func PutHeader(b []byte, host string, port int) (n int) {
	n = len(host)
	b[0] = TypeDm
	b[1] = byte(n)
	copy(b[2:], []byte(host))
	binary.BigEndian.PutUint16(b[2+n:], uint16(port))
	n += 4
	return
}

func GetHeader(host string, port int) (buf []byte, err error) {
	hostlen := len(host)
	if hostlen > 255 {
		err = fmt.Errorf("host length can't be greater than 255")
		return
	}
	buf = make([]byte, hostlen+4)
	PutHeader(buf, host, port)
	return
}

func checkTimestamp(ts int64) (ok bool, diff int64) {
	nts := time.Now().Unix()
	diff = nts - ts
	if diff < 0 {
		diff = -diff
	}
	ok = diff <= IvExpireSecond
	return
}

func isAllowedInHost(b byte) bool {
	return unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b)) || b == '.' || b == '-' || b == '_' || b == ':' || b == '[' || b == ']'
}

func ParseAddr(b []byte) (addr *SockAddr, data []byte, err error) {
	addr = &SockAddr{}
	defer func() {
		if err != nil {
			addr = nil
		}
	}()
	n := len(b)
	if n < 1 {
		err = fmt.Errorf("parse addr: empty data (0 bytes)")
		return
	}
	var nop bool
	atyp := b[0]
l:
	for {
		switch atyp {
		default:
			break l
		case TypeNop:
			if n < 2 {
				err = fmt.Errorf("parse addr: insufficient data for nop header (need 2, have %d)", n)
				return
			}
			noplen := int(b[1])
			if noplen >= 128 {
				err = fmt.Errorf("parse addr: invalid nop length %d (max 127)", noplen)
				return
			}
			if n < noplen+2+1 {
				err = fmt.Errorf("parse addr: data too short for nop payload: need %d bytes, have %d", noplen+2+1, n)
				return
			}
			for i, v := range b[2 : noplen+2] {
				if v != 0 {
					err = fmt.Errorf("parse addr: non-zero nop padding at offset %d: 0x%02x", i, v)
					return
				}
			}
			b = b[noplen+2:]
			n = len(b)
			atyp = b[0]
			nop = true
			addr.Nop = nop
		case TypeTs:
			if n < LenTs+1+1 {
				err = fmt.Errorf("parse addr: data too short for timestamp: need %d, have %d", LenTs+1+1, n)
				return
			}
			ts := binary.BigEndian.Uint64(b[1 : 1+LenTs])
			ok, diff := checkTimestamp(int64(ts))
			if !ok {
				err = fmt.Errorf("parse addr: timestamp expired: ts=%d diff=%ds max=%ds", ts, diff, IvExpireSecond)
				return
			}
			b = b[LenTs+1:]
			n = len(b)
			atyp = b[0]
			addr.Ts = true
		}
	}
	var header []byte
	switch atyp {
	default:
		err = fmt.Errorf("parse addr: unsupported address type 0x%02x (data len=%d, first bytes=%x)", atyp, n, safeHead(b, 16))
		return
	case TypeMux:
		if !nop {
			err = fmt.Errorf("parse addr: mux type requires nop padding")
			return
		}
		header = b[:1]
		data = b[1:]
	case TypeIPv4:
		if nop {
			err = fmt.Errorf("parse addr: nop padding not allowed before ipv4")
			return
		}
		if n < LenIPv4+2+1 {
			err = fmt.Errorf("parse addr: insufficient data for ipv4: need %d, have %d", LenIPv4+2+1, n)
			return
		}
		header = b[:LenIPv4+2+1]
		data = b[LenIPv4+2+1:]
	case TypeIPv6:
		if nop {
			err = fmt.Errorf("parse addr: nop padding not allowed before ipv6")
			return
		}
		if n < LenIPv6+2+1 {
			err = fmt.Errorf("parse addr: insufficient data for ipv6: need %d, have %d", LenIPv6+2+1, n)
			return
		}
		header = b[:LenIPv6+2+1]
		data = b[LenIPv6+2+1:]
	case TypeDm:
		if n < 2 {
			err = fmt.Errorf("parse addr: insufficient data for domain header (need 2, have %d)", n)
			return
		}
		dmlen := int(b[1])
		if n < dmlen+1+2+1 {
			err = fmt.Errorf("parse addr: insufficient data for domain: dmlen=%d need=%d have=%d", dmlen, dmlen+1+2+1, n)
			return
		}
		for i, v := range b[2 : 2+dmlen] {
			if !isAllowedInHost(v) {
				err = fmt.Errorf("parse addr: invalid character 0x%02x at host offset %d (host=%q)", v, i, string(b[2:2+dmlen]))
				return
			}
		}
		header = b[:2+dmlen+2]
		data = b[2+dmlen+2:]
	}
	addr.Hdr = DupBuffer(header)
	data = DupBuffer(data)
	err = nil
	return
}

func safeHead(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}
