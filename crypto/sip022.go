// Package crypto provides SIP022 UDP header support for shadowsocks 2022 methods.
// The SIP022 header wraps the SOCKS5-style address (ATYP + ADDR + PORT + PAYLOAD)
// with a type, timestamp, and random padding for protocol compliance.
//
// Request format (Client → Server):
//
//	[Type=0(1)][Timestamp(8)][PaddingLen(2)][Padding(N)][ATYP(1)][ADDR(var)][PORT(2)][PAYLOAD]
//
// Response format (Server → Client):
//
//	[Type=1(1)][Timestamp(8)][ClientSessionID(8)][PaddingLen(2)][Padding(N)][ATYP(1)][ADDR(var)][PORT(2)][PAYLOAD]
package crypto

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"time"
)

// BuildSIP022Request wraps a SOCKS5-style UDP relay packet with a SIP022 request header.
// Input:  [ATYP(1)][ADDR(var)][PORT(2)][PAYLOAD]
// Output: [Type=0(1)][Timestamp(8)][PaddingLen(2)][Padding(N)][ATYP(1)][ADDR(var)][PORT(2)][PAYLOAD]
func BuildSIP022Request(b []byte) []byte {
	return buildSIP022(b, 0, 0)
}

// BuildSIP022Response wraps a SOCKS5-style UDP relay packet with a SIP022 response header.
// Includes ClientSessionID for shadowsocks-rust interop.
func BuildSIP022Response(b []byte, clientSID uint64) []byte {
	return buildSIP022(b, 1, clientSID)
}

// buildSIP022 builds a SIP022 packet.
// extra: 0 for request (no clientSID), 1 for response (includes clientSID as extra 8 bytes after TS).
func buildSIP022(b []byte, sipType byte, clientSID uint64) []byte {
	if len(b) < 4 {
		return b
	}
	atyp := b[0]
	if atyp != 1 && atyp != 3 {
		return b // unsupported type, pass through
	}

	ts := time.Now().Unix()
	padLen := rand.IntN(64)
	extra := 0
	if sipType == 1 {
		extra = 8 // ClientSessionID
	}

	out := make([]byte, 1+8+extra+2+padLen+len(b))
	out[0] = sipType
	binary.BigEndian.PutUint64(out[1:9], uint64(ts))
	if sipType == 1 {
		binary.BigEndian.PutUint64(out[9:17], clientSID)
	}
	binary.BigEndian.PutUint16(out[9+extra:11+extra], uint16(padLen))
	copy(out[11+extra+padLen:], b)
	return out
}

// ParseSIP022 parses a SIP022-formatted UDP packet.
// Handles both request (Type=0) and response (Type=1, with ClientSessionID) formats.
//
// Returns:
//
//	hdr     — the full header including address+port (for echoing back in responses)
//	host    — target host
//	port    — target port
//	payload — data after the address+port
func ParseSIP022(b []byte) (hdr []byte, host string, port int, payload []byte, err error) {
	if len(b) < 12 || (b[0] != 0 && b[0] != 1) {
		err = fmt.Errorf("not a SIP022 header (len=%d type=%d)", len(b), b[0])
		return
	}
	sipType := b[0]

	// Timestamp is always at offset 1
	ts := int64(binary.BigEndian.Uint64(b[1:9]))
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > 30 {
		err = fmt.Errorf("SIP022 timestamp too far off: %d", diff)
		return
	}

	var padLenPos int
	if sipType == 1 {
		// Response format: Type(1) + TS(8) + ClientSID(8) + PadLen(2) + Pad + Addr + Payload
		if len(b) < 19 { // 1+8+8+2 minimum
			err = fmt.Errorf("SIP022 response too short: %d", len(b))
			return
		}
		padLenPos = 17 // after Type(1) + TS(8) + ClientSID(8)
	} else {
		// Request format: Type(0) + TS(8) + PadLen(2) + Pad + Addr + Payload
		padLenPos = 9 // after Type(1) + TS(8)
	}

	padLen := int(binary.BigEndian.Uint16(b[padLenPos : padLenPos+2]))
	if padLen > 900 {
		err = fmt.Errorf("SIP022 padding too large: %d", padLen)
		return
	}
	skip := padLenPos + 2 + padLen
	if len(b) < skip {
		err = fmt.Errorf("SIP022 packet too short: %d < %d", len(b), skip)
		return
	}
	rest := b[skip:]

	// After SIP022 header: ATYP+ADDR+PORT+PAYLOAD in SOCKS5 format
	addr, data, addrErr := parseSIP022Addr(rest)
	if addrErr != nil {
		err = fmt.Errorf("SIP022 address parse: %w", addrErr)
		return
	}

	hdr = b[:skip+len(rest)-len(data)]
	host = addr.Host()
	port, _ = strconv.Atoi(addr.Port())
	payload = data
	return
}

// parseSIP022Addr parses the SOCKS5-style address (ATYP+ADDR+PORT+PAYLOAD)
// that follows the SIP022 header.
func parseSIP022Addr(b []byte) (addr *sipAddr, data []byte, err error) {
	if len(b) < 4 {
		err = fmt.Errorf("packet too short: %d", len(b))
		return
	}
	atyp := b[0]
	switch atyp {
	case 1: // IPv4
		if len(b) < 7 {
			err = fmt.Errorf("IPv4 packet too short: %d", len(b))
			return
		}
		addr = &sipAddr{hdr: b[:7]}
		data = b[7:]
	case 3: // Domain
		if len(b) < 4 {
			err = fmt.Errorf("domain packet too short")
			return
		}
		dlen := int(b[1])
		hdrLen := 1 + 1 + dlen + 2
		if len(b) < hdrLen {
			err = fmt.Errorf("domain packet truncated: need %d have %d", hdrLen, len(b))
			return
		}
		addr = &sipAddr{hdr: b[:hdrLen]}
		data = b[hdrLen:]
	default:
		err = fmt.Errorf("unsupported ATYP: %d", atyp)
		return
	}
	return
}

// sipAddr is a minimal address type for SIP022 parsing.
type sipAddr struct {
	hdr []byte
}

func (s *sipAddr) Host() string {
	switch s.hdr[0] {
	case 1:
		return net.IP(s.hdr[1:5]).String()
	case 3:
		return string(s.hdr[2 : 2+int(s.hdr[1])])
	}
	return ""
}

func (s *sipAddr) Port() string {
	switch s.hdr[0] {
	case 1:
		return fmt.Sprintf("%d", binary.BigEndian.Uint16(s.hdr[5:7]))
	case 3:
		dlen := int(s.hdr[1])
		return fmt.Sprintf("%d", binary.BigEndian.Uint16(s.hdr[2+dlen:2+dlen+2]))
	}
	return ""
}

// BuildSOCKS5Response builds a SOCKS5 UDP response from SIP022 parsed fields.
// Writes into b starting at offset 0: [RSV(2)][FRAG(1)][ATYP(1)][ADDR(var)][PORT(2)][PAYLOAD]
func BuildSOCKS5Response(b []byte, host string, port int, payload []byte) int {
	b[0] = 0
	b[1] = 0
	b[2] = 0 // RSV + FRAG
	off := 3
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		b[off] = 1 // ATYP IPv4
		off++
		copy(b[off:], ip4)
		off += 4
	} else {
		b[off] = 3 // ATYP Domain
		off++
		b[off] = byte(len(host))
		off++
		copy(b[off:], host)
		off += len(host)
	}
	binary.BigEndian.PutUint16(b[off:], uint16(port))
	off += 2
	copy(b[off:], payload)
	off += len(payload)
	return off
}
