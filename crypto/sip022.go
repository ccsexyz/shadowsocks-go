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
// Returns nil when the input does not carry a valid address header: an
// unwrapped datagram would be rejected by the receiving 2022 layer anyway,
// so callers get an explicit "nothing to send" instead of a silent
// pass-through that desyncs the declared payload format.
func BuildSIP022Request(b []byte) []byte {
	return buildSIP022(b, 0, 0)
}

// BuildSIP022Response wraps a SOCKS5-style UDP relay packet with a SIP022 response header.
// Includes ClientSessionID for shadowsocks-rust interop. Returns nil for
// input without a valid address header (see BuildSIP022Request).
func BuildSIP022Response(b []byte, clientSID uint64) []byte {
	return buildSIP022(b, 1, clientSID)
}

// buildSIP022 builds a SIP022 packet.
// extra: 0 for request (no clientSID), 1 for response (includes clientSID as extra 8 bytes after TS).
func buildSIP022(b []byte, sipType byte, clientSID uint64) []byte {
	if len(b) < 4 {
		return nil
	}
	atyp := b[0]
	if atyp != 1 && atyp != 3 && atyp != 4 {
		return nil // unsupported address type: nothing spec-compliant to send
	}
	// The address body must be complete (the same bounds parseSIP022Addr
	// enforces on the receiving side): a truncated ATYP+ADDR+PORT would be
	// wrapped into a packet the 2022 peer drops anyway.
	switch atyp {
	case 1:
		if len(b) < 7 {
			return nil
		}
	case 4:
		if len(b) < 19 {
			return nil
		}
	case 3:
		if len(b) < 4+int(b[1]) {
			return nil
		}
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
	// Random padding: all-zero padding is a fingerprint distinguishing this
	// implementation from spec-compliant peers.
	PutRandomBytes(out[11+extra : 11+extra+padLen])
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
	// b[0] must not be evaluated when b is empty: the error path itself used
	// to index the empty slice and panic on zero-length decrypted payloads.
	var typeByte byte
	if len(b) > 0 {
		typeByte = b[0]
	}
	if len(b) < 12 || (typeByte != 0 && typeByte != 1) {
		err = fmt.Errorf("not a SIP022 header (len=%d type=%d)", len(b), typeByte)
		return
	}

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

	rest := sip022AddrStart(b)
	if rest == nil {
		err = fmt.Errorf("SIP022 header malformed")
		return
	}

	// After SIP022 header: ATYP+ADDR+PORT+PAYLOAD in SOCKS5 format
	addr, data, addrErr := parseSIP022Addr(rest)
	if addrErr != nil {
		err = fmt.Errorf("SIP022 address parse: %w", addrErr)
		return
	}

	skip := len(b) - len(rest)
	hdr = b[:skip+len(rest)-len(data)]
	host = addr.Host()
	port, _ = strconv.Atoi(addr.Port())
	payload = data
	return
}

// sip022AddrStart validates the SIP022 wrapper (type, length, padding) and
// returns the slice starting at the ATYP byte. Returns nil if malformed.
func sip022AddrStart(b []byte) []byte {
	if len(b) < 12 || (b[0] != 0 && b[0] != 1) {
		return nil
	}
	sipType := b[0]
	padLenPos := 9
	if sipType == 1 {
		if len(b) < 19 {
			return nil
		}
		padLenPos = 17
	}
	padLen := int(binary.BigEndian.Uint16(b[padLenPos : padLenPos+2]))
	if padLen > 900 {
		return nil
	}
	skip := padLenPos + 2 + padLen
	if len(b) < skip {
		return nil
	}
	return b[skip:]
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
	case 4: // IPv6
		if len(b) < 19 {
			err = fmt.Errorf("IPv6 packet too short: %d", len(b))
			return
		}
		addr = &sipAddr{hdr: b[:19]}
		data = b[19:]
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

// Sip022Payload extracts the payload from a SIP022 packet without allocations.
// Intentionally skips timestamp validation — only use on the outbound (response)
// path where the timestamp is freshly generated.
// Returns nil if the packet is malformed.
func Sip022Payload(b []byte) []byte {
	rest := sip022AddrStart(b)
	if rest == nil || len(rest) < 4 {
		return nil
	}
	atyp := rest[0]
	var hdrLen int
	switch atyp {
	case 1:
		hdrLen = 7
	case 4:
		hdrLen = 19
	case 3:
		if len(rest) < 2 {
			return nil
		}
		hdrLen = 1 + 1 + int(rest[1]) + 2
	default:
		return nil
	}
	if len(rest) < hdrLen {
		return nil
	}
	return rest[hdrLen:]
}

// validateUDP2022Packet validates a decrypted SIP022 UDP payload without
// allocating. Per SIP022, the UDP replay window must not be updated before
// the packet's main header has been validated. A 2022 tunnel carries exactly
// one payload format: SIP022 (type 0 client / type 1 server, fresh ±30s
// timestamp). Bare ATYP packets belong to the classic cipher layers and are
// rejected here: their first byte (ATYP=1) aliases as SIP022 type 1, so
// accepting them made every 2022 receiver guess the format — and some bare
// IPv4 packets (e.g. DNS queries whose first QNAME label length is 1 or 4
// bytes) parsed as structurally valid but timestamp-stale SIP022 and were
// silently dropped. Senders that tunnel legacy payloads through a 2022 hop
// must wrap them with BuildSIP022Request first.
//
// Both type 0 and type 1 are accepted regardless of session role: the AEAD
// layer already authenticated the peer and the replay window is per session,
// so the type byte carries no security weight here, and role-strict checking
// would only add interop risk against lenient peers.
func validateUDP2022Packet(b []byte) bool {
	if len(b) < 12 || (b[0] != 0 && b[0] != 1) {
		return false
	}
	if Sip022Payload(b) == nil {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(b[1:9]))
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	return diff <= 30
}

func (s *sipAddr) Host() string {
	switch s.hdr[0] {
	case 1:
		return net.IP(s.hdr[1:5]).String()
	case 4:
		return net.IP(s.hdr[1:17]).String()
	case 3:
		return string(s.hdr[2 : 2+int(s.hdr[1])])
	}
	return ""
}

func (s *sipAddr) Port() string {
	switch s.hdr[0] {
	case 1:
		return fmt.Sprintf("%d", binary.BigEndian.Uint16(s.hdr[5:7]))
	case 4:
		return fmt.Sprintf("%d", binary.BigEndian.Uint16(s.hdr[17:19]))
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
	} else if ip6 := ip.To16(); ip6 != nil {
		b[off] = 4 // ATYP IPv6
		off++
		copy(b[off:], ip6)
		off += 16
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
