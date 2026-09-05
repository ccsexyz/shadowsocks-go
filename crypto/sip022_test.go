package crypto

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// Build a minimal SIP022 request: Type=0, TS, PadLen=0, ATYP=1(IPv4)+IP+Port+Payload
func makeSIP022Request(ip [4]byte, port uint16, payload []byte) []byte {
	buf := make([]byte, 1+8+2+0+1+4+2+len(payload))
	buf[0] = 0                                                      // Type=0 request
	binary.BigEndian.PutUint64(buf[1:9], uint64(time.Now().Unix())) // current TS
	binary.BigEndian.PutUint16(buf[9:11], 0)                        // PadLen=0
	buf[11] = 1                                                     // ATYP IPv4
	copy(buf[12:16], ip[:])
	binary.BigEndian.PutUint16(buf[16:18], port)
	copy(buf[18:], payload)
	return buf
}

func makeSIP022RequestDomain(domain string, port uint16, payload []byte) []byte {
	buf := make([]byte, 1+8+2+0+1+1+len(domain)+2+len(payload))
	buf[0] = 0
	binary.BigEndian.PutUint64(buf[1:9], 1234567890)
	binary.BigEndian.PutUint16(buf[9:11], 0) // PadLen=0
	buf[11] = 3                              // ATYP domain
	buf[12] = byte(len(domain))
	copy(buf[13:], domain)
	binary.BigEndian.PutUint16(buf[13+len(domain):], port)
	copy(buf[13+len(domain)+2:], payload)
	return buf
}

func makeSIP022Response(ip [4]byte, port uint16, payload []byte) []byte {
	buf := make([]byte, 1+8+8+2+0+1+4+2+len(payload))
	buf[0] = 1 // Type=1 response
	binary.BigEndian.PutUint64(buf[1:9], 1234567890)
	// ClientSID at 9:17 (leave as zeroes)
	binary.BigEndian.PutUint16(buf[17:19], 0) // PadLen=0
	buf[19] = 1                               // ATYP IPv4
	copy(buf[20:24], ip[:])
	binary.BigEndian.PutUint16(buf[24:26], port)
	copy(buf[26:], payload)
	return buf
}

func TestSip022Payload_IPv4Request(t *testing.T) {
	payload := []byte("hello world")
	pkt := makeSIP022Request([4]byte{127, 0, 0, 1}, 8080, payload)
	got := Sip022Payload(pkt)
	if !bytes.Equal(got, payload) {
		t.Errorf("expected %q, got %q", payload, got)
	}
}

func TestSip022Payload_DomainRequest(t *testing.T) {
	payload := []byte("data")
	pkt := makeSIP022RequestDomain("example.com", 443, payload)
	got := Sip022Payload(pkt)
	if !bytes.Equal(got, payload) {
		t.Errorf("expected %q, got %q", payload, got)
	}
}

func TestSip022Payload_IPv4Response(t *testing.T) {
	payload := []byte("response data")
	pkt := makeSIP022Response([4]byte{10, 0, 0, 1}, 9999, payload)
	got := Sip022Payload(pkt)
	if !bytes.Equal(got, payload) {
		t.Errorf("expected %q, got %q", payload, got)
	}
}

// TestSip022Payload_MalformedInputs pins that every malformed shape returns
// nil: short input, invalid type, short response body, oversized or
// overrunning padding length, missing or malformed address body.
func TestSip022Payload_MalformedInputs(t *testing.T) {
	badType := make([]byte, 20)
	badType[0] = 2 // neither request (0) nor response (1)
	shortResponse := make([]byte, 18)
	shortResponse[0] = 1 // type 1 needs 19 bytes
	oversizedPad := makeSIP022Request([4]byte{1, 2, 3, 4}, 80, []byte("x"))
	binary.BigEndian.PutUint16(oversizedPad[9:11], 901)
	skipPastEnd := makeSIP022Request([4]byte{1, 2, 3, 4}, 80, []byte("x"))
	binary.BigEndian.PutUint16(skipPastEnd[9:11], uint16(len(skipPastEnd)))
	headerOnly := makeSIP022Request([4]byte{1, 2, 3, 4}, 80, []byte("x"))[:12]
	invalidATYP := makeSIP022Request([4]byte{1, 2, 3, 4}, 80, []byte("x"))
	invalidATYP[11] = 2
	badDomainLen := makeSIP022RequestDomain("example.com", 443, []byte("data"))
	badDomainLen[12] = 255 // domain length exceeds the body
	shortV6 := makeSIP022RequestIPv6([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 443, []byte("x"))[:20]

	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"nil", nil},
		{"three-bytes", []byte{0, 0, 0}},
		{"eleven-bytes", make([]byte, 11)},
		{"bad-type", badType},
		{"short-response", shortResponse},
		{"oversized-padding", oversizedPad},
		{"padding-skips-past-end", skipPastEnd},
		{"no-address-body", headerOnly},
		{"invalid-atyp", invalidATYP},
		{"domain-length-past-end", badDomainLen},
		{"truncated-ipv6", shortV6},
	} {
		if got := Sip022Payload(tc.pkt); got != nil {
			t.Errorf("%s: Sip022Payload = %q, want nil", tc.name, got)
		}
	}
}

func TestSip022Payload_BigDomain(t *testing.T) {
	domain := strings.Repeat("a", 200)
	pkt := makeSIP022RequestDomain(domain, 443, []byte("big"))
	got := Sip022Payload(pkt)
	if !bytes.Equal(got, []byte("big")) {
		t.Errorf("expected 'big', got %q", got)
	}
}

func TestSip022Payload_ConsistentWithParseSIP022(t *testing.T) {
	// Sip022Payload and ParseSIP022 must agree on the payload for random
	// IPv4 and IPv6 packets.
	for range 100 {
		payload := make([]byte, rand.IntN(100))
		_, _ = crand.Read(payload)

		ip := [4]byte{byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))}
		port := uint16(rand.IntN(65535-1024) + 1024)
		var ip6 [16]byte
		crand.Read(ip6[:])
		pkts := [][]byte{
			makeSIP022Request(ip, port, payload),
			makeSIP022RequestIPv6(ip6, port, payload),
		}

		for _, pkt := range pkts {
			_, _, _, parsedPayload, err := ParseSIP022(pkt)
			if err != nil {
				t.Fatalf("ParseSIP022 unexpected error: %v", err)
			}
			sipPayload := Sip022Payload(pkt)
			if !bytes.Equal(parsedPayload, sipPayload) {
				t.Errorf("payload mismatch: ParseSIP022=%q, Sip022Payload=%q", parsedPayload, sipPayload)
			}
		}
	}
}

func makeSIP022RequestIPv6(ip [16]byte, port uint16, payload []byte) []byte {
	buf := make([]byte, 1+8+2+0+1+16+2+len(payload))
	buf[0] = 0
	binary.BigEndian.PutUint64(buf[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(buf[9:11], 0) // PadLen=0
	buf[11] = 4                              // ATYP IPv6
	copy(buf[12:28], ip[:])
	binary.BigEndian.PutUint16(buf[28:30], port)
	copy(buf[30:], payload)
	return buf
}

func TestSip022Payload_IPv6(t *testing.T) {
	ip := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	payload := []byte("ipv6-data")
	pkt := makeSIP022RequestIPv6(ip, 443, payload)
	got := Sip022Payload(pkt)
	if !bytes.Equal(got, payload) {
		t.Errorf("expected %q, got %q", payload, got)
	}
}

func TestParseSIP022_IPv6(t *testing.T) {
	ip := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	payload := []byte("ipv6-data-parse")
	pkt := makeSIP022RequestIPv6(ip, 443, payload)
	_, host, port, data, err := ParseSIP022(pkt)
	if err != nil {
		t.Fatalf("ParseSIP022 IPv6: %v", err)
	}
	if host != "2001:db8::1" {
		t.Errorf("expected '2001:db8::1', got '%s'", host)
	}
	if port != 443 {
		t.Errorf("expected 443, got %d", port)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("expected %q, got %q", payload, data)
	}
}

func TestBuildSIP022_IPv6(t *testing.T) {
	ip := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	payload := []byte("build-ipv6-test")
	// Construct a SOCKS5-style address: [ATYP=4][IPv6=16][PORT=2][PAYLOAD]
	addr := make([]byte, 1+16+2+len(payload))
	addr[0] = 4 // ATYP IPv6
	copy(addr[1:17], ip[:])
	binary.BigEndian.PutUint16(addr[17:19], 8080)
	copy(addr[19:], payload)

	out := BuildSIP022Request(addr)
	if len(out) <= len(addr) {
		t.Fatal("BuildSIP022Request should prepend header")
	}
	got := Sip022Payload(out)
	if !bytes.Equal(got, payload) {
		t.Errorf("expected %q, got %q", payload, got)
	}
}

func TestBuildSOCKS5Response_IPv6(t *testing.T) {
	ip := "2001:db8::1"
	payload := []byte("socks5-ipv6-resp")
	buf := make([]byte, 3+1+16+2+len(payload))
	n := BuildSOCKS5Response(buf, ip, 8080, payload)
	if n != len(buf) {
		t.Errorf("expected len %d, got %d", len(buf), n)
	}
	if buf[3] != 4 {
		t.Errorf("expected ATYP=4 for IPv6, got %d", buf[3])
	}
	gotPayload := buf[3+1+16+2:]
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("expected %q, got %q", payload, gotPayload)
	}
}

// Benchmarks

var benchSipPayload []byte // sink to prevent compiler optimizations

func BenchmarkSip022Payload_IPv4(b *testing.B) {
	ip := [4]byte{127, 0, 0, 1}
	payload := []byte("hello world benchmark data")
	pkt := makeSIP022Request(ip, 8080, payload)
	b.ResetTimer()
	for range b.N {
		benchSipPayload = Sip022Payload(pkt)
	}
}

func BenchmarkParseSIP022_IPv4(b *testing.B) {
	ip := [4]byte{127, 0, 0, 1}
	payload := []byte("hello world benchmark data")
	pkt := makeSIP022Request(ip, 8080, payload)
	b.ResetTimer()
	for range b.N {
		_, _, _, benchSipPayload, _ = ParseSIP022(pkt)
	}
}

func BenchmarkSip022Payload_Domain(b *testing.B) {
	payload := []byte("data")
	pkt := makeSIP022RequestDomain("example.com", 443, payload)
	b.ResetTimer()
	for range b.N {
		benchSipPayload = Sip022Payload(pkt)
	}
}

func BenchmarkParseSIP022_Domain(b *testing.B) {
	payload := []byte("data")
	pkt := makeSIP022RequestDomain("example.com", 443, payload)
	b.ResetTimer()
	for range b.N {
		_, _, _, benchSipPayload, _ = ParseSIP022(pkt)
	}
}

func BenchmarkSip022Payload_IPv6(b *testing.B) {
	ip := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	payload := []byte("ipv6 benchmark data")
	pkt := makeSIP022RequestIPv6(ip, 443, payload)
	b.ResetTimer()
	for range b.N {
		benchSipPayload = Sip022Payload(pkt)
	}
}

func TestParseSIP022_EmptyNoPanic(t *testing.T) {
	// Empty and short inputs must produce an error, not panic on b[0] in the
	// error-formatting path (reachable via zero-length decrypted payloads).
	for _, in := range [][]byte{nil, {}, {1}, []byte{1, 2, 3}} {
		if _, _, _, _, err := ParseSIP022(in); err == nil {
			t.Errorf("ParseSIP022(len=%d) should fail", len(in))
		}
	}
}

// TestBuildSIP022_InvalidInputReturnsNil pins the wrap contract: input that
// does not carry a valid ATYP header (too short, an unsupported address type,
// or a truncated address body) must yield nil — never a silent pass-through
// that would enter a 2022 tunnel bare, and never a wrapped packet the
// receiving layer is guaranteed to drop.
func TestBuildSIP022_InvalidInputReturnsNil(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{1, 2, 3},            // too short for ATYP+ADDR+PORT
		{9, 1, 2, 3, 4},      // unsupported ATYP=9
		{0},                  // bare zero byte
		{1, 127, 0, 0},       // truncated IPv4 address
		{1, 127, 0, 0, 1, 0}, // missing the second port byte
		{4, 1, 2, 3},         // truncated IPv6 address
		{3, 200, 'a', 'b'},   // domain claims 200 bytes, body has 2
	}
	for _, in := range inputs {
		if out := BuildSIP022Request(in); out != nil {
			t.Errorf("BuildSIP022Request(len=%d) = %d bytes, want nil", len(in), len(out))
		}
		if out := BuildSIP022Response(in, 0); out != nil {
			t.Errorf("BuildSIP022Response(len=%d) = %d bytes, want nil", len(in), len(out))
		}
	}
	// A valid address must still wrap.
	out := BuildSIP022Request([]byte{1, 127, 0, 0, 1, 0, 80, 'h', 'i'})
	if out == nil {
		t.Fatal("valid IPv4 packet must wrap")
	}
	if Sip022Payload(out) == nil {
		t.Fatal("wrapped packet must parse back")
	}
	// The smallest complete shape of each family must keep wrapping.
	v6 := append(make([]byte, 16), 0, 80)
	minimal := [][]byte{
		{1, 127, 0, 0, 1, 0, 80}, // ATYP=1: exactly 7 bytes
		{3, 0, 0, 80},            // ATYP=3: empty domain, 4 bytes
		append([]byte{4}, v6...), // ATYP=4: exactly 19 bytes
	}
	for _, in := range minimal {
		if out := BuildSIP022Request(in); out == nil {
			t.Errorf("minimal complete ATYP=%d packet must wrap", in[0])
		}
	}
}
