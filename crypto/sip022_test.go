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
	buf[0] = 0 // Type=0 request
	binary.BigEndian.PutUint64(buf[1:9], uint64(time.Now().Unix())) // current TS
	binary.BigEndian.PutUint16(buf[9:11], 0)          // PadLen=0
	buf[11] = 1                                        // ATYP IPv4
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
	buf[11] = 3                               // ATYP domain
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
	buf[19] = 1                                 // ATYP IPv4
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

func TestSip022Payload_TooShort(t *testing.T) {
	if got := Sip022Payload(nil); got != nil {
		t.Error("expected nil for nil input")
	}
	if got := Sip022Payload([]byte{0, 0, 0}); got != nil {
		t.Error("expected nil for short input")
	}
	if got := Sip022Payload(make([]byte, 11)); got != nil {
		t.Error("expected nil for len=11")
	}
}

func TestSip022Payload_BadType(t *testing.T) {
	buf := make([]byte, 20)
	buf[0] = 2 // invalid type
	if got := Sip022Payload(buf); got != nil {
		t.Error("expected nil for invalid type")
	}
}

func TestSip022Payload_ResponseTooShort(t *testing.T) {
	buf := make([]byte, 18)
	buf[0] = 1 // Type=1 (needs at least 19 bytes)
	if got := Sip022Payload(buf); got != nil {
		t.Error("expected nil for short response")
	}
}

func TestSip022Payload_PaddingTooLarge(t *testing.T) {
	pkt := makeSIP022Request([4]byte{1, 2, 3, 4}, 80, []byte("x"))
	// Corrupt padding length
	binary.BigEndian.PutUint16(pkt[9:11], 901)
	if got := Sip022Payload(pkt); got != nil {
		t.Error("expected nil for padding > 900")
	}
}

func TestSip022Payload_PacketTooShortForSkip(t *testing.T) {
	pkt := makeSIP022Request([4]byte{1, 2, 3, 4}, 80, []byte("x"))
	// Corrupt padding length to make skip exceed packet length
	binary.BigEndian.PutUint16(pkt[9:11], uint16(len(pkt)))
	if got := Sip022Payload(pkt); got != nil {
		t.Error("expected nil when skip exceeds packet length")
	}
}

func TestSip022Payload_RestTooShort(t *testing.T) {
	pkt := makeSIP022Request([4]byte{1, 2, 3, 4}, 80, []byte("x"))
	// Truncate after SIP022 header to have < 4 bytes in rest
	pkt = pkt[:12] // just header, no rest
	if got := Sip022Payload(pkt); got != nil {
		t.Error("expected nil when rest is too short")
	}
}

func TestSip022Payload_InvalidATYP(t *testing.T) {
	pkt := makeSIP022Request([4]byte{1, 2, 3, 4}, 80, []byte("x"))
	// Corrupt ATYP
	pkt[11] = 2 // invalid ATYP
	if got := Sip022Payload(pkt); got != nil {
		t.Error("expected nil for invalid ATYP")
	}
}

func TestSip022Payload_DomainHdrTooShort(t *testing.T) {
	pkt := makeSIP022RequestDomain("example.com", 443, []byte("data"))
	// Corrupt domain length to exceed packet
	restStart := 11
	pkt[restStart] = 3     // ATYP domain
	pkt[restStart+1] = 255 // domain length way too long
	if got := Sip022Payload(pkt); got != nil {
		t.Error("expected nil when domain header exceeds packet")
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
	// Verify Sip022Payload and ParseSIP022 agree on payload for various packets
	for range 100 {
		payload := make([]byte, rand.IntN(100))
		_, _ = crand.Read(payload)

		ip := [4]byte{byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))}
		port := uint16(rand.IntN(65535-1024) + 1024)
		pkt := makeSIP022Request(ip, port, payload)

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

func makeSIP022RequestIPv6(ip [16]byte, port uint16, payload []byte) []byte {
	buf := make([]byte, 1+8+2+0+1+16+2+len(payload))
	buf[0] = 0
	binary.BigEndian.PutUint64(buf[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(buf[9:11], 0) // PadLen=0
	buf[11] = 4                                 // ATYP IPv6
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

func TestSip022Payload_IPv6TooShort(t *testing.T) {
	ip := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	payload := []byte("x")
	pkt := makeSIP022RequestIPv6(ip, 443, payload)
	// Truncate in the middle of the IPv6 address
	short := pkt[:12+8] // only 8 bytes of 16-byte IPv6 addr
	if got := Sip022Payload(short); got != nil {
		t.Error("expected nil for truncated IPv6 packet")
	}
}

func TestSip022Payload_IPv6ConsistentWithParseSIP022(t *testing.T) {
	for range 100 {
		var ip [16]byte
		crand.Read(ip[:])
		payload := make([]byte, rand.IntN(50))
		crand.Read(payload)
		port := uint16(rand.IntN(65535-1024) + 1024)
		pkt := makeSIP022RequestIPv6(ip, port, payload)

		_, _, _, parsedPayload, err := ParseSIP022(pkt)
		if err != nil {
			t.Fatalf("ParseSIP022 IPv6 unexpected error: %v", err)
		}
		sipPayload := Sip022Payload(pkt)
		if !bytes.Equal(parsedPayload, sipPayload) {
			t.Errorf("IPv6 payload mismatch: ParseSIP022=%q, Sip022Payload=%q", parsedPayload, sipPayload)
		}
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
