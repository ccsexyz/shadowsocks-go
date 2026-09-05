package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func mustAESGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return aead
}

// buildUDP2022AESPacket builds a SIP022 AES UDP packet with a caller-chosen
// session/packet ID and body.
func buildUDP2022AESPacket(t *testing.T, psk, sessionKey, body []byte, sid, pid uint64) []byte {
	t.Helper()
	var sepHdr [16]byte
	binary.BigEndian.PutUint64(sepHdr[0:8], sid)
	binary.BigEndian.PutUint64(sepHdr[8:16], pid)

	block, err := aes.NewCipher(psk)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	encHdr := make([]byte, 16)
	block.Encrypt(encHdr, sepHdr[:])

	aead := mustAESGCM(t, sessionKey)
	out := make([]byte, 0, 16+len(body)+aead.Overhead())
	out = append(out, encHdr...)
	out = aead.Seal(out, sepHdr[4:16], body, nil)
	return out
}

// validUDP2022Body returns a SIP022 main packet (type + timestamp + padding
// len + addr + payload) that passes validateUDP2022Packet.
func validUDP2022Body() []byte {
	b := make([]byte, 0, 11+7+5)
	b = append(b, 0) // type: client request
	binary.BigEndian.PutUint64(b[len(b):len(b)+8], uint64(time.Now().Unix()))
	b = b[:len(b)+8]
	b = append(b, 0, 0)                   // padding len
	b = append(b, 1, 127, 0, 0, 1, 0, 80) // IPv4 addr + port
	b = append(b, []byte("hello")...)
	return b
}

// TestUDP2022AES_ReplayWindowNotBurnedByInvalidBody verifies the SIP022 rule
// that the sliding window is not updated for packets that fail
// authentication or main-header validation: a packet whose body does not
// decrypt must not consume the packet ID of a later valid packet.
func TestUDP2022AES_ReplayWindowNotBurnedByInvalidBody(t *testing.T) {
	psk := []byte("0123456789abcdef")
	cb, err := newUdp2022AESCipherBlock(psk, 16)
	if err != nil {
		t.Fatal(err)
	}

	var sid uint64 = 0x1122334455667788
	var pid uint64 = 1
	// The session table is process-global; reset the test session so the
	// sliding window starts clean even under -count>1.
	udp2022Sessions.Delete(sid)
	sessionKey := kdf2022(psk, uint64ToBytes(sid), len(psk))
	body := validUDP2022Body()

	good := buildUDP2022AESPacket(t, psk, sessionKey, body, sid, pid)
	// Authenticates fine but fails main-header validation (garbage header).
	badHeader := buildUDP2022AESPacket(t, psk, sessionKey, []byte("garbage"), sid, pid)
	// Valid header whose MAC is broken (corrupted body).
	badMAC := append([]byte{}, good...)
	badMAC[len(badMAC)-1] ^= 0xff

	dst := make([]byte, 2048)
	if _, _, err := cb.Decrypt(dst, badHeader); err == nil {
		t.Fatal("packet with invalid main header must be dropped")
	}
	if _, _, err := cb.Decrypt(dst, badMAC); err == nil {
		t.Fatal("packet with corrupted body must fail to decrypt")
	}

	plaintext, _, err := cb.Decrypt(dst, good)
	if err != nil {
		t.Fatalf("valid packet with same packet ID rejected after corrupt packet: %v", err)
	}
	if !bytes.Equal(plaintext, body) {
		t.Fatalf("plaintext mismatch: %q", plaintext)
	}

	// A genuine replay of the accepted packet must still be dropped.
	if _, _, err := cb.Decrypt(dst, good); err == nil {
		t.Fatal("replayed packet must be dropped")
	}
}

// TestUDP2022ChaCha_ShortPacketDropped verifies that packets whose decrypted
// payload is too short to carry the session/packet ID prefix are dropped
// instead of being delivered without a replay check.
func TestUDP2022ChaCha_ShortPacketDropped(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	cb, err := newUdp2022ChaChaCipherBlock(psk, 32)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 24)
	PutRandomBytes(nonce)
	packet := make([]byte, 0, 24+aead.Overhead()+3)
	packet = append(packet, nonce...)
	packet = aead.Seal(packet, nonce, []byte{1, 2, 3}, nil)

	dst := make([]byte, 2048)
	if _, _, err := cb.Decrypt(dst, packet); err == nil {
		t.Fatal("short decrypted payload must be dropped")
	}
}

// TestUDP2022_SendPIDMonotonicAcrossSessionExpiry verifies that outgoing
// packet IDs keep increasing even when the session entry is evicted (e.g.
// by the idle janitor). A reset would make the peer's replay window reject
// every subsequent packet.
func TestUDP2022_SendPIDMonotonicAcrossSessionExpiry(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	cb, err := newUdp2022AESCipherBlock(psk, 32)
	if err != nil {
		t.Fatal(err)
	}

	dst := make([]byte, 2048)
	ct1, _, err := cb.Encrypt(dst, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(psk)
	var sepHdr1 [16]byte
	block.Decrypt(sepHdr1[:], ct1[:16])
	sid := binary.BigEndian.Uint64(sepHdr1[0:8])
	pid1 := binary.BigEndian.Uint64(sepHdr1[8:16])

	// Simulate the receiving side's 60s idle expiry on our own session.
	udp2022Sessions.Delete(sid)

	ct2, _, err := cb.Encrypt(dst, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	var sepHdr2 [16]byte
	block.Decrypt(sepHdr2[:], ct2[:16])
	if sid2 := binary.BigEndian.Uint64(sepHdr2[0:8]); sid2 != sid {
		t.Fatalf("session ID changed across expiry: %d -> %d", sid, sid2)
	}
	if pid2 := binary.BigEndian.Uint64(sepHdr2[8:16]); pid2 != pid1+1 {
		t.Fatalf("packet ID not monotonic across session expiry: %d -> %d", pid1, pid2)
	}
}

func TestValidateUDP2022Packet(t *testing.T) {
	if !validateUDP2022Packet(validUDP2022Body()) {
		t.Fatal("valid packet rejected")
	}

	bad := validUDP2022Body()
	bad[0] = 7 // invalid type
	if validateUDP2022Packet(bad) {
		t.Fatal("invalid type accepted")
	}

	bad = validUDP2022Body()
	binary.BigEndian.PutUint64(bad[1:9], uint64(time.Now().Unix()-3600)) // stale
	if validateUDP2022Packet(bad) {
		t.Fatal("stale timestamp accepted")
	}

	bad = validUDP2022Body()
	binary.BigEndian.PutUint16(bad[9:11], 901) // padding len over the limit
	if validateUDP2022Packet(bad) {
		t.Fatal("oversized padding accepted")
	}

	if validateUDP2022Packet([]byte{0, 1, 2}) {
		t.Fatal("truncated packet accepted")
	}
}

// TestValidateUDP2022StaleType1Rejected pins that a server→client (type=1)
// packet whose timestamp went stale is rejected by the timestamp check: its
// first bytes alias as ATYP=1, so the legacy parse must not resurrect it
// after a replay-window reset.
func TestValidateUDP2022StaleType1Rejected(t *testing.T) {
	resp := BuildSIP022Response([]byte{1, 127, 0, 0, 1, 0, 80, 'h', 'i'}, 0)
	if !validateUDP2022Packet(resp) {
		t.Fatal("fresh type=1 response rejected")
	}
	// Rebuild with a stale timestamp.
	stale := BuildSIP022Response([]byte{1, 127, 0, 0, 1, 0, 80, 'h', 'i'}, 0)
	binary.BigEndian.PutUint64(stale[1:9], uint64(time.Now().Unix()-3600))
	if validateUDP2022Packet(stale) {
		t.Fatal("stale type=1 packet accepted via legacy fall-through")
	}
}

// TestValidateUDP2022RejectsLegacyBare pins the strict 2022 payload format:
// bare ATYP packets are a classic-cipher shape and must be rejected at the
// 2022 layer — accepting them forced every 2022 receiver to guess the format.
// Legacy payloads reach a 2022 hop only via BuildSIP022Request wrapping.
func TestValidateUDP2022RejectsLegacyBare(t *testing.T) {
	// Short legacy IPv4 packet.
	legacy := []byte{1, 127, 0, 0, 1, 0, 80, 'h', 'i'}
	if validateUDP2022Packet(legacy) {
		t.Fatal("legacy bare IPv4 packet accepted")
	}
	// Legacy bare domain packet.
	legacyLong := append([]byte{3, 9}, []byte("localhost")...)
	legacyLong = append(legacyLong, 0, 80)
	legacyLong = append(legacyLong, []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")...)
	if validateUDP2022Packet(legacyLong) {
		t.Fatal("legacy bare domain packet accepted")
	}
	// Bare IPv4 packets carrying DNS queries whose QNAME shapes used to
	// alias as structurally-valid-but-stale SIP022 (ARCOUNT=0 at
	// payload[10:12] → padLen 0; QNAME label length 1 or 4 → inner ATYP).
	for _, qname := range []string{"m.google.com", "a.pp.ua", "mail.google.com"} {
		if validateUDP2022Packet(dnsQueryBarePacket(qname)) {
			t.Fatalf("DNS-query-shaped bare IPv4 packet (%s) accepted at the 2022 layer", qname)
		}
	}
	// The same payload, properly SIP022-wrapped, must pass.
	if !validateUDP2022Packet(BuildSIP022Request(dnsQueryBarePacket("m.google.com"))) {
		t.Fatal("SIP022-wrapped DNS query rejected")
	}
}

// dnsQueryBarePacket builds a bare ATYP=1 UDP packet addressed to
// 192.168.1.53:53 whose payload is a plain DNS query for qname
// (QDCOUNT=1, AN/NS/ARCOUNT=0).
func dnsQueryBarePacket(qname string) []byte {
	dns := make([]byte, 12)
	dns[0], dns[1] = 0xab, 0xcd
	dns[2] = 0x01 // recursion desired
	dns[5] = 1    // QDCOUNT=1
	for _, label := range dnsLabels(qname) {
		dns = append(dns, byte(len(label)))
		dns = append(dns, label...)
	}
	dns = append(dns, 0)    // root
	dns = append(dns, 0, 1) // QTYPE=A
	dns = append(dns, 0, 1) // QCLASS=IN
	out := make([]byte, 0, 7+len(dns))
	out = append(out, 1, 192, 168, 1, 53, 0, 53)
	out = append(out, dns...)
	return out
}

func dnsLabels(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func TestUDP2022SessionCapEvictsOnInsert(t *testing.T) {
	old := udp2022MaxSessions
	udp2022MaxSessions = 100
	defer func() {
		udp2022MaxSessions = old
		udp2022Sessions.Range(func(k, _ any) bool {
			udp2022Sessions.Delete(k)
			return true
		})
		udp2022SessionCount.Store(0)
	}()
	for i := 0; i < 150; i++ {
		udp2022CreateSession(uint64(i)+1, nil)
	}
	count := 0
	udp2022Sessions.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count > 100 {
		t.Fatalf("session table not capped at insert time: %d entries", count)
	}
}
