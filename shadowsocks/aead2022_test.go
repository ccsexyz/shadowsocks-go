package ss

import (
	"encoding/binary"
	"testing"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

// TestBuildAead2022HeaderPaddingNonZeroWithoutPayload pins the SIP022 rule
// that a request header with no initial payload MUST carry non-zero padding:
// servers are required to reject zero padding together with zero payload, so
// a zero roll here makes the client fail against every compliant server.
func TestBuildAead2022HeaderPaddingNonZeroWithoutPayload(t *testing.T) {
	psk := utils.GetRandomBytes(32)
	hdr, err := GetHeader("1.2.3.4", 80)
	if err != nil {
		t.Fatal(err)
	}
	addr := &SockAddr{Hdr: hdr}

	// Enough iterations that the pre-fix uniform [0,900] range would almost
	// surely produce zero at least once.
	const iterations = 10000
	for i := 0; i < iterations; i++ {
		salt := utils.GetRandomBytes(32)
		ciph, err := crypto.NewTcpCipher2022(test2022Method, psk, salt)
		if err != nil {
			t.Fatal(err)
		}
		total := buildAead2022Header(ciph, salt, addr, nil)
		if total == nil {
			t.Fatal("buildAead2022Header returned nil")
		}
		padSize, ok := parseAead2022RequestPadding(test2022Method, psk, salt, total)
		if !ok {
			t.Fatalf("iteration %d: header parse failed", i)
		}
		if padSize == 0 {
			t.Fatalf("iteration %d: zero padding with empty payload", i)
		}
		if padSize > 900 {
			t.Fatalf("iteration %d: padding %d exceeds MaxPaddingLength", i, padSize)
		}
	}
}

// parseAead2022RequestPadding decrypts a client request header with a fresh
// cipher (TcpCipher2022 carries a per-packet nonce) and returns the declared
// padding length.
func parseAead2022RequestPadding(method string, psk, salt, total []byte) (int, bool) {
	ciph, err := crypto.NewTcpCipher2022(method, psk, salt)
	if err != nil {
		return 0, false
	}
	oh := ciph.Overhead()
	saltLen := len(salt)
	hdr1Len := 1 + 8 + 2 + oh
	if len(total) < saltLen+hdr1Len {
		return 0, false
	}
	hdr1, ok := ciph.DecryptPacket(append([]byte{}, total[saltLen:saltLen+hdr1Len]...))
	if !ok || len(hdr1) < 11 {
		return 0, false
	}
	hdr2Len := int(binary.BigEndian.Uint16(hdr1[9:11])) + oh
	if len(total) < saltLen+hdr1Len+hdr2Len {
		return 0, false
	}
	hdr2, ok := ciph.DecryptPacket(append([]byte{}, total[saltLen+hdr1Len:saltLen+hdr1Len+hdr2Len]...))
	if !ok {
		return 0, false
	}
	_, rest, err := ParseAddr(hdr2)
	if err != nil || len(rest) < 2 {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(rest[:2])), true
}
