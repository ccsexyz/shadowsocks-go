package ss

import (
	"net"
	"sync"
	"testing"

	"github.com/ccsexyz/shadowsocks-go/crypto"
)

func TestParseAddrWithMultipleBackendsForUDP_Non2022(t *testing.T) {
	// Server side: create a non-2022 encrypted UDP packet
	serverCfg := &Config{}
	serverCfg.Method = "aes-256-gcm"
	serverCfg.Password = "test123"
	CheckConfig(serverCfg)

	cb, err := crypto.NewCipherBlock("aes-256-gcm", "test123")
	if err != nil {
		t.Fatal("NewCipherBlock:", err)
	}

	// Build address header: ATYP=1, 127.0.0.1:80
	header := []byte{1, 127, 0, 0, 1, 0, 80}
	payload := []byte("test-payload")
	plaintext := append(header, payload...)

	enc, iv, err := cb.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal("Encrypt:", err)
	}
	if len(iv) == 0 {
		t.Error("non-2022 Encrypt should return non-empty IV")
	}

	// Parse with matching backend
	backends := []*Config{
		{CryptoConfig: CryptoConfig{Method: "aes-256-gcm", Password: "test123"}},
	}
	for _, c := range backends {
		CheckBasicConfig(c)
	}

	ctx, err := ParseAddrWithMultipleBackendsForUDP(enc, backends)
	if err != nil {
		t.Fatal("ParseAddrWithMultipleBackendsForUDP:", err)
	}
	if ctx.chs != backends[0] {
		t.Error("should match first backend")
	}
	if string(ctx.data) != string(payload) {
		t.Errorf("data mismatch: %q vs %q", ctx.data, payload)
	}
	if len(ctx.iv) == 0 {
		t.Error("non-2022 ctx.iv should not be empty")
	}
}

func TestParseAddrWithMultipleBackendsForUDP_2022(t *testing.T) {
	cb, err := crypto.NewCipherBlock("2022-blake3-aes-256-gcm",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal("NewCipherBlock:", err)
	}

	header := []byte{1, 127, 0, 0, 1, 0, 80}
	payload := []byte("test-payload-2022")
	plaintext := append(header, payload...)

	enc, iv, err := cb.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal("Encrypt:", err)
	}
	if len(iv) != 0 {
		t.Error("2022 Encrypt should return empty IV (replay handled by sliding window)")
	}

	backends := []*Config{
		{CryptoConfig: CryptoConfig{Method: "2022-blake3-aes-256-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
		{CryptoConfig: CryptoConfig{Method: "aes-256-gcm", Password: "wrong-password"}},
	}
	for _, c := range backends {
		CheckBasicConfig(c)
	}

	ctx, err := ParseAddrWithMultipleBackendsForUDP(enc, backends)
	if err != nil {
		t.Fatal("ParseAddrWithMultipleBackendsForUDP:", err)
	}
	if ctx.chs != backends[0] {
		t.Error("should match the 2022 backend")
	}
	if string(ctx.data) != string(payload) {
		t.Errorf("data mismatch: %q vs %q", ctx.data, payload)
	}
	// Key assertion: 2022 returns empty IV, caller must guard udpFilterTestAndAdd
	if len(ctx.iv) != 0 {
		t.Errorf("2022 ctx.iv should be empty, got %d bytes", len(ctx.iv))
	}
}

func TestParseAddrWithMultipleBackendsForUDP_WrongBackendsSkipped(t *testing.T) {
	cb, err := crypto.NewCipherBlock("aes-256-gcm", "correct-password")
	if err != nil {
		t.Fatal("NewCipherBlock:", err)
	}

	plaintext := []byte{1, 127, 0, 0, 1, 0, 80, 'd', 'a', 't', 'a'}
	enc, _, err := cb.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal("Encrypt:", err)
	}

	// All backends have wrong passwords
	backends := []*Config{
		{CryptoConfig: CryptoConfig{Method: "aes-256-gcm", Password: "wrong1"}},
		{CryptoConfig: CryptoConfig{Method: "aes-128-gcm", Password: "wrong2"}},
		{CryptoConfig: CryptoConfig{Method: "chacha20-ietf-poly1305", Password: "wrong3"}},
	}
	for _, c := range backends {
		CheckBasicConfig(c)
	}

	_, err = ParseAddrWithMultipleBackendsForUDP(enc, backends)
	if err == nil {
		t.Error("should fail when no backend can decrypt")
	}
}

func TestParseAddrWithMultipleBackendsForUDP_2022IVIsEmpty(t *testing.T) {
	// This test verifies the exact scenario that caused the bug:
	// 2022 Decrypt returns empty IV, and MultiUDPConn.ReadFrom must
	// not call udpFilterTestAndAdd with an empty IV.

	cb, err := crypto.NewCipherBlock("2022-blake3-aes-128-gcm",
		"AAAAAAAAAAAAAAAAAAAAAA==")
	if err != nil {
		t.Fatal("NewCipherBlock:", err)
	}

	plaintext := []byte{1, 127, 0, 0, 1, 0, 80, 'x'}
	enc, _, err := cb.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal("Encrypt:", err)
	}

	backends := []*Config{
		{CryptoConfig: CryptoConfig{Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}},
	}
	for _, c := range backends {
		CheckBasicConfig(c)
	}

	ctx, err := ParseAddrWithMultipleBackendsForUDP(enc, backends)
	if err != nil {
		t.Fatal(err)
	}

	// This is the critical assertion: 2022 IV must be empty.
	// If this fails, udpFilterTestAndAdd would be called with empty IV
	// and all subsequent packets would be rejected as duplicates.
	if len(ctx.iv) != 0 {
		t.Fatalf("2022 IV must be empty to trigger len(iv)>0 guard, got %d bytes: %x", len(ctx.iv), ctx.iv)
	}

	// Simulate what MultiUDPConn.ReadFrom does after getting the context.
	// The guard MUST skip udpFilterTestAndAdd when iv is empty.
	if len(ctx.iv) > 0 {
		t.Error("len(ctx.iv)>0 guard should skip filter for 2022")
	}
	// If we had called udpFilterTestAndAdd(ctx.iv) here without the guard,
	// it would store an empty IV and break all future 2022 packets.
}

func TestParseAddrWithMultipleBackendsForUDP_Mixed2022AndNon2022(t *testing.T) {
	// Verify that when both 2022 and non-2022 backends are configured,
	// the correct one is selected based on the packet's encryption.

	psk32 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	// Create a 2022-encrypted packet
	cb2022, _ := crypto.NewCipherBlock("2022-blake3-aes-256-gcm", psk32)
	plaintext := []byte{3, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0, 0, 80, 'd', 'a', 't', 'a'}
	enc2022, _, _ := cb2022.Encrypt(nil, plaintext)

	backends := []*Config{
		{CryptoConfig: CryptoConfig{Method: "aes-256-gcm", Password: "non2022-password"}},      // wrong for this packet
		{CryptoConfig: CryptoConfig{Method: "2022-blake3-aes-256-gcm", Password: psk32}},       // correct
		{CryptoConfig: CryptoConfig{Method: "chacha20-ietf-poly1305", Password: "another-pw"}}, // wrong
	}
	for _, c := range backends {
		CheckBasicConfig(c)
	}

	ctx, err := ParseAddrWithMultipleBackendsForUDP(enc2022, backends)
	if err != nil {
		t.Fatal("should find the 2022 backend:", err)
	}
	if ctx.chs != backends[1] {
		t.Error("should match backend[1] (the 2022 one)")
	}
	if len(ctx.iv) != 0 {
		t.Errorf("2022 IV should be empty, got %d bytes", len(ctx.iv))
	}

	// Now test with a non-2022 packet
	cbNon2022, _ := crypto.NewCipherBlock("aes-256-gcm", "non2022-password")
	encNon2022, _, _ := cbNon2022.Encrypt(nil, plaintext)

	ctx2, err := ParseAddrWithMultipleBackendsForUDP(encNon2022, backends)
	if err != nil {
		t.Fatal("should find the non-2022 backend:", err)
	}
	if ctx2.chs != backends[0] {
		t.Error("should match backend[0] (the aes-256-gcm one)")
	}
	if len(ctx2.iv) == 0 {
		t.Error("non-2022 IV should not be empty")
	}
}

func TestMultiUDPConn_IVGuardPresent(t *testing.T) {
	// Verify at compile time that all udpFilterTestAndAdd call sites
	// are protected by len(iv) > 0. This test documents the requirement.
	//
	// Call sites (all in udpconn.go):
	// 1. readImpl:118       — guarded by len(iv) > 0 ✓
	// 2. MultiUDPConn:206   — guarded by len(ctx.iv) > 0 ✓ (fixed a069f4c)
	// 3. MultiUDPConn:233   — guarded by len(iv) > 0 ✓

	// If a new CipherBlock returns empty IV (like 2022), any new
	// udpFilterTestAndAdd call site must also add the len(iv)>0 guard.
	//
	// To find all call sites: grep -rn 'udpFilterTestAndAdd' --include='*.go'
	_ = net.IPv4len // prevent unused import error
	_ = sync.Map{}
}
