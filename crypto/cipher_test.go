package crypto

import (
	"bytes"
	"testing"
)

// TestAEADChunkLengthBeyondLimitRejected verifies that a decrypted chunk
// length above 0x3FFF is treated as a protocol violation instead of being
// masked down (the two high bits are reserved by the AEAD spec).
func TestAEADChunkLengthBeyondLimitRejected(t *testing.T) {
	const password = "test-password-01"
	key := kdf(password, 16)
	iv := GetRandomBytes(16)

	aead, err := (&aesAEADCreater{key}).NewAEAD(iv)
	if err != nil {
		t.Fatal(err)
	}
	encTag := aead.Seal(nil, zeroBuf[:aead.NonceSize()], []byte{0x40, 0x00}, nil)

	dec, err := NewAESGCMDecrypter(key, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := dec.WriteFrame(iv); err != nil {
		t.Fatal(err)
	}
	if err := dec.WriteFrame(encTag); err != nil {
		t.Fatal(err)
	}

	if _, err := dec.ReadFrame(make([]byte, 64)); err == nil {
		t.Fatal("ReadFrame: oversized chunk length must be rejected")
	}

	dec2, err := NewAESGCMDecrypter(key, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := dec2.WriteFrame(iv); err != nil {
		t.Fatal(err)
	}
	if err := dec2.WriteFrame(encTag); err != nil {
		t.Fatal(err)
	}
	if _, err := dec2.Read(make([]byte, 64)); err == nil {
		t.Fatal("Read: oversized chunk length must be rejected")
	}
}

// TestAEADChunkLengthLimitAccepted verifies a legitimate 0x3FFF chunk still
// passes through the length check.
func TestAEADChunkLengthLimitAccepted(t *testing.T) {
	const password = "test-password-01"
	key := kdf(password, 16)
	iv := GetRandomBytes(16)

	aead, err := (&aesAEADCreater{key}).NewAEAD(iv)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0xab}, aeadSizeMask)
	encTag := aead.Seal(nil, zeroBuf[:aead.NonceSize()], []byte{0x3f, 0xff}, nil)
	var nonce1 [12]byte
	nonce1[0] = 1 // nonce counter increments little-endian
	encBody := aead.Seal(nil, nonce1[:], payload, nil)

	dec, err := NewAESGCMDecrypter(key, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := dec.WriteFrame(iv); err != nil {
		t.Fatal(err)
	}
	if err := dec.WriteFrame(encTag); err != nil {
		t.Fatal(err)
	}
	if err := dec.WriteFrame(encBody); err != nil {
		t.Fatal(err)
	}

	frame, err := dec.ReadFrame(make([]byte, aeadSizeMask+64))
	if err != nil {
		t.Fatalf("ReadFrame: maximum-length chunk rejected: %v", err)
	}
	if !bytes.Equal(frame, payload) {
		t.Fatal("frame content mismatch")
	}
}

// TestUnknownMethodFailsClosed verifies that a typo'd cipher method returns
// an error everywhere instead of silently falling back to the default method.
func TestUnknownMethodFailsClosed(t *testing.T) {
	const bogus = "aes-257-gcm"
	if _, err := NewEncrypter(bogus, "pw"); err == nil {
		t.Error("NewEncrypter: unknown method must fail")
	}
	if _, err := NewDecrypter(bogus, "pw"); err == nil {
		t.Error("NewDecrypter: unknown method must fail")
	}
	if _, err := NewCipherBlock(bogus, "pw"); err == nil {
		t.Error("NewCipherBlock: unknown method must fail")
	}
	if _, err := NewPacker(bogus, "pw", true); err == nil {
		t.Error("NewPacker: unknown method must fail")
	}
	if _, err := NewUnpacker(bogus, "pw"); err == nil {
		t.Error("NewUnpacker: unknown method must fail")
	}
	if HasMethod(bogus) {
		t.Error("HasMethod: unknown method must not be reported as known")
	}
	if !HasMethod("aes-128-gcm") || !HasMethod("2022-blake3-aes-256-gcm") {
		t.Error("HasMethod: known methods must be reported")
	}
}

// TestNewCipherBlockEmptyPasswordError verifies the empty-password error is
// descriptive rather than a bare io.EOF.
func TestNewCipherBlockEmptyPasswordError(t *testing.T) {
	_, err := NewCipherBlock("aes-128-gcm", "")
	if err == nil {
		t.Fatal("empty password must be rejected")
	}
	if err.Error() != "password cannot be empty" {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestAEADStreamRoundtripAfterLengthCheck is a sanity check that the legacy
// AEAD stream still decrypts after the length check change.
func TestAEADStreamRoundtripAfterLengthCheck(t *testing.T) {
	const password = "test-password-02"
	master := kdf(password, 16)
	iv := GetRandomBytes(16)

	enc, err := NewAESGCMEncrypter(aeadKey(master, iv), iv)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewAESGCMDecrypter(master, 16)
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("shadowsocks"), 1000)
	if err := enc.WriteFrame(payload); err != nil {
		t.Fatal(err)
	}

	// The encrypter emits the IV as the first bytes of its output stream.
	wire := make([]byte, 0, len(iv)+len(payload)*2)
	buf := make([]byte, 4096)
	for {
		n, err := enc.Read(buf)
		wire = append(wire, buf[:n]...)
		if err != nil {
			break
		}
	}

	if err := dec.WriteFrame(wire); err != nil {
		t.Fatal(err)
	}
	got, err := dec.ReadFrame(make([]byte, len(payload)+64))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestAEADUnpacker_ShortDatagramNoPanic(t *testing.T) {
	// A UDP datagram shorter than salt+tag must be dropped, not panic on
	// b[ivLen:packetLen] (remote unauthenticated crash).
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		u, err := NewUnpacker(method, "test-password")
		if err != nil {
			t.Fatalf("%s: NewUnpacker: %v", method, err)
		}
		hr := u.Headroom()
		buf := make([]byte, hr.Front+hr.Rear+256)
		for _, n := range []int{0, 1, 8, hr.Front - 1, hr.Front + 15} {
			_, _, err := u.UnpackInPlace(buf, 0, n)
			if err == nil {
				t.Errorf("%s: UnpackInPlace(len=%d) should fail", method, n)
			}
		}
	}
}
