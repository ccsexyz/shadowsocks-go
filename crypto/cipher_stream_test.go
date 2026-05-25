package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// helpers

func drainEncrypted(t *testing.T, enc CipherStream) []byte {
	t.Helper()
	var out []byte
	for {
		frame, err := enc.ReadFrame(nil)
		if err != nil && err != io.EOF {
			t.Fatal("ReadFrame:", err)
		}
		if frame != nil {
			for _, seg := range [][]byte{frame} {
				out = append(out, seg...)
			}

		}
		if err == io.EOF {
			break
		}
	}
	return out
}

func drainDecrypted(t *testing.T, dec CipherStream) []byte {
	t.Helper()
	var out []byte
	for {
		frame, err := dec.ReadFrame(nil)
		if err != nil && err != io.EOF {
			t.Fatal("ReadFrame:", err)
		}
		if frame != nil {
			for _, seg := range [][]byte{frame} {
				out = append(out, seg...)
			}

		}
		if err == io.EOF {
			break
		}
	}
	return out
}

func feedDecrypter(t *testing.T, dec CipherStream, data []byte) {
	t.Helper()
	pos := 0
	for pos < len(data) {
		chunkSize := min(len(data)-pos, 1500)
		chunk := data[pos : pos+chunkSize]
		pos += chunkSize
		if err := dec.WriteFrame(chunk); err != nil {
			t.Fatal("WriteBuffer:", err)
		}
	}
}

// ---- WriteBuffer + ReadFrame roundtrip for AEAD enc ----

func TestWriteBufferReadFrame_Encrypt_4KB(t *testing.T) {
	testEncryptRoundtrip(t, 4096)
}

func TestWriteBufferReadFrame_Encrypt_16KB(t *testing.T) {
	testEncryptRoundtrip(t, 16384)
}

func TestWriteBufferReadFrame_Encrypt_1B(t *testing.T) {
	testEncryptRoundtrip(t, 1)
}

func TestWriteBufferReadFrame_Encrypt_0B(t *testing.T) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	if err := enc.WriteFrame([]byte{}); err != nil {
		t.Fatal(err)
	}
	frames := drainEncrypted(t, enc)
	// 0-byte plaintext should produce some overhead (IV + possible empty frame)
	t.Logf("0-byte input produced %d bytes encrypted output", len(frames))
}

func testEncryptRoundtrip(t *testing.T, size int) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	dec, _ := NewDecrypter("aes-256-gcm", "test-password")

	plaintext := make([]byte, size)
	rand.Read(plaintext)

	// Encrypt
	if err := enc.WriteFrame(plaintext); err != nil {
		t.Fatal("WriteBuffer:", err)
	}
	wire := drainEncrypted(t, enc)

	// Decrypt
	feedDecrypter(t, dec, wire)
	recovered := drainDecrypted(t, dec)

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("size=%d: got %d bytes, want %d", size, len(recovered), len(plaintext))
	}
}

// ---- Multiple WriteBuffer calls, single ReadFrame drain ----

func TestWriteBufferReadFrame_MultipleWrites(t *testing.T) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	dec, _ := NewDecrypter("aes-256-gcm", "test-password")

	// Write in chunks
	for i := 0; i < 10; i++ {
		chunk := make([]byte, 512)
		rand.Read(chunk)
		if err := enc.WriteFrame(chunk); err != nil {
			t.Fatal("WriteBuffer:", err)
		}
	}

	wire := drainEncrypted(t, enc)
	feedDecrypter(t, dec, wire)
	recovered := drainDecrypted(t, dec)

	if len(recovered) != 5120 {
		t.Errorf("expected 5120 bytes, got %d", len(recovered))
	}
}

// ---- WriteBuffer with multi-segment Buffer ----

func TestWriteBufferReadFrame_MultiSegment(t *testing.T) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	dec, _ := NewDecrypter("aes-256-gcm", "test-password")

	b1 := []byte("hello ")
	b2 := []byte("world")
	merged := make([]byte, len(b1)+len(b2))
	copy(merged, b1)
	copy(merged[len(b1):], b2)

	if err := enc.WriteFrame(merged); err != nil {
		t.Fatal("WriteBuffer:", err)
	}

	wire := drainEncrypted(t, enc)
	feedDecrypter(t, dec, wire)
	recovered := drainDecrypted(t, dec)

	if string(recovered) != "hello world" {
		t.Errorf("got %q, want %q", recovered, "hello world")
	}
}

// ---- ReadFrame before any WriteBuffer (should return io.EOF) ----

func TestReadFrame_FreshEncrypterReturnsIV(t *testing.T) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	// A fresh encrypter writes the IV to its internal buffer immediately.
	// ReadFrame should return the IV.
	frame, err := enc.ReadFrame(nil)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame == nil {
		t.Fatal("expected frame with IV, got nil")
	}
	if len(frame) == 0 {
		t.Error("IV frame should not be empty")
	}
	t.Logf("IV frame: %d bytes", len(frame))

	// After draining IV, should get io.EOF (no more data)
	frame2, err := enc.ReadFrame(nil)
	if frame2 != nil {

		t.Error("expected nil after draining IV")
	}
	if err != io.EOF {
		t.Errorf("expected io.EOF after IV, got %v", err)
	}
}

// ---- Decrypter: ReadFrame with not enough data ----

func TestDecryptReadFrame_NotEnoughData(t *testing.T) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	dec, _ := NewDecrypter("aes-256-gcm", "test-password")

	enc.WriteFrame([]byte("hello"))
	wire := drainEncrypted(t, enc)

	// Feed IV (enough for AEAD init) but not enough for a complete frame
	ivLen := 32
	if err := dec.WriteFrame(wire[:ivLen]); err != nil {
		t.Fatal(err)
	}
	// Not enough for a full AEAD frame yet — should get io.EOF
	frame, err := dec.ReadFrame(nil)
	if frame != nil {

	}
	if err != io.EOF {
		t.Errorf("expected io.EOF with only IV, got %v", err)
	}

	// Feed the rest
	rest := wire[ivLen:]
	if err := dec.WriteFrame(rest); err != nil {
		t.Fatal(err)
	}
	frame, err = dec.ReadFrame(nil)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if frame == nil {
		t.Fatal("expected frame after feeding complete data")
	}
	if string([][]byte{frame}[0]) != "hello" {
		t.Errorf("got %q", [][]byte{frame}[0])
	}

}

// ---- PlainCipherStream ----

func TestPlainCipherStream_WriteBufferReadFrame(t *testing.T) {
	enc, _ := NewPlainEncrypter(nil, nil)
	dec, _ := NewPlainDecrypter(nil, 0)

	payload := []byte("plaintext-data")
	if err := enc.WriteFrame(payload); err != nil {
		t.Fatal(err)
	}
	wire := drainEncrypted(t, enc)
	if !bytes.Equal(wire, payload) {
		t.Errorf("plain enc: got %q, want %q", wire, payload)
	}

	if err := dec.WriteFrame(wire); err != nil {
		t.Fatal(err)
	}
	recovered := drainDecrypted(t, dec)
	if !bytes.Equal(recovered, payload) {
		t.Errorf("plain dec: got %q, want %q", recovered, payload)
	}
}

// ---- ReadFrame drain all frames from a multi-chunk encrypted stream ----

func TestWriteBufferReadFrame_MultiFrameDecrypt(t *testing.T) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	dec, _ := NewDecrypter("aes-256-gcm", "test-password")

	// Write multiple frames worth of data (each 1KB chunk = 1 AEAD frame)
	plaintext := make([]byte, 8192)
	rand.Read(plaintext)
	enc.WriteFrame(plaintext)
	wire := drainEncrypted(t, enc)

	// Feed wire in small chaotic chunks
	pos := 0
	for pos < len(wire) {
		chunkSize := min(len(wire)-pos, 1234) // uneven chunk
		dec.WriteFrame(wire[pos : pos+chunkSize])
		pos += chunkSize
	}

	recovered := drainDecrypted(t, dec)
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("got %d bytes, want %d", len(recovered), len(plaintext))
	}
}

// ---- WriteBuffer on enc then WriteBuffer on dec (direct hand-off) ----

func TestWriteBufferReadFrame_DirectHandoff(t *testing.T) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	dec, _ := NewDecrypter("aes-256-gcm", "test-password")

	plaintext := make([]byte, 4096)
	rand.Read(plaintext)

	enc.WriteFrame(plaintext)

	// Directly pass encrypted frames to decrypter
	frameCount := 0
	for {
		frame, err := enc.ReadFrame(nil)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if frame == nil {
			break
		}
		frameCount++
		dec.WriteFrame(frame) // transfers ownership
	}
	t.Logf("processed %d encrypted frames", frameCount)

	recovered := drainDecrypted(t, dec)
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("got %d bytes, want %d", len(recovered), len(plaintext))
	}
}

// ---- Multiple enc/dec pairs, same method ----

func TestWriteBufferReadFrame_Stress(t *testing.T) {
	methods := []string{"aes-256-gcm", "chacha20poly1305"}
	sizes := []int{1, 16, 257, 1024, 4096, 16384}

	for _, method := range methods {
		for _, size := range sizes {
			enc, _ := NewEncrypter(method, "test-password")
			dec, _ := NewDecrypter(method, "test-password")

			plaintext := make([]byte, size)
			rand.Read(plaintext)

			enc.WriteFrame(plaintext)
			wire := drainEncrypted(t, enc)
			feedDecrypter(t, dec, wire)
			recovered := drainDecrypted(t, dec)

			if !bytes.Equal(recovered, plaintext) {
				t.Errorf("%s size=%d: mismatch", method, size)
			}
		}
	}
}

// ---- Encrypt once, decrypt in multiple ReadFrame calls ----

func TestDecryptReadFrame_MultipleCalls(t *testing.T) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	dec, _ := NewDecrypter("aes-256-gcm", "test-password")

	plaintext := make([]byte, 16384)
	rand.Read(plaintext)
	enc.WriteFrame(plaintext)

	wire := drainEncrypted(t, enc)
	dec.WriteFrame(wire)

	// ReadFrame now decrypts all available chunks and returns them merged.
	frame, err := dec.ReadFrame(nil)
	if err != nil {
		t.Fatal(err)
	}

	recovered := [][]byte{frame}
	var all []byte
	for _, seg := range recovered {
		all = append(all, seg...)
	}
	if !bytes.Equal(all, plaintext) {
		t.Errorf("got %d bytes, want %d", len(all), len(plaintext))
	}
	t.Logf("16KB → %d segments in one ReadFrame", len(recovered))
}
