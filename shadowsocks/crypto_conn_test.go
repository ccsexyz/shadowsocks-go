package ss

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/ccsexyz/shadowsocks-go/crypto"
)

// eofWithDataReader returns all remaining data plus io.EOF in a single
// Read call. This mimics the Go io.Reader contract: "Callers should
// always process the n > 0 bytes returned before considering the error."
// Real TCP connections produce this when data and FIN arrive together.
type eofWithDataReader struct {
	data []byte
	pos  int
}

func (r *eofWithDataReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, io.EOF
}

func createStreamCipherPair(t *testing.T) (enc, dec crypto.CipherStream) {
	t.Helper()
	var err error
	enc, err = crypto.NewEncrypter("aes-256-gcm", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	dec, err = crypto.NewDecrypter("aes-256-gcm", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	return
}

// drainReadFrame calls ReadFrame in a loop until EOF, collecting all data.
func drainReadFrame(codec *cipherStreamCodec, r io.Reader) ([]byte, error) {
	var result []byte
	for {
		data, err := codec.ReadFrame(r)
		if len(data) > 0 {
			result = append(result, data...)
		}
		if err != nil {
			return result, err
		}
	}
}

// ======================== WriteFrame tests ========================

func TestWriteFrame_DrainsAllOverhead(t *testing.T) {
	enc, _ := createStreamCipherPair(t)
	codec := newCipherStreamCodec(enc, nil)

	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := codec.WriteFrame(&buf, plaintext); err != nil {
		t.Fatal(err)
	}

	if buf.Len() <= len(plaintext) {
		t.Errorf("WriteFrame wrote %d bytes <= plaintext %d — overhead not flushed!",
			buf.Len(), len(plaintext))
	}
	t.Logf("plaintext=%d, encrypted=%d, overhead=%d", len(plaintext), buf.Len(), buf.Len()-len(plaintext))
}

func TestWriteFrame_ManySizes(t *testing.T) {
	sizes := []int{1, 16, 257, 512, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 8192, 10000}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			enc, _ := createStreamCipherPair(t)
			codec := newCipherStreamCodec(enc, nil)
			plaintext := make([]byte, size)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := codec.WriteFrame(&buf, plaintext); err != nil {
				t.Fatal(err)
			}
			if buf.Len() <= size {
				t.Errorf("size=%d: wrote %d bytes <= plaintext, overhead missing", size, buf.Len())
			}
		})
	}
}

// ======================== ReadFrame tests ========================

func TestReadFrame_DataWithEOF(t *testing.T) {
	enc, dec := createStreamCipherPair(t)
	codec := newCipherStreamCodec(enc, dec)
	plaintext := []byte("hello, this is test data that must survive EOF in the same Read call")

	var encBuf bytes.Buffer
	if err := codec.WriteFrame(&encBuf, plaintext); err != nil {
		t.Fatal(err)
	}

	reader := &eofWithDataReader{data: encBuf.Bytes()}
	result, err := codec.ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame returned error on data+EOF: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("data mismatch: got %d bytes, want %d bytes", len(result), len(plaintext))
	}
}

func TestReadFrame_CleanEOF(t *testing.T) {
	_, dec := createStreamCipherPair(t)
	codec := newCipherStreamCodec(nil, dec)
	_, err := codec.ReadFrame(&eofWithDataReader{})
	// Empty reader returns 0,io.EOF — no IV ever written to decrypter.
	// The decrypter's AEAD is nil, so ReadFrame returns "AEAD is nil".
	// This is correct: the connection closed before the SS handshake.
	if err == nil || err == io.EOF {
		t.Errorf("expected 'AEAD is nil' error, got %v", err)
	}
}

// ======================== Full roundtrip tests ========================
// These use drainReadFrame which loops ReadFrame, correctly handling
// the fact that ReadFrame returns data in buffer-sized chunks.

func TestRoundtrip_Streaming(t *testing.T) {
	enc, dec := createStreamCipherPair(t)
	writeCodec := newCipherStreamCodec(enc, nil)
	readCodec := newCipherStreamCodec(nil, dec)

	var buf bytes.Buffer
	var original, recovered []byte

	for i := range 100 {
		size := (i*73)%2048 + 64
		frame := make([]byte, size)
		if _, err := rand.Read(frame); err != nil {
			t.Fatal(err)
		}
		original = append(original, frame...)
		if err := writeCodec.WriteFrame(&buf, frame); err != nil {
			t.Fatalf("WriteFrame at i=%d (size=%d): %v", i, size, err)
		}
	}

	var err error
	recovered, err = drainReadFrame(readCodec, &buf)
	if err != io.EOF {
		t.Fatalf("drainReadFrame: expected io.EOF, got %v (recovered %d/%d)", err, len(recovered), len(original))
	}
	if !bytes.Equal(recovered, original) {
		t.Errorf("mismatch: got %d bytes, want %d", len(recovered), len(original))
	}
}

func TestRoundtrip_SingleFrameLargeData(t *testing.T) {
	enc, dec := createStreamCipherPair(t)
	writeCodec := newCipherStreamCodec(enc, nil)
	readCodec := newCipherStreamCodec(nil, dec)

	// 128KB single frame
	plaintext := make([]byte, 131072)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	var encBuf bytes.Buffer
	if err := writeCodec.WriteFrame(&encBuf, plaintext); err != nil {
		t.Fatal(err)
	}
	if encBuf.Len() <= len(plaintext) {
		t.Fatalf("WriteFrame: %d <= %d — data loss", encBuf.Len(), len(plaintext))
	}

	encryptedSize := encBuf.Len()
	result, err := drainReadFrame(readCodec, &encBuf)
	if err != io.EOF {
		t.Fatalf("drainReadFrame: expected io.EOF, got %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("mismatch: got %d bytes, want %d", len(result), len(plaintext))
	}
	t.Logf("128KB roundtrip: encrypted=%d, plaintext=%d, OK", encryptedSize, len(plaintext))
}

func TestRoundtrip_1MB(t *testing.T) {
	enc, dec := createStreamCipherPair(t)
	writeCodec := newCipherStreamCodec(enc, nil)
	readCodec := newCipherStreamCodec(nil, dec)

	plaintext := make([]byte, 1024*1024) // 1 MB
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	var encBuf bytes.Buffer
	if err := writeCodec.WriteFrame(&encBuf, plaintext); err != nil {
		t.Fatal(err)
	}
	if encBuf.Len() <= len(plaintext) {
		t.Fatalf("WriteFrame: %d <= %d — data loss", encBuf.Len(), len(plaintext))
	}

	encryptedSize := encBuf.Len()
	result, err := drainReadFrame(readCodec, &encBuf)
	if err != io.EOF {
		t.Fatalf("drainReadFrame: expected io.EOF, got %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("mismatch: got %d bytes, want %d", len(result), len(plaintext))
	}
	t.Logf("1MB roundtrip: encrypted=%d, plaintext=%d, overhead=%d — OK",
		encryptedSize, len(plaintext), encryptedSize-len(plaintext))
}

// ==================== Old WriteFrame bug reproduction ====================

func TestOldWriteFrameBug_Reproduction(t *testing.T) {
	enc, _ := createStreamCipherPair(t)
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	// Simulate OLD WriteFrame: total < len(plaintext) + c.Overhead() [Overhead() returns 0]
	// Use a small read buffer to force the encrypt stream to return data in
	// multiple calls, which triggers the under-counting bug.
	oldWriteFrame := func(w io.Writer, pt []byte) error {
		if _, err := enc.Write(pt); err != nil {
			return err
		}
		smallBuf := make([]byte, 256) // force multiple reads from encrypt stream
		var total int
		for total < len(pt) {
			n, err := enc.Read(smallBuf)
			if n > 0 {
				if _, werr := w.Write(smallBuf[:n]); werr != nil {
					return werr
				}
				total += n
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
		}
		return nil
	}

	var oldBuf bytes.Buffer
	if err := oldWriteFrame(&oldBuf, plaintext); err != nil {
		t.Fatal(err)
	}

	oldEncrypted := oldBuf.Len()
	if oldEncrypted >= 4264 {
		t.Skipf("old bug not triggered — bytes.Buffer coalesced reads (wrote %d)", oldEncrypted)
	}

	// Old output should be truncated — overhead bytes were lost.
	_, dec := createStreamCipherPair(t)
	readCodec := newCipherStreamCodec(nil, dec)
	recovered, err := drainReadFrame(readCodec, &oldBuf)

	if err == io.EOF && bytes.Equal(recovered, plaintext) {
		t.Error("OLD WriteFrame unexpectedly roundtripped correctly — the bug did not manifest")
	} else {
		t.Logf("OLD WriteFrame bug confirmed: wrote %d bytes for %d bytes plaintext (recovered %d)",
			oldEncrypted, len(plaintext), len(recovered))
	}

	// NEW WriteFrame drains until io.EOF — full roundtrip must succeed.
	enc2, dec2 := createStreamCipherPair(t)
	newCodec := newCipherStreamCodec(enc2, dec2)
	var newBuf bytes.Buffer
	if err := newCodec.WriteFrame(&newBuf, plaintext); err != nil {
		t.Fatal(err)
	}
	newEncrypted := newBuf.Len()
	result, err := drainReadFrame(newCodec, &newBuf)
	if err != io.EOF {
		t.Fatalf("NEW roundtrip failed: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Error("NEW roundtrip data mismatch")
	}
	t.Logf("NEW: %d plaintext → %d encrypted → %d decrypted OK",
		len(plaintext), newEncrypted, len(result))
}
