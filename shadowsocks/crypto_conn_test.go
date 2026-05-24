package ss

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/ccsexyz/shadowsocks-go/crypto"
)

// eofWithDataReader returns all remaining data plus io.EOF in a single Read call.
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

// ======================== Write tests ========================

func TestCryptoConnStream_Write(t *testing.T) {
	enc, _ := createStreamCipherPair(t)

	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	mc := newMockConn()
	cc := newCryptoConnStream(newBaseConn(mc, nil), enc, nil)

	if _, err := cc.Write(plaintext); err != nil {
		t.Fatal(err)
	}

	written := mc.getWritten()
	if len(written) <= len(plaintext) {
		t.Errorf("Write wrote %d bytes <= plaintext %d — overhead not flushed!",
			len(written), len(plaintext))
	}
	t.Logf("plaintext=%d, encrypted=%d, overhead=%d", len(plaintext), len(written), len(written)-len(plaintext))
}

func TestCryptoConnStream_Write_manySizes(t *testing.T) {
	sizes := []int{1, 16, 257, 512, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 8192, 10000}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			enc, _ := createStreamCipherPair(t)
			plaintext := make([]byte, size)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatal(err)
			}
			mc := newMockConn()
			cc := newCryptoConnStream(newBaseConn(mc, nil), enc, nil)
			if _, err := cc.Write(plaintext); err != nil {
				t.Fatal(err)
			}
			written := mc.getWritten()
			if len(written) <= size {
				t.Errorf("size=%d: wrote %d bytes <= plaintext, overhead missing", size, len(written))
			}
		})
	}
}

// ======================== Read tests ========================

func TestCryptoConnStream_Read_roundtrip(t *testing.T) {
	enc, dec := createStreamCipherPair(t)
	plaintext := []byte("hello, this is test data")

	// Encrypt via Write
	mcEnc := newMockConn()
	ccEnc := newCryptoConnStream(newBaseConn(mcEnc, nil), enc, nil)
	if _, err := ccEnc.Write(plaintext); err != nil {
		t.Fatal(err)
	}

	// Decrypt via Read: feed encrypted data to a mock conn, read back
	mcDec := newMockConn()
	mcDec.setReadData(mcEnc.getWritten())
	ccDec := newCryptoConnStream(newBaseConn(mcDec, nil), nil, dec)

	buf := make([]byte, 65536)
	segs, err := ccDec.Read(buf, nil)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	result := make([]byte, 0)
	for _, s := range segs {
		result = append(result, s...)
	}
	if !bytes.Equal(result, plaintext) {
		t.Errorf("roundtrip mismatch: got %d bytes, want %d bytes", len(result), len(plaintext))
	}
}
