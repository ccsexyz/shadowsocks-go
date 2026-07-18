package ss

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"net"
	"sync"
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

// TestCryptoConn2022_ServerHandshakeRace verifies that concurrent Write calls
// during the server handshake do not cause double-handshake or data corruption.
// Run with: go test -race -run TestCryptoConn2022_ServerHandshakeRace
func TestCryptoConn2022_ServerHandshakeRace(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	method := "2022-blake3-aes-256-gcm"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawClient, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		defer rawClient.Close()

		salt := make([]byte, 32)
		for i := range salt {
			salt[i] = byte(i)
		}
		ciph, _ := crypto.NewTcpCipher2022(method, psk, salt)
		addr := &SockAddr{Hdr: []byte{1, 127, 0, 0, 1, 0, 80}}
		header := buildAead2022Header(ciph, salt, addr, nil)
		rawClient.Write(header)

		clientAead := newClientCryptoConn2022(newBaseConn(rawClient, nil), method, psk, ciph)
		defer clientAead.Close()

		// Read handshake + 2 data writes from server
		buf := make([]byte, 4096)
		total := 0
		for total < 20 {
			n, err := ReadN(clientAead, buf[total:], nil)
			if err != nil {
				t.Logf("client read done after %d bytes: %v", total, err)
				return
			}
			total += n
		}
		t.Logf("client received %d bytes total", total)
	}()

	// Server side
	rawServer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer rawServer.Close()

	cliSalt := make([]byte, 32)
	io.ReadFull(rawServer, cliSalt)
	serverCiph, _ := crypto.NewTcpCipher2022(method, psk, cliSalt)
	hdr1Len := 1 + 8 + 2 + serverCiph.Overhead()
	hdr1 := make([]byte, hdr1Len)
	io.ReadFull(rawServer, hdr1)
	serverCiph.DecryptPacket(hdr1)
	addrLen := int(uint16(hdr1[9])<<8 | uint16(hdr1[10]))
	hdr2Len := addrLen + serverCiph.Overhead()
	hdr2 := make([]byte, hdr2Len)
	io.ReadFull(rawServer, hdr2)
	serverCiph.DecryptPacket(hdr2)

	svSalt := make([]byte, 32)
	sConn := newServerCryptoConn2022(newBaseConn(rawServer, nil), method, psk, svSalt, cliSalt, serverCiph)
	defer sConn.Close()

	// Concurrent writes to trigger the handshake race.
	var wg2 sync.WaitGroup
	errCh := make(chan error, 2)
	wg2.Add(2)
	go func() {
		defer wg2.Done()
		_, err := sConn.Write([]byte("goroutine-1-data"))
		errCh <- err
	}()
	go func() {
		defer wg2.Done()
		_, err := sConn.Write([]byte("goroutine-2-data"))
		errCh <- err
	}()
	wg2.Wait()
	close(errCh)

	for e := range errCh {
		if e != nil {
			t.Errorf("concurrent write error: %v", e)
		}
	}
	wg.Wait()
}
