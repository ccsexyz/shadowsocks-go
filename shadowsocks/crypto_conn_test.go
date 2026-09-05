package ss

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
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

		clientAead := newClientCryptoConn2022(newBaseConn(rawClient, nil), method, psk, salt, ciph)
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

// craft2022ServerResponse builds a server response (salt + encrypted fixed
// header) with caller-controlled timestamp and echoed salt, for testing the
// client handshake validation.
func craft2022ServerResponse(t *testing.T, method string, psk, svSalt, cliSalt []byte, ts int64, dataLen int) ([]byte, *crypto.TcpCipher2022) {
	t.Helper()
	svCiph, err := crypto.NewTcpCipher2022(method, psk, svSalt)
	if err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 1+8+len(cliSalt)+2)
	hdr[0] = aead2022ServerType
	binary.BigEndian.PutUint64(hdr[1:9], uint64(ts))
	copy(hdr[9:9+len(cliSalt)], cliSalt)
	binary.BigEndian.PutUint16(hdr[9+len(cliSalt):11+len(cliSalt)], uint16(dataLen))
	out := append([]byte{}, svSalt...)
	out = append(out, svCiph.EncryptPacket(hdr)...)
	return out, svCiph
}

// read2022ClientRequest consumes the client's salt and both encrypted header
// frames from rawServer and returns the client salt.
func read2022ClientRequest(rawServer net.Conn, method string, psk []byte) (cliSalt []byte, err error) {
	buf := make([]byte, 4096)
	if _, err = io.ReadFull(rawServer, buf[:len(psk)]); err != nil {
		return
	}
	cliSalt = append([]byte{}, buf[:len(psk)]...)
	ciph, err := crypto.NewTcpCipher2022(method, psk, cliSalt)
	if err != nil {
		return
	}
	hdr1Len := 1 + 8 + 2 + ciph.Overhead()
	if _, err = io.ReadFull(rawServer, buf[:hdr1Len]); err != nil {
		return
	}
	hdr1, ok := ciph.DecryptPacket(append([]byte{}, buf[:hdr1Len]...))
	if !ok {
		err = io.ErrUnexpectedEOF
		return
	}
	hdr2Len := int(binary.BigEndian.Uint16(hdr1[9:11])) + ciph.Overhead()
	_, err = io.ReadFull(rawServer, buf[:hdr2Len])
	return
}

// start2022ServerHandshake reads the client request header from rawServer and
// writes the given response bytes. It reports problems via the returned error
// so it can run on a goroutine synchronized by the caller.
func start2022ServerHandshake(rawServer net.Conn, method string, psk []byte, response []byte) error {
	if _, err := read2022ClientRequest(rawServer, method, psk); err != nil {
		return err
	}
	_, err := rawServer.Write(response)
	return err
}

func new2022TestPair(t *testing.T, method string, psk []byte) (client *cryptoConn2022, rawServer net.Conn, salt []byte, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rawServer, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	salt = utils.GetRandomBytes(len(psk))
	ciph, err := crypto.NewTcpCipher2022(method, psk, salt)
	if err != nil {
		t.Fatal(err)
	}
	header := buildAead2022Header(ciph, salt, &SockAddr{Hdr: []byte{1, 127, 0, 0, 1, 0, 80}}, nil)
	if _, err := rawClient.Write(header); err != nil {
		t.Fatal(err)
	}
	client = newClientCryptoConn2022(newBaseConn(rawClient, nil), method, psk, salt, ciph)
	return client, rawServer, salt, func() {
		client.Close()
		rawServer.Close()
		ln.Close()
	}
}

const test2022Method = "2022-blake3-aes-256-gcm"

// TestCryptoConn2022_ZeroLengthFrameSkipped verifies that a zero-length
// payload chunk is skipped (matching shadowsocks-rust) instead of aborting
// the stream.
func TestCryptoConn2022_ZeroLengthFrameSkipped(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	client, rawServer, salt, cleanup := new2022TestPair(t, test2022Method, psk)
	defer cleanup()

	// Response header (no bundled data), then a zero-length frame, then a
	// normal frame. All frames share one cipher instance so the nonce
	// counter stays consistent with the client's.
	resp, svCiph := craft2022ServerResponse(t, test2022Method, psk, utils.GetRandomBytes(len(psk)), salt, time.Now().Unix(), 0)
	stream := append([]byte{}, resp...)
	stream = append(stream, svCiph.EncryptPacket([]byte{0, 0})...)
	stream = append(stream, svCiph.EncryptPacket([]byte{0, 2})...)
	stream = append(stream, svCiph.EncryptPacket([]byte("hi"))...)

	go func() {
		start2022ServerHandshake(rawServer, test2022Method, psk, stream)
	}()

	buf := make([]byte, 64)
	segs, err := client.Read(buf, nil)
	if err != nil {
		t.Fatalf("read after zero-length frame: %v", err)
	}
	if string(segs[0]) != "hi" {
		t.Fatalf("payload mismatch: %q", segs[0])
	}
}

// TestCryptoConn2022_ClientHandshakeRejectsBadSalt verifies the client
// rejects a server response whose request-salt echo does not match (SIP022).
func TestCryptoConn2022_ClientHandshakeRejectsBadSalt(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	client, rawServer, _, cleanup := new2022TestPair(t, test2022Method, psk)
	defer cleanup()

	done := make(chan struct{})
	resp, _ := craft2022ServerResponse(t, test2022Method, psk, utils.GetRandomBytes(len(psk)), []byte("WRONG-SALT-WRONG-SALT-WRONG-SALT"), time.Now().Unix(), 0)
	go func() {
		defer close(done)
		start2022ServerHandshake(rawServer, test2022Method, psk, resp)
	}()

	buf := make([]byte, 64)
	_, err := client.Read(buf, nil)
	<-done
	if err == nil {
		t.Fatal("handshake with unmatched salt must fail")
	}
}

// TestCryptoConn2022_ClientHandshakeRejectsStaleTimestamp verifies the client
// rejects a server response older than 30 seconds (SIP022).
func TestCryptoConn2022_ClientHandshakeRejectsStaleTimestamp(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	client, rawServer, salt, cleanup := new2022TestPair(t, test2022Method, psk)
	defer cleanup()

	done := make(chan struct{})
	resp, _ := craft2022ServerResponse(t, test2022Method, psk, utils.GetRandomBytes(len(psk)), salt, time.Now().Unix()-120, 0)
	go func() {
		defer close(done)
		start2022ServerHandshake(rawServer, test2022Method, psk, resp)
	}()

	buf := make([]byte, 64)
	_, err := client.Read(buf, nil)
	<-done
	if err == nil {
		t.Fatal("handshake with stale timestamp must fail")
	}
}

// TestCryptoConn2022_ClientHandshakeAcceptsValidResponse is the positive
// counterpart: a well-formed response validates and the stream works.
func TestCryptoConn2022_ClientHandshakeAcceptsValidResponse(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	client, rawServer, salt, cleanup := new2022TestPair(t, test2022Method, psk)
	defer cleanup()

	payload := []byte("server hello")
	// Response header bundled with data, encrypted with a cipher derived
	// from the server's own response salt.
	resp, svCiph := craft2022ServerResponse(t, test2022Method, psk, utils.GetRandomBytes(len(psk)), salt, time.Now().Unix(), len(payload))
	stream := append(append([]byte{}, resp...), svCiph.EncryptPacket(payload)...)

	go func() {
		start2022ServerHandshake(rawServer, test2022Method, psk, stream)
	}()

	buf := make([]byte, 64)
	segs, err := client.Read(buf, nil)
	if err != nil {
		t.Fatalf("valid handshake rejected: %v", err)
	}
	if string(segs[0]) != string(payload) {
		t.Fatalf("payload mismatch: %q", segs[0])
	}
}

// TestSS2022DialCapsBundledPayload pins that the initial payload bundled
// into the 2022 request header respects the 0x3FFF frame cap and the
// remainder is sent as regular chunked frames.
func TestSS2022DialCapsBundledPayload(t *testing.T) {
	psk := utils.GetRandomBytes(32)
	cfg := &Config{CryptoConfig: CryptoConfig{Method: test2022Method, Password: base64.StdEncoding.EncodeToString(psk)}}
	CheckConfig(cfg)

	payload := tlsObfsPayload // 65568 bytes, well past 0x3FFF

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type dialResult struct {
		conn Conn
		err  error
	}
	conch := make(chan dialResult, 1)
	go func() {
		raw, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			conch <- dialResult{err: derr}
			return
		}
		defer raw.Close()
		opt := &DialOptions{Target: "example.com:443", C: cfg, Data: payload}
		conn, derr := ss2022DialWithConn(AsNetConn(raw), opt)
		conch <- dialResult{conn: conn, err: derr}
	}()

	rawSrv, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer rawSrv.Close()

	buf := make([]byte, 66000)
	if _, err := io.ReadFull(rawSrv, buf[:32]); err != nil {
		t.Fatal(err)
	}
	cliSalt := append([]byte{}, buf[:32]...)
	ciph, err := crypto.NewTcpCipher2022(test2022Method, psk, cliSalt)
	if err != nil {
		t.Fatal(err)
	}
	oh := ciph.Overhead()

	// hdr1: verify the bundled length respects the cap.
	hdr1Len := 1 + 8 + 2 + oh
	if _, err := io.ReadFull(rawSrv, buf[:hdr1Len]); err != nil {
		t.Fatal(err)
	}
	hdr1 := append([]byte{}, buf[:hdr1Len]...)
	hdr1, ok := ciph.DecryptPacket(hdr1)
	if !ok {
		t.Fatal("hdr1 decrypt failed")
	}
	if hdr1[0] != aead2022ClientType {
		t.Fatalf("type = %d", hdr1[0])
	}
	addrLen := int(binary.BigEndian.Uint16(hdr1[9:11]))
	if addrLen > 0x3FFF {
		t.Fatalf("request header addrLen = %d, exceeds the 0x3FFF cap", addrLen)
	}

	// hdr2: addr + padding + bundled payload.
	hdr2Len := addrLen + oh
	if _, err := io.ReadFull(rawSrv, buf[:hdr2Len]); err != nil {
		t.Fatal(err)
	}
	hdr2 := append([]byte{}, buf[:hdr2Len]...)
	hdr2, ok = ciph.DecryptPacket(hdr2)
	if !ok {
		t.Fatal("hdr2 decrypt failed")
	}
	_, rest, err := ParseAddr(hdr2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) < 2 {
		t.Fatal("hdr2 too short for padding length")
	}
	padSize := int(binary.BigEndian.Uint16(rest[:2]))
	bundled := rest[2+padSize:]

	// Server response completing the client handshake.
	svSalt := utils.GetRandomBytes(32)
	resp, _ := craft2022ServerResponse(t, test2022Method, psk, svSalt, cliSalt, time.Now().Unix(), 0)
	if _, err := rawSrv.Write(resp); err != nil {
		t.Fatal(err)
	}

	// Chunked remainder: decrypt frames with the client-direction cipher,
	// which continues its counter after hdr1/hdr2.
	received := append([]byte{}, bundled...)
	for len(received) < len(payload) {
		if _, err := io.ReadFull(rawSrv, buf[:2+oh]); err != nil {
			t.Fatal(err)
		}
		lb := append([]byte{}, buf[:2+oh]...)
		lb, ok = ciph.DecryptPacket(lb)
		if !ok {
			t.Fatal("length tag decrypt failed")
		}
		chunkLen := int(binary.BigEndian.Uint16(lb[:2]))
		if chunkLen > 0x3FFF {
			t.Fatalf("chunk length %d exceeds the 0x3FFF cap", chunkLen)
		}
		if _, err := io.ReadFull(rawSrv, buf[:chunkLen+oh]); err != nil {
			t.Fatal(err)
		}
		seg := append([]byte{}, buf[:chunkLen+oh]...)
		seg, ok = ciph.DecryptPacket(seg)
		if !ok {
			t.Fatal("chunk decrypt failed")
		}
		received = append(received, seg...)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("payload corrupted across header bundle + chunked remainder")
	}

	res := <-conch
	if res.err != nil {
		t.Fatal(res.err)
	}
	res.conn.Close()
}
