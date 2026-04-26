package ss

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

// FrameCodec encrypts/decrypts data on a per-connection basis.
type FrameCodec interface {
	ReadFrame(r io.Reader) ([]byte, error)
	WriteFrame(w io.Writer, plaintext []byte) error
	Overhead() int
	Close() error
}

// cipherStreamCodec implements FrameCodec using classic CipherStream (stream AEAD).
type cipherStreamCodec struct {
	enc crypto.CipherStream
	dec crypto.CipherStream
}

func newCipherStreamCodec(enc, dec crypto.CipherStream) *cipherStreamCodec {
	return &cipherStreamCodec{enc: enc, dec: dec}
}

func (c *cipherStreamCodec) ReadFrame(r io.Reader) ([]byte, error) {
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)

	for {
		nr, rerr := r.Read(buf)
		if rerr != nil {
			return nil, rerr
		}
		if _, err := c.dec.Write(buf[:nr]); err != nil {
			return nil, err
		}
		n, err := c.dec.Read(buf)
		if n > 0 {
			return append([]byte{}, buf[:n]...), nil
		}
		if err != nil && err != io.EOF {
			return nil, err
		}
	}
}

func (c *cipherStreamCodec) WriteFrame(w io.Writer, plaintext []byte) error {
	if _, err := c.enc.Write(plaintext); err != nil {
		return err
	}
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)

	var total int
	for total < len(plaintext)+c.Overhead() {
		n, err := c.enc.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return err
			}
			total += n
		}
		if err == io.EOF {
			break
		}
	}
	return nil
}

func (c *cipherStreamCodec) Overhead() int { return 0 }
func (c *cipherStreamCodec) Close() error  { return nil }

// aead2022Codec implements FrameCodec using the AEAD-2022 protocol.
type aead2022Codec struct {
	method      string
	psk         []byte
	readCipher  *crypto.TcpCipher2022
	writeCipher *crypto.TcpCipher2022

	// server handshake state
	svSalt  []byte
	cliSalt []byte

	// initial data from server handshake
	initBuf []byte

	rlbuf []byte
	rdbuf []byte
	wlbuf []byte
	wdbuf []byte
}

func newServerAead2022Codec(method string, psk, svSalt, cliSalt []byte, readCipher *crypto.TcpCipher2022) *aead2022Codec {
	return &aead2022Codec{
		method:     method,
		psk:        psk,
		readCipher: readCipher,
		svSalt:     svSalt,
		cliSalt:    cliSalt,
	}
}

func newClientAead2022Codec(method string, psk []byte, writeCipher *crypto.TcpCipher2022) *aead2022Codec {
	return &aead2022Codec{
		method:      method,
		psk:         psk,
		writeCipher: writeCipher,
	}
}

func (c *aead2022Codec) ReadFrame(r io.Reader) ([]byte, error) {
	if c.readCipher == nil {
		if err := c.doServerHandshake(r); err != nil {
			return nil, err
		}
	}
	if len(c.initBuf) > 0 {
		data := c.initBuf
		c.initBuf = nil
		return data, nil
	}

	lbLen := 2 + c.readCipher.Overhead()
	if cap(c.rlbuf) < lbLen {
		c.rlbuf = make([]byte, lbLen)
	}
	lb := c.rlbuf[:lbLen]
	if _, err := io.ReadFull(r, lb); err != nil {
		return nil, err
	}
	lb, ok := c.readCipher.DecryptPacket(lb)
	if !ok {
		return nil, fmt.Errorf("decrypt length failed")
	}
	length := int(uint16(lb[0])<<8 | uint16(lb[1]))

	dataLen := length + c.readCipher.Overhead()
	if cap(c.rdbuf) < dataLen {
		c.rdbuf = make([]byte, dataLen)
	}
	data := c.rdbuf[:dataLen]
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	data, ok = c.readCipher.DecryptPacket(data)
	if !ok {
		return nil, fmt.Errorf("decrypt data failed")
	}
	return append([]byte{}, data[:length]...), nil
}

func (c *aead2022Codec) WriteFrame(w io.Writer, plaintext []byte) error {
	if c.svSalt != nil {
		chunk := plaintext
		if len(chunk) > 0xFFFF {
			chunk = chunk[:0xFFFF]
		}
		svCiph, err := crypto.NewTcpCipher2022(c.method, c.psk, c.svSalt)
		if err != nil {
			return err
		}
		svHdr := make([]byte, 1+8+len(c.cliSalt)+2)
		svHdr[0] = aead2022ServerType
		PutUint64Timestamp(svHdr[1:9])
		copy(svHdr[9:9+len(c.cliSalt)], c.cliSalt)
		PutUint16BE(svHdr[9+len(c.cliSalt):11+len(c.cliSalt)], uint16(len(chunk)))
		svHdr = svCiph.EncryptPacket(svHdr)

		data := make([]byte, len(chunk), len(chunk)+svCiph.Overhead())
		copy(data, chunk)
		data = svCiph.EncryptPacket(data)

		resp := make([]byte, len(c.svSalt)+len(svHdr)+len(data))
		copy(resp, c.svSalt)
		copy(resp[len(c.svSalt):], svHdr)
		copy(resp[len(c.svSalt)+len(svHdr):], data)
		if _, err := w.Write(resp); err != nil {
			return err
		}
		c.writeCipher = svCiph
		c.svSalt = nil
		c.cliSalt = nil
		return nil
	}

	chunk := plaintext
	if len(chunk) > 0xFFFF {
		chunk = chunk[:0xFFFF]
	}
	overhead := c.writeCipher.Overhead()
	lbLen := 2 + overhead
	if cap(c.wlbuf) < lbLen {
		c.wlbuf = make([]byte, lbLen)
	}
	lb := c.wlbuf[:2:lbLen]
	PutUint16BE(lb[:2], uint16(len(chunk)))
	lb = c.writeCipher.EncryptPacket(lb)

	dataLen := len(chunk) + overhead
	if cap(c.wdbuf) < dataLen {
		c.wdbuf = make([]byte, dataLen)
	}
	data := c.wdbuf[:len(chunk):dataLen]
	copy(data, chunk)
	data = c.writeCipher.EncryptPacket(data)

	_, err := w.Write(append(lb, data...))
	return err
}

func (c *aead2022Codec) doServerHandshake(r io.Reader) error {
	svSalt := make([]byte, len(c.psk))
	if _, err := io.ReadFull(r, svSalt); err != nil {
		return err
	}
	svCiph, err := crypto.NewTcpCipher2022(c.method, c.psk, svSalt)
	if err != nil {
		return err
	}
	hdrLen := 1 + 8 + len(c.psk) + 2 + svCiph.Overhead()
	svBuf := make([]byte, hdrLen)
	if _, err := io.ReadFull(r, svBuf); err != nil {
		return err
	}
	svBuf, ok := svCiph.DecryptPacket(svBuf)
	if !ok {
		return fmt.Errorf("decrypt server header failed")
	}
	if svBuf[0] != aead2022ServerType {
		return fmt.Errorf("unexpected server stream type: %d", svBuf[0])
	}
	dataLen := int(uint16(svBuf[1+8+len(c.psk)])<<8 | uint16(svBuf[1+8+len(c.psk)+1]))
	if dataLen > 0 {
		dataBuf := make([]byte, dataLen+svCiph.Overhead())
		if _, err := io.ReadFull(r, dataBuf); err != nil {
			return err
		}
		dataBuf, ok = svCiph.DecryptPacket(dataBuf)
		if !ok {
			return fmt.Errorf("decrypt initial server data failed")
		}
		c.initBuf = append([]byte{}, dataBuf[:dataLen]...)
	}
	c.readCipher = svCiph
	return nil
}

func (c *aead2022Codec) Overhead() int {
	if c.writeCipher != nil {
		return c.writeCipher.Overhead()
	}
	return 16 // default AES-GCM overhead
}

func (c *aead2022Codec) Close() error { return nil }

func PutUint16BE(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func PutUint64Timestamp(b []byte) {
	now := uint64(time.Now().Unix())
	b[0] = byte(now >> 56)
	b[1] = byte(now >> 48)
	b[2] = byte(now >> 40)
	b[3] = byte(now >> 32)
	b[4] = byte(now >> 24)
	b[5] = byte(now >> 16)
	b[6] = byte(now >> 8)
	b[7] = byte(now)
}

// CryptoConn wraps a raw Conn with a FrameCodec for encryption/decryption.
type CryptoConn struct {
	Conn
	codec      FrameCodec
	buf        []byte // leftover plaintext from last read
	rlbuf      []byte
	rdbuf      []byte
	wlbuf      []byte
	wdbuf      []byte
	deferClose bool
}

func newCryptoConn(conn Conn, codec FrameCodec) *CryptoConn {
	return &CryptoConn{Conn: conn, codec: codec}
}

func (c *CryptoConn) Unwrap() net.Conn { return c.Conn }

func (c *CryptoConn) Close() error {
	if c.deferClose {
		go func() {
			time.Sleep(time.Duration(rand.Int()%64+8) * time.Second)
			c.Conn.Close()
		}()
		return nil
	}
	return c.Conn.Close()
}

func (c *CryptoConn) DeferClose()       { c.deferClose = true }
func (c *CryptoConn) CancelDeferClose() { c.deferClose = false }

func (c *CryptoConn) Read(b []byte) (n int, err error) {
	if len(c.buf) > 0 {
		n = copy(b, c.buf)
		c.buf = c.buf[n:]
		if len(c.buf) == 0 {
			c.buf = nil
		}
		return n, nil
	}

	plain, err := c.codec.ReadFrame(c.Conn)
	if err != nil {
		return 0, err
	}
	n = copy(b, plain)
	if n < len(plain) {
		c.buf = plain[n:]
	}
	return n, nil
}

func (c *CryptoConn) Write(b []byte) (n int, err error) {
	return c.WriteBuffers([][]byte{b})
}

func (c *CryptoConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	for _, b := range bufs {
		if err = c.codec.WriteFrame(c.Conn, b); err != nil {
			return
		}
		n += len(b)
	}
	return
}
