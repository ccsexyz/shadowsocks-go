package ss

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

// cryptoConnStream implements Conn with direct stream cipher encryption/decryption.
// It eliminates the FrameCodec abstraction by handling the read/write loops inline.
type cryptoConnStream struct {
	Conn
	enc        crypto.CipherStream
	dec        crypto.CipherStream
	deferClose bool
	rr         io.Reader // persistent reader for inner conn, lazy-init in Read
}

func newCryptoConnStream(conn Conn, enc, dec crypto.CipherStream) *cryptoConnStream {
	return &cryptoConnStream{Conn: conn, enc: enc, dec: dec}
}

func (c *cryptoConnStream) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	if c.rr == nil {
		c.rr = AsReader(c.Conn, nil)
	}
	r := c.rr
	for {
		frame, err := c.dec.ReadFrame(buf)
		if frame != nil {
			// Fast path: ReadFrame reused buf as output.
			// The data is already in buf — return directly without copy.
			if len(frame) > 0 && len(buf) > 0 && &frame[0] == &buf[0] {
				return [][]byte{buf[:len(frame)]}, nil
			}
			if cap(buf) >= len(frame) {
				n := copy(buf, frame)
				return [][]byte{buf[:n]}, nil
			}
			return [][]byte{frame}, nil
		}
		if err != nil && err != io.EOF {
			return nil, err
		}
		nr, rerr := r.Read(buf)
		if nr > 0 {
			if werr := c.dec.WriteFrame(buf[:nr]); werr != nil {
				return nil, werr
			}
		}
		if rerr != nil {
			frame, err := c.dec.ReadFrame(buf)
			if frame != nil {
				if len(frame) > 0 && len(buf) > 0 && &frame[0] == &buf[0] {
					return [][]byte{buf[:len(frame)]}, nil
				}
				if cap(buf) >= len(frame) {
					n := copy(buf, frame)
					return [][]byte{buf[:n]}, nil
				}
				return [][]byte{frame}, nil
			}
			if err == nil || err == io.EOF {
				return nil, rerr
			}
			return nil, err
		}
	}
}

func (c *cryptoConnStream) Write(bufs ...[]byte) (n int, err error) {
	for _, b := range bufs {
		n += len(b)
	}
	plaintext := flatten(bufs)
	if err := c.enc.WriteFrame(plaintext); err != nil {
		return n, err
	}
	w := AsReadWriteCloser(c.Conn, nil)
	_, err = c.enc.WriteEncryptedTo(w)
	return n, err
}

// cryptoConn2022 implements Conn with direct AEAD-2022 frame encryption/decryption.
// Unlike stream ciphers, AEAD-2022 frames are self-contained packets:
// [encrypted 2-byte length tag] [encrypted payload]. Each frame is read
// directly from the underlying conn and decrypted in-place into the caller's buf.
type cryptoConn2022 struct {
	Conn
	method      string
	psk         []byte
	readCipher  *crypto.TcpCipher2022
	writeCipher *crypto.TcpCipher2022

	// Server-side handshake state
	svSalt  []byte
	cliSalt []byte

	initBuf    []byte // initial data from server handshake (client side)
	wlbuf      []byte // write length-tag buffer: 2+overhead
	wdbuf      []byte // write data buffer: max chunk + overhead
	deferClose bool
}

func newServerCryptoConn2022(conn Conn, method string, psk, svSalt, cliSalt []byte, readCipher *crypto.TcpCipher2022) *cryptoConn2022 {
	overhead := readCipher.Overhead()
	return &cryptoConn2022{
		Conn:       conn,
		method:     method,
		psk:        psk,
		readCipher: readCipher,
		svSalt:     svSalt,
		cliSalt:    cliSalt,
		wlbuf:      make([]byte, 2+overhead),
		wdbuf:      make([]byte, 65535+overhead),
	}
}

func newClientCryptoConn2022(conn Conn, method string, psk []byte, writeCipher *crypto.TcpCipher2022) *cryptoConn2022 {
	overhead := writeCipher.Overhead()
	return &cryptoConn2022{
		Conn:        conn,
		method:      method,
		psk:         psk,
		writeCipher: writeCipher,
		wlbuf:       make([]byte, 2+overhead),
		wdbuf:       make([]byte, 65535+overhead),
	}
}

func (c *cryptoConn2022) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	// Client side: complete handshake on first read
	if c.readCipher == nil {
		if err := c.clientHandshake(pool); err != nil {
			return nil, err
		}
	}

	// Return initial data from server handshake first
	if c.initBuf != nil {
		data := c.initBuf
		c.initBuf = nil
		if cap(buf) >= len(data) {
			n := copy(buf, data)
			return [][]byte{buf[:n]}, nil
		}
		return [][]byte{data}, nil
	}

	return c.readFrame(buf, pool)
}

func (c *cryptoConn2022) readFrame(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	r := AsReader(c.Conn, pool)
	overhead := c.readCipher.Overhead()

	// Read and decrypt length tag
	lbLen := 2 + overhead
	var lbArr [22]byte
	lb := lbArr[:lbLen]
	if _, err := io.ReadFull(r, lb); err != nil {
		return nil, err
	}
	lb, ok := c.readCipher.DecryptPacket(lb)
	if !ok {
		return nil, fmt.Errorf("decrypt length failed")
	}
	length := int(uint16(lb[0])<<8 | uint16(lb[1]))
	if length == 0 {
		return nil, fmt.Errorf("zero-length 2022 frame")
	}

	dataLen := length + overhead
	if cap(buf) >= dataLen {
		if _, err := io.ReadFull(r, buf[:dataLen]); err != nil {
			return nil, err
		}
		dec, ok := c.readCipher.DecryptPacket(buf[:dataLen])
		if !ok {
			return nil, fmt.Errorf("decrypt data failed")
		}
		return [][]byte{dec[:length]}, nil
	}

	data := make([]byte, dataLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	dec, ok := c.readCipher.DecryptPacket(data)
	if !ok {
		return nil, fmt.Errorf("decrypt data failed")
	}
	return [][]byte{dec[:length]}, nil
}

func (c *cryptoConn2022) Write(bufs ...[]byte) (n int, err error) {
	for _, b := range bufs {
		n += len(b)
	}
	plaintext := flatten(bufs)
	if err := c.writeFrame(plaintext); err != nil {
		return n, err
	}
	return n, nil
}

func (c *cryptoConn2022) writeFrame(plaintext []byte) error {
	w := AsReadWriteCloser(c.Conn, nil)
	totalLen := len(plaintext)

	// Server: send handshake response on first write
	if c.svSalt != nil {
		svCiph, err := crypto.NewTcpCipher2022(c.method, c.psk, c.svSalt)
		if err != nil {
			return err
		}
		// If payload fits in a single handshake frame, bundle it.
		// Otherwise send empty handshake then fall through to chunked write.
		hdrPayloadLen := totalLen
		if hdrPayloadLen > 0xFFFF {
			hdrPayloadLen = 0
		}
		svHdr := make([]byte, 1+8+len(c.cliSalt)+2)
		svHdr[0] = aead2022ServerType
		binary.BigEndian.PutUint64(svHdr[1:9], uint64(time.Now().Unix()))
		copy(svHdr[9:9+len(c.cliSalt)], c.cliSalt)
		binary.BigEndian.PutUint16(svHdr[9+len(c.cliSalt):11+len(c.cliSalt)], uint16(hdrPayloadLen))
		svHdr = svCiph.EncryptPacket(svHdr)

		resp := make([]byte, len(c.svSalt)+len(svHdr))
		copy(resp, c.svSalt)
		copy(resp[len(c.svSalt):], svHdr)
		if hdrPayloadLen > 0 {
			data := make([]byte, totalLen+svCiph.Overhead())
			copy(data, plaintext)
			data = svCiph.EncryptPacket(data[:totalLen])
			resp = append(resp, data...)
		}
		if _, err := w.Write(resp); err != nil {
			return err
		}
		c.writeCipher = svCiph
		c.svSalt = nil
		c.cliSalt = nil
		if hdrPayloadLen > 0 {
			return nil
		}
		// fall through to chunked write below
	}

	// Chunked encryption with length tags
	overhead := c.writeCipher.Overhead()
	for off := 0; off < totalLen; {
		chunkLen := totalLen - off
		if chunkLen > 0xFFFF {
			chunkLen = 0xFFFF
		}
		lbLen := 2 + overhead
		if cap(c.wlbuf) < lbLen {
			c.wlbuf = make([]byte, lbLen)
		}
		lb := c.wlbuf[:2:lbLen]
		binary.BigEndian.PutUint16(lb[:2], uint16(chunkLen))
		lb = c.writeCipher.EncryptPacket(lb)

		dataLen := chunkLen + overhead
		if cap(c.wdbuf) < dataLen {
			c.wdbuf = make([]byte, dataLen)
		}
		data := c.wdbuf[:chunkLen:dataLen]
		copy(data, plaintext[off:off+chunkLen])
		data = c.writeCipher.EncryptPacket(data)

		if _, err := w.Write(append(lb, data...)); err != nil {
			return err
		}
		off += chunkLen
	}
	return nil
}

func (c *cryptoConn2022) clientHandshake(pool *utils.BufPool) error {
	r := AsReader(c.Conn, pool)

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
		data := make([]byte, dataLen+svCiph.Overhead())
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}
		_, ok = svCiph.DecryptPacket(data)
		if !ok {
			return fmt.Errorf("decrypt initial server data failed")
		}
		c.initBuf = data[:dataLen]
	}
	c.readCipher = svCiph
	return nil
}

func (c *cryptoConn2022) Close() error {
	if c.deferClose {
		go func() {
			time.Sleep(time.Duration(rand.Int()%64+8) * time.Second)
			c.Conn.Close()
		}()
		return nil
	}
	return c.Conn.Close()
}

func (c *cryptoConn2022) DeferClose()       { c.deferClose = true }
func (c *cryptoConn2022) CancelDeferClose() { c.deferClose = false }
func (c *cryptoConn2022) Unwrap() Conn      { return c.Conn }

func (c *cryptoConn2022) GetCfg() *Config {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetCfg()
	}
	return nil
}
func (c *cryptoConn2022) SetDst(dst Addr) {
	if cm := getConnMeta(c.Conn); cm != nil {
		cm.SetDst(dst)
	}
}
func (c *cryptoConn2022) GetDst() Addr {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetDst()
	}
	return nil
}
func (c *cryptoConn2022) GetHost() string {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetHost()
	}
	return ""
}

func (c *cryptoConnStream) Close() error {
	if c.deferClose {
		go func() {
			time.Sleep(time.Duration(rand.Int()%64+8) * time.Second)
			c.Conn.Close()
		}()
		return nil
	}
	return c.Conn.Close()
}

func (c *cryptoConnStream) DeferClose()       { c.deferClose = true }
func (c *cryptoConnStream) CancelDeferClose() { c.deferClose = false }
func (c *cryptoConnStream) Unwrap() Conn      { return c.Conn }

func (c *cryptoConnStream) GetCfg() *Config {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetCfg()
	}
	return nil
}
func (c *cryptoConnStream) SetDst(dst Addr) {
	if cm := getConnMeta(c.Conn); cm != nil {
		cm.SetDst(dst)
	}
}
func (c *cryptoConnStream) GetDst() Addr {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetDst()
	}
	return nil
}
func (c *cryptoConnStream) GetHost() string {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetHost()
	}
	return ""
}

func flatten(bufs [][]byte) []byte {
	if len(bufs) == 1 {
		return bufs[0]
	}
	n := 0
	for _, b := range bufs {
		n += len(b)
	}
	out := make([]byte, n)
	off := 0
	for _, b := range bufs {
		off += copy(out[off:], b)
	}
	return out
}
