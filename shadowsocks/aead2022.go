package ss

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

const (
	aead2022ClientType = 0
	aead2022ServerType = 1

	aead2022TimestampDiff = 30
)

type Aead2022Conn struct {
	Conn
	readCipher  *crypto.TcpCipher2022
	writeCipher *crypto.TcpCipher2022
	buf         []byte
	method      string
	psk         []byte
	once        sync.Once
	rerr        error

	svSalt  []byte
	cliSalt []byte

	lbuf []byte
	dbuf []byte
}

func newAead2022Conn(conn Conn, readCipher, writeCipher *crypto.TcpCipher2022) *Aead2022Conn {
	return &Aead2022Conn{
		Conn:        conn,
		readCipher:  readCipher,
		writeCipher: writeCipher,
	}
}

func newServerAead2022Conn(conn Conn, readCipher *crypto.TcpCipher2022, method string, psk, svSalt, cliSalt []byte) *Aead2022Conn {
	return &Aead2022Conn{
		Conn:        conn,
		readCipher:  readCipher,
		method:      method,
		psk:         psk,
		svSalt:      svSalt,
		cliSalt:     cliSalt,
	}
}

func newClientAead2022Conn(conn Conn, writeCipher *crypto.TcpCipher2022, method string, psk []byte) *Aead2022Conn {
	return &Aead2022Conn{
		Conn:        conn,
		writeCipher: writeCipher,
		method:      method,
		psk:         psk,
	}
}

func (c *Aead2022Conn) doServerHandshake() error {
	svSalt := make([]byte, len(c.psk))
	_, err := io.ReadFull(c.Conn, svSalt)
	if err != nil {
		return fmt.Errorf("read server salt: %w", err)
	}
	svCiph, err := crypto.NewTcpCipher2022(c.method, c.psk, svSalt)
	if err != nil {
		return err
	}
	hdrLen := 1 + 8 + len(c.psk) + 2 + svCiph.Overhead()
	svBuf := make([]byte, hdrLen)
	_, err = io.ReadFull(c.Conn, svBuf)
	if err != nil {
		return fmt.Errorf("read server header: %w", err)
	}
	svBuf, ok := svCiph.DecryptPacket(svBuf)
	if !ok {
		return fmt.Errorf("decrypt server header failed")
	}
	if svBuf[0] != aead2022ServerType {
		return fmt.Errorf("unexpected server stream type: %d", svBuf[0])
	}
	dataLen := int(binary.BigEndian.Uint16(svBuf[1+8+len(c.psk):]))
	if dataLen > 0 {
		dataBuf := make([]byte, dataLen+svCiph.Overhead())
		_, err = io.ReadFull(c.Conn, dataBuf)
		if err != nil {
			return fmt.Errorf("read initial server data: %w", err)
		}
		dataBuf, ok = svCiph.DecryptPacket(dataBuf)
		if !ok {
			return fmt.Errorf("decrypt initial server data failed")
		}
		c.buf = dataBuf[:dataLen]
	} else {
		tagBuf := make([]byte, svCiph.Overhead())
		_, err = io.ReadFull(c.Conn, tagBuf)
		if err != nil {
			return fmt.Errorf("read empty server data tag: %w", err)
		}
		tagBuf, ok = svCiph.DecryptPacket(tagBuf)
		if !ok {
			return fmt.Errorf("decrypt empty server data failed")
		}
	}
	c.readCipher = svCiph
	return nil
}

func (c *Aead2022Conn) Read(b []byte) (n int, err error) {
	if c.readCipher == nil {
		c.once.Do(func() {
			c.rerr = c.doServerHandshake()
		})
		if c.rerr != nil {
			return 0, c.rerr
		}
	}
	if len(c.buf) > 0 {
		n = copy(b, c.buf)
		c.buf = c.buf[n:]
		if len(c.buf) == 0 {
			c.buf = nil
		}
		return n, nil
	}

	lbLen := 2 + c.readCipher.Overhead()
	if cap(c.lbuf) < lbLen {
		c.lbuf = make([]byte, lbLen)
	}
	lb := c.lbuf[:lbLen]
	_, err = io.ReadFull(c.Conn, lb)
	if err != nil {
		return 0, err
	}
	var ok bool
	lb, ok = c.readCipher.DecryptPacket(lb)
	if !ok {
		return 0, fmt.Errorf("decrypt length failed")
	}
	length := int(binary.BigEndian.Uint16(lb[:2]))

	dataLen := length + c.readCipher.Overhead()
	if cap(c.dbuf) < dataLen {
		c.dbuf = make([]byte, dataLen)
	}
	data := c.dbuf[:dataLen]
	_, err = io.ReadFull(c.Conn, data)
	if err != nil {
		return 0, err
	}
	data, ok = c.readCipher.DecryptPacket(data)
	if !ok {
		return 0, fmt.Errorf("decrypt data failed")
	}
	plain := data[:length]

	n = copy(b, plain)
	if n < len(plain) {
		c.buf = plain[n:]
	}
	return n, nil
}
func (c *Aead2022Conn) Write(b []byte) (n int, err error) {
	if c.svSalt != nil {
		chunk := b
		if len(chunk) > 0xFFFF {
			chunk = chunk[:0xFFFF]
		}
		b = b[len(chunk):]

		svCiph, cerr := crypto.NewTcpCipher2022(c.method, c.psk, c.svSalt)
		if cerr != nil {
			return 0, cerr
		}
		svHdr := make([]byte, 1+8+len(c.cliSalt)+2)
		svHdr[0] = aead2022ServerType
		binary.BigEndian.PutUint64(svHdr[1:9], uint64(time.Now().Unix()))
		copy(svHdr[9:9+len(c.cliSalt)], c.cliSalt)
		binary.BigEndian.PutUint16(svHdr[9+len(c.cliSalt):11+len(c.cliSalt)], uint16(len(chunk)))
		svHdr = svCiph.EncryptPacket(svHdr)

		data := make([]byte, len(chunk), len(chunk)+svCiph.Overhead())
		copy(data, chunk)
		data = svCiph.EncryptPacket(data)

		resp := make([]byte, len(c.svSalt)+len(svHdr)+len(data))
		copy(resp, c.svSalt)
		copy(resp[len(c.svSalt):], svHdr)
		copy(resp[len(c.svSalt)+len(svHdr):], data)
		_, err = c.Conn.Write(resp)
		if err != nil {
			return 0, err
		}

		c.writeCipher = svCiph
		c.svSalt = nil
		c.cliSalt = nil
		n = len(chunk)
	}

	for len(b) > 0 {
		chunk := b
		if len(chunk) > 0xFFFF {
			chunk = chunk[:0xFFFF]
		}
		b = b[len(chunk):]

		overhead := c.writeCipher.Overhead()
		lbLen := 2 + overhead
		if cap(c.lbuf) < lbLen {
			c.lbuf = make([]byte, lbLen)
		}
		lb := c.lbuf[:2:lbLen]
		binary.BigEndian.PutUint16(lb[:2], uint16(len(chunk)))
		lb = c.writeCipher.EncryptPacket(lb)

		dataLen := len(chunk) + overhead
		if cap(c.dbuf) < dataLen {
			c.dbuf = make([]byte, dataLen)
		}
		data := c.dbuf[:len(chunk):dataLen]
		copy(data, chunk)
		data = c.writeCipher.EncryptPacket(data)

		_, err = c.Conn.WriteBuffers([][]byte{lb, data})
		if err != nil {
			return n, err
		}
		n += len(chunk)
	}
	return
}

func buildAead2022Header(cipher *crypto.TcpCipher2022, salt []byte, addr Addr, data []byte) []byte {
	ah := addr.Header()
	if len(ah) == 0 {
		return nil
	}

	var paddingSize int
	if len(data) > 0 {
		paddingSize = 0
	} else {
		paddingSize = rand.IntN(901)
	}

	addrLen := len(ah) + 2 + paddingSize + len(data)

	hdr1 := make([]byte, 1+8+2)
	hdr1[0] = aead2022ClientType
	binary.BigEndian.PutUint64(hdr1[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(hdr1[9:11], uint16(addrLen))
	hdr1 = cipher.EncryptPacket(hdr1)

	hdr2Len := len(ah) + 2 + paddingSize + len(data)
	hdr2 := make([]byte, hdr2Len)
	copy(hdr2, ah)
	binary.BigEndian.PutUint16(hdr2[len(ah):], uint16(paddingSize))
	if paddingSize > 0 {
		utils.PutRandomBytes(hdr2[len(ah)+2 : len(ah)+2+paddingSize])
	}
	if len(data) > 0 {
		copy(hdr2[len(ah)+2+paddingSize:], data)
	}
	hdr2 = cipher.EncryptPacket(hdr2)

	total := make([]byte, len(salt)+len(hdr1)+len(hdr2))
	copy(total, salt)
	copy(total[len(salt):], hdr1)
	copy(total[len(salt)+len(hdr1):], hdr2)
	return total
}

func ss2022AcceptHandler(conn Conn, lis *listener) AcceptResult {
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)

	saltLen := lis.c.Ivlen
	if saltLen == 0 {
		lis.c.Log("invalid ivlen for AEAD-2022 method")
		return AcceptResult{AcceptReject, nil}
	}
	_, err := io.ReadFull(conn, buf[:saltLen])
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}
	salt := make([]byte, saltLen)
	copy(salt, buf[:saltLen])

	psk, derr := crypto.DecodePSK(lis.c.Password, lis.c.Ivlen)
	if derr != nil {
		lis.c.Log("decode PSK failed:", derr)
		return AcceptResult{AcceptReject, nil}
	}

	ciph, err := crypto.NewTcpCipher2022(lis.c.Method, psk, salt)
	if err != nil {
		lis.c.Log("create cipher failed:", err)
		return AcceptResult{AcceptReject, nil}
	}

	hdr1Len := 1 + 8 + 2 + ciph.Overhead()
	_, err = io.ReadFull(conn, buf[:hdr1Len])
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}
	hdr1 := make([]byte, hdr1Len)
	copy(hdr1, buf[:hdr1Len])
	var ok bool
	hdr1, ok = ciph.DecryptPacket(hdr1)
	if !ok {
		lis.c.Log("decrypt header packet 1 failed")
		return AcceptResult{AcceptReject, nil}
	}

	if hdr1[0] != aead2022ClientType {
		lis.c.Log("unexpected stream type:", hdr1[0])
		return AcceptResult{AcceptReject, nil}
	}

	now := uint64(time.Now().Unix())
	ts := binary.BigEndian.Uint64(hdr1[1:9])
	diff := now - ts
	if ts > now {
		diff = ts - now
	}
	if diff > aead2022TimestampDiff {
		lis.c.Log("invalid timestamp:", ts, "now:", now)
		return AcceptResult{AcceptReject, nil}
	}

	addrLen := int(binary.BigEndian.Uint16(hdr1[9:11]))

	hdr2Len := addrLen + ciph.Overhead()
	if cap(buf) < hdr2Len {
		buf = make([]byte, hdr2Len)
	}
	_, err = io.ReadFull(conn, buf[:hdr2Len])
	if err != nil {
		return AcceptResult{AcceptReject, nil}
	}
	hdr2 := make([]byte, hdr2Len)
	copy(hdr2, buf[:hdr2Len])
	hdr2, ok = ciph.DecryptPacket(hdr2)
	if !ok {
		lis.c.Log("decrypt header packet 2 failed")
		return AcceptResult{AcceptReject, nil}
	}

	addr, rest, err := ParseAddr(hdr2)
	if err != nil {
		lis.c.Log("parse addr failed:", err)
		return AcceptResult{AcceptReject, nil}
	}
	if len(rest) < 2 {
		lis.c.Log("header too short for padding size")
		return AcceptResult{AcceptReject, nil}
	}
	padSize := int(binary.BigEndian.Uint16(rest[:2]))
	if padSize > 900 {
		lis.c.Log("invalid padding size:", padSize)
		return AcceptResult{AcceptReject, nil}
	}
	if len(rest) < 2+padSize {
		lis.c.Log("header shorter than padding size")
		return AcceptResult{AcceptReject, nil}
	}
	data := rest[2+padSize:]

	svSalt := utils.GetRandomBytes(saltLen)
	ssConn := newServerAead2022Conn(conn, ciph, lis.c.Method, psk, svSalt, salt)
	conn.SetDst(addr)

	if len(data) > 0 {
		return AcceptResult{AcceptContinue, &RemainConn{Conn: ssConn, remain: data}}
	}
	return AcceptResult{AcceptContinue, ssConn}
}

func ss2022Dial(opt *DialOptions) (conn Conn, err error) {
	c := opt.C

	var tconn *TCPConn
	if c.Obfs {
		conn, err = DialObfs(c.Remoteaddr, c)
	} else {
		tconn, err = DialTCP(c.Remoteaddr, c)
		if tconn != nil {
			conn = tconn
		}
	}
	if err != nil {
		return nil, err
	}

	psk, derr := crypto.DecodePSK(c.Password, c.Ivlen)
	if derr != nil {
		conn.Close()
		return nil, derr
	}

	host, port, sperr := utils.SplitHostAndPort(opt.Target)
	if sperr != nil {
		conn.Close()
		return nil, sperr
	}
	addrBuf, err := GetHeader(host, port)
	if err != nil {
		conn.Close()
		return nil, err
	}
	addr := &SockAddr{Hdr: addrBuf}

	salt := utils.GetRandomBytes(c.Ivlen)
	ciph, err := crypto.NewTcpCipher2022(c.Method, psk, salt)
	if err != nil {
		conn.Close()
		return nil, err
	}

	header := buildAead2022Header(ciph, salt, addr, opt.Data)
	if header == nil {
		conn.Close()
		return nil, fmt.Errorf("build header failed")
	}
	c.Log("ss2022Dial: sending header len", len(header), "salt len", len(salt), "data len", len(opt.Data))
	_, err = conn.Write(header)
	if err != nil {
		conn.Close()
		return nil, err
	}
	c.Log("ss2022Dial: header sent")
	opt.Data = nil

	ssConn := newClientAead2022Conn(conn, ciph, c.Method, psk)
	return ssConn, nil
}

func tryDecodeAead2022(b []byte, cfg *Config) (*parseContext, error) {
	saltLen := cfg.Ivlen
	if saltLen == 0 || len(b) <= saltLen {
		return nil, errInvalidHeader
	}

	psk, err := crypto.DecodePSK(cfg.Password, saltLen)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, saltLen)
	copy(salt, b[:saltLen])

	ciph, err := crypto.NewTcpCipher2022(cfg.Method, psk, salt)
	if err != nil {
		return nil, err
	}

	hdr1PlainLen := 1 + 8 + 2
	hdr1Len := hdr1PlainLen + ciph.Overhead()
	if len(b) < saltLen+hdr1Len {
		return nil, errInvalidHeader
	}

	hdr1 := make([]byte, hdr1Len)
	copy(hdr1, b[saltLen:saltLen+hdr1Len])
	hdr1, ok := ciph.DecryptPacket(hdr1)
	if !ok {
		return nil, errInvalidHeader
	}

	if hdr1[0] != aead2022ClientType {
		return nil, errInvalidHeader
	}

	now := uint64(time.Now().Unix())
	ts := binary.BigEndian.Uint64(hdr1[1:9])
	diff := now - ts
	if ts > now {
		diff = ts - now
	}
	if diff > aead2022TimestampDiff {
		return nil, errInvalidHeader
	}

	addrLen := int(binary.BigEndian.Uint16(hdr1[9:11]))

	hdr2Len := addrLen + ciph.Overhead()
	if len(b) < saltLen+hdr1Len+hdr2Len {
		return nil, errInvalidHeader
	}

	hdr2 := make([]byte, hdr2Len)
	copy(hdr2, b[saltLen+hdr1Len:saltLen+hdr1Len+hdr2Len])
	hdr2, ok = ciph.DecryptPacket(hdr2)
	if !ok {
		return nil, errInvalidHeader
	}

	addr, rest, err := ParseAddr(hdr2)
	if err != nil {
		return nil, err
	}

	if len(rest) < 2 {
		return nil, errInvalidHeader
	}
	padSize := int(binary.BigEndian.Uint16(rest[:2]))
	if padSize > 900 {
		return nil, errInvalidHeader
	}
	if len(rest) < 2+padSize {
		return nil, errInvalidHeader
	}

	data := make([]byte, len(rest[2+padSize:]))
	copy(data, rest[2+padSize:])

	if tail := saltLen + hdr1Len + hdr2Len; tail < len(b) {
		extra := make([]byte, len(b)-tail)
		copy(extra, b[tail:])
		data = append(data, extra...)
	}

	return &parseContext{
		data:      data,
		addr:      addr,
		chs:       cfg,
		cliCipher: ciph,
		cliSalt:   salt,
	}, nil
}
