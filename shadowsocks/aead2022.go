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

const (
	aead2022ClientType = 0
	aead2022ServerType = 1

	aead2022TimestampDiff = 30
)

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

	// SIP022: check salt for replay. Store incoming salts and reject duplicates.
	saltStr := utils.SliceToString(salt)
	if !lis.c.getTCPIvChecker().check(saltStr) {
		lis.c.Log("reject replayed salt from", conn.RemoteAddr().String())
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
	// SIP022: reject requests with zero padding and zero initial payload
	if padSize == 0 && len(rest) == 2 {
		lis.c.Log("reject: zero padding and zero payload")
		return AcceptResult{AcceptReject, nil}
	}
	data := rest[2+padSize:]

	svSalt := utils.GetRandomBytes(saltLen)
	ssConn := newCryptoConn(conn, newServerAead2022Codec(lis.c.Method, psk, svSalt, salt, ciph))
	ssConn.DeferClose()
	conn.SetDst(addr)

	if len(data) > 0 {
		return AcceptResult{AcceptContinue, &RemainConn{Conn: ssConn, remain: data}}
	}
	return AcceptResult{AcceptContinue, ssConn}
}

func ss2022Dial(opt *DialOptions) (conn Conn, err error) {
	c := opt.C

	var tconn *BaseConn
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

	ssConn := newCryptoConn(conn, newClientAead2022Codec(c.Method, psk, ciph))
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
	// SIP022: reject requests with zero padding and zero initial payload
	if padSize == 0 && len(rest) == 2 {
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
