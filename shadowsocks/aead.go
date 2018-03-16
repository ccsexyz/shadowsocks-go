package ss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"

	"github.com/ccsexyz/utils"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

var (
	errInvalidAEADMethod = errors.New("invalid aead method")
)

func aeadKeySize(method string) int {
	switch method {
	default:
		panic(errInvalidAEADMethod)
	case "aes-128-gcm":
		return 16
	case "aes-192-gcm":
		return 24
	case "aes-256-gcm":
		return 32
	case "chacha20poly1305":
		return 32
	}
}

// IsAEAD will check if the method is AEAD cipher name
func IsAEAD(method string) bool {
	switch method {
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20poly1305":
		return true
	default:
		return false
	}
}

func getAEAD(method string, key []byte) (cipher.AEAD, error) {
	switch method {
	default:
		panic(errInvalidAEADMethod)
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case "chacha20poly1305":
		return chacha20poly1305.New(key)
	}
}

func aeadKey(method, password string, salt []byte) []byte {
	keyLen := aeadKeySize(method)
	key := kdf(password, keyLen)
	subKey := make([]byte, keyLen)
	r := hkdf.New(sha1.New, key, salt, []byte("ss-subkey"))
	io.ReadFull(r, subKey)
	return subKey
}

type ssAeadNonce [32]byte

func (s *ssAeadNonce) increment() {
	for i := range *s {
		(*s)[i]++
		if (*s)[i] != 0 {
			return
		}
	}
}

type SSAeadDecrypter struct {
	ssAeadNonce
	cipher.AEAD
}

func (s *SSAeadDecrypter) Decrypt(dst, src []byte) error {
	_, err := s.AEAD.Open(dst[:0], s.ssAeadNonce[:s.NonceSize()], src, nil)
	s.increment()
	return err
}

type SSAeadDecrypterMaker struct {
	method   string
	password string
	ivlen    int
}

func (s *SSAeadDecrypterMaker) Make(iv []byte) (*SSAeadDecrypter, error) {
	aead, err := getAEAD(s.method, aeadKey(s.method, s.password, iv))
	if err != nil {
		return nil, err
	}
	return &SSAeadDecrypter{AEAD: aead}, nil
}

type SSAeadEncrypter struct {
	ssAeadNonce
	cipher.AEAD
}

func NewSSAeadDecrypterMaker(method, password string) *SSAeadDecrypterMaker {
	return &SSAeadDecrypterMaker{
		method:   method,
		password: password,
		ivlen:    aeadKeySize(method),
	}
}

func (s *SSAeadEncrypter) Encrypt(dst, src []byte) error {
	s.AEAD.Seal(dst[:0], s.ssAeadNonce[:s.NonceSize()], src, nil)
	s.increment()
	return nil
}

type SSAeadEncrypterMaker struct {
	method   string
	password string
	ivlen    int
}

func NewSSAeadEncrypterMaker(method, password string) *SSAeadEncrypterMaker {
	return &SSAeadEncrypterMaker{
		method:   method,
		password: password,
		ivlen:    aeadKeySize(method),
	}
}

func (s *SSAeadEncrypterMaker) Make(iv []byte) (*SSAeadEncrypter, error) {
	aead, err := getAEAD(s.method, aeadKey(s.method, s.password, iv))
	if err != nil {
		return nil, err
	}
	return &SSAeadEncrypter{AEAD: aead}, nil
}

const (
	aeadSizeMask   = 0x3FFF
	aeadMaxOutSize = 1200
)

type AEADShadowSocksConn struct {
	Conn
	buf      []byte
	off      int
	enc      *SSAeadEncrypter
	dec      *SSAeadDecrypter
	encMaker *SSAeadEncrypterMaker
	decMaker *SSAeadDecrypterMaker
}

func NewAEADShadowSocksConn(conn Conn, encMaker *SSAeadEncrypterMaker, decMaker *SSAeadDecrypterMaker) Conn {
	return &AEADShadowSocksConn{
		Conn:     conn,
		encMaker: encMaker,
		decMaker: decMaker,
	}
}

func (c *AEADShadowSocksConn) ReadBuffer(b []byte) ([]byte, error) {
	if c.dec == nil {
		if len(b) < c.decMaker.ivlen {
			return nil, io.ErrShortBuffer
		}
		iv := b[:c.decMaker.ivlen]
		err := ReadFull(c.Conn, iv)
		if err != nil {
			return nil, err
		}
		c.dec, err = c.decMaker.Make(iv)
		if err != nil {
			return nil, err
		}
		c.decMaker = nil
	}
	if c.buf != nil {
		if len(b) >= len(c.buf[c.off:]) {
			b = c.buf[c.off:]
			utils.PutBuf(c.buf)
			c.off = 0
			c.buf = nil
		} else {
			b = c.buf[c.off : c.off+len(b)]
			c.off += len(b)
		}
		return b, nil
	}
	tagLen := c.dec.Overhead()
	if len(b) < tagLen+2 {
		return nil, io.ErrShortBuffer
	}
	err := ReadFull(c.Conn, b[:tagLen+2])
	if err != nil {
		return nil, err
	}
	err = c.dec.Decrypt(b, b[:tagLen+2])
	if err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(b[:2])) & aeadSizeMask
	if len(b) > length+tagLen {
		err = ReadFull(c.Conn, b[:length+tagLen])
		if err != nil {
			return nil, err
		}
		err = c.dec.Decrypt(b, b[:length+tagLen])
		if err != nil {
			return nil, err
		}
		return b[:length], nil
	}
	c.buf = utils.GetBuf(length + tagLen)
	defer func() {
		if err == nil {
			return
		}
		utils.PutBuf(c.buf)
		c.buf = nil
	}()
	err = ReadFull(c.Conn, c.buf)
	if err != nil {
		return nil, err
	}
	err = c.dec.Decrypt(c.buf, c.buf)
	if err != nil {
		return nil, err
	}
	c.off = len(b)
	return c.buf[:c.off], nil
}

func (c *AEADShadowSocksConn) WriteBuffers(bufs [][]byte) error {
	var err error
	wbufs := make([][]byte, 0, 4+len(bufs)*4)
	for _, buf := range bufs {
		for len(buf) > aeadMaxOutSize {
			b := buf[:aeadMaxOutSize]
			buf = buf[aeadMaxOutSize:]
			wbufs = append(wbufs, b)
		}
		if len(buf) > 0 {
			wbufs = append(wbufs, buf)
		}
	}
	bufs = append(bufs[:0], wbufs...)
	wbufs = wbufs[:0]
	if c.enc == nil {
		iv := utils.GetRandomBytes(c.encMaker.ivlen)
		wbufs = append(wbufs, iv)
		c.enc, err = c.encMaker.Make(iv)
		if err != nil {
			return err
		}
		c.encMaker = nil
	}
	for _, buf := range bufs {
		b := utils.GetBuf(len(buf) + c.enc.Overhead()*2 + 2)
		defer utils.PutBuf(b)
		binary.BigEndian.PutUint16(b[:2], uint16(len(buf)))
		err = c.enc.Encrypt(b, b[:2])
		if err != nil {
			return err
		}
		wbufs = append(wbufs, b[:2+c.enc.Overhead()])
		err = c.enc.Encrypt(b[2+c.enc.Overhead():], buf)
		if err != nil {
			return err
		}
		wbufs = append(wbufs, b[2+c.enc.Overhead():])
	}
	return c.Conn.WriteBuffers(wbufs)
}
