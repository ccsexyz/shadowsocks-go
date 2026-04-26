package crypto

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"sync"
)

var errInvalidKeyLength = errors.New("invalid key length for cipher method")
var errInvalidMethod = errors.New("invalid cipher method")

const cipherBlockLen = 8192
const aeadSizeMask = 0x3FFF

type cipherMemBlock struct {
	b [cipherBlockLen]byte
}

var cipherBlockPool = sync.Pool{
	New: func() interface{} {
		return &cipherMemBlock{}
	},
}

func getCipherMemBlock() *cipherMemBlock {
	return cipherBlockPool.Get().(*cipherMemBlock)
}

func putCipherMemBlock(b *cipherMemBlock) {
	cipherBlockPool.Put(b)
}

type CipherStream interface {
	io.ReadWriter
	GetIV() []byte
}

type PlainCipherStream struct {
	b bytes.Buffer
}

func (p *PlainCipherStream) Read(b []byte) (n int, err error) {
	return p.b.Read(b)
}

func (p *PlainCipherStream) Write(b []byte) (n int, err error) {
	return p.b.Write(b)
}

func (p *PlainCipherStream) GetIV() []byte {
	return []byte{}
}

type dataWriter interface {
	writeData([]byte) (int, error)
}

type baseCipherStream struct {
	b     bytes.Buffer
	dw    dataWriter
	iv    []byte
	ivLen int
	isEnc bool
}

func (b *baseCipherStream) initEncrypter(iv []byte, dw dataWriter) {
	b.iv = append([]byte{}, iv...)
	b.ivLen = len(iv)
	b.isEnc = true
	b.dw = dw
	b.b.Write(iv)
}

func (b *baseCipherStream) initDecrypter(ivLen int, dw dataWriter) {
	b.ivLen = ivLen
	b.isEnc = false
	b.dw = dw
}

func (b *baseCipherStream) Read(p []byte) (n int, err error) {
	return b.b.Read(p)
}

func (b *baseCipherStream) Write(p []byte) (n int, err error) {
	n1, err := b.writeIV(p)
	if err != nil {
		return
	}
	n += n1
	p = p[n1:]

	for len(p) > 0 {
		p2 := p
		if len(p2) > cipherBlockLen {
			p2 = p2[:cipherBlockLen]
		}
		p = p[len(p2):]
		var n2 int
		n2, err = b.dw.writeData(p2)
		if err != nil {
			return
		}
		n += n2
	}
	return
}

func (b *baseCipherStream) writeIV(p []byte) (n int, err error) {
	if b.isEnc || len(b.iv) >= b.ivLen {
		return
	}
	n = b.ivLen - len(b.iv)
	if len(p) < n {
		n = len(p)
	}
	b.iv = append(b.iv, p[:n]...)
	return
}

func (b *baseCipherStream) GetIV() []byte {
	if b.iv == nil {
		return []byte{}
	}
	return b.iv
}

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

func NewPlainEncrypter(_, _ []byte) (CipherStream, error) {
	return &PlainCipherStream{}, nil
}

func NewPlainDecrypter(_ []byte, _ int) (CipherStream, error) {
	return &PlainCipherStream{}, nil
}

func newNotSupportedEncrypter(_, _ []byte) (CipherStream, error) {
	return nil, errInvalidMethod
}

func newNotSupportedDecrypter(_ []byte, _ int) (CipherStream, error) {
	return nil, errInvalidMethod
}

type cipherMethodEntry struct {
	keylen         int
	ivlen          int
	newEncrypter   func(key, iv []byte) (CipherStream, error)
	newDecrypter   func(key []byte, ivLen int) (CipherStream, error)
	newCipherBlock func(key []byte, ivLen int) (CipherBlock, error)
	is2022         bool
}

var cipherMethod = map[string]cipherMethodEntry{
	"aes-128-gcm":                {16, 16, NewAESGCMEncrypter, NewAESGCMDecrypter, NewAESGCMCipherBlock, false},
	"aes-192-gcm":                {24, 24, NewAESGCMEncrypter, NewAESGCMDecrypter, NewAESGCMCipherBlock, false},
	"aes-256-gcm":                {32, 32, NewAESGCMEncrypter, NewAESGCMDecrypter, NewAESGCMCipherBlock, false},
	"chacha20poly1305":           {32, 32, NewChacha20Poly1305Encrypter, NewChacha20Poly1305Decrypter, NewChaCha20Poly1305CipherBlock, false},
	"plain":                     {0, 0, NewPlainEncrypter, NewPlainDecrypter, NewPlainCipherBlock, false},
	"2022-blake3-aes-128-gcm":   {16, 16, newNotSupportedEncrypter, newNotSupportedDecrypter, New2022AESGCMCipherBlock, true},
	"2022-blake3-aes-256-gcm":   {32, 32, newNotSupportedEncrypter, newNotSupportedDecrypter, New2022AESGCMCipherBlock, true},
	"2022-blake3-chacha20-poly1305": {32, 32, newNotSupportedEncrypter, newNotSupportedDecrypter, New2022Chacha20Poly1305CipherBlock, true},
}

func IsAEAD(method string) bool {
	switch method {
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20poly1305",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return true
	default:
		return false
	}
}

func IsAEAD2022(method string) bool {
	switch method {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return true
	default:
		return false
	}
}

func GetIvLen(method string) int {
	m, ok := cipherMethod[method]
	if ok {
		return m.ivlen
	}
	return cipherMethod[DefaultMethod].ivlen
}

func NewEncrypter(method, password string) (enc CipherStream, err error) {
	if password == "" && method != "plain" {
		err = fmt.Errorf("password cannot be empty")
		return
	}
	m, ok := cipherMethod[method]
	if !ok {
		m = cipherMethod[DefaultMethod]
	}
	if m.is2022 {
		psk, derr := DecodePSK(password, m.keylen)
		if derr != nil {
			err = derr
			return
		}
		salt := GetRandomBytes(m.keylen)
		enc, err = m.newEncrypter(psk, salt)
		return
	}
	iv := GetRandomBytes(m.ivlen)
	key := kdf(password, m.keylen)
	if IsAEAD(method) {
		key = aeadKey(key, iv)
	}
	enc, err = m.newEncrypter(key, iv)
	return
}

func NewDecrypter(method, password string) (dec CipherStream, err error) {
	if password == "" && method != "plain" {
		err = fmt.Errorf("password cannot be empty")
		return
	}
	m, ok := cipherMethod[method]
	if !ok {
		m = cipherMethod[DefaultMethod]
	}
	if m.is2022 {
		psk, derr := DecodePSK(password, m.keylen)
		if derr != nil {
			err = derr
			return
		}
		dec, err = m.newDecrypter(psk, m.ivlen)
		return
	}
	dec, err = m.newDecrypter(kdf(password, m.keylen), m.ivlen)
	return
}
