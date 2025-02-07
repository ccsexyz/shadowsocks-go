package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

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
	b.iv = CopyBuffer(iv)
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

// copy from https://github.com/riobard/go-shadowsocks2/blob/master/core/cipher.go
// key-derivation function from original Shadowsocks
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

var cipherMethod = map[string]struct {
	keylen         int
	ivlen          int
	newEncrypter   func(key, iv []byte) (CipherStream, error)
	newDecrypter   func(key []byte, ivLen int) (CipherStream, error)
	newCipherBlock func(key []byte, ivLen int) (CipherBlock, error)
}{
	"aes-128-gcm":      {16, 16, NewAESGCMEncrypter, NewAESGCMDecrypter, NewAESGCMCipherBlock},
	"aes-192-gcm":      {24, 24, NewAESGCMEncrypter, NewAESGCMDecrypter, NewAESGCMCipherBlock},
	"aes-256-gcm":      {32, 32, NewAESGCMEncrypter, NewAESGCMDecrypter, NewAESGCMCipherBlock},
	"chacha20poly1305": {32, 32, NewChacha20Poly1305Encrypter, NewChacha20Poly1305Decrypter, NewChaCha20Poly1305CipherBlock},
	"plain":            {0, 0, NewPlainEncrypter, NewPlainDecrypter, NewPlainCipherBlock},
}

func IsAEAD(method string) bool {
	switch method {
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20poly1305":
		return true
	default:
		return false
	}
}

func NewEncrypter(method, password string) (enc CipherStream, err error) {
	if password == "" && method != "plain" {
		err = fmt.Errorf("password cannot be empty")
		return
	}
	m, ok := cipherMethod[method]
	if !ok {
		m, _ = cipherMethod[defaultMethod]
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
		m, _ = cipherMethod[defaultMethod]
	}
	dec, err = m.newDecrypter(kdf(password, m.keylen), m.ivlen)
	return
}

func GetIvLen(method string) int {
	m, ok := cipherMethod[method]
	if ok {
		return m.ivlen
	}
	return cipherMethod[defaultMethod].ivlen
}

var initialVector = []byte{167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107}

type ssAEADNonce [32]byte

func (s *ssAEADNonce) increment() {
	for i := range *s {
		(*s)[i]++
		if (*s)[i] != 0 {
			return
		}
	}
}

type ssAEADCrypt struct {
	ssAEADNonce
	cipher.AEAD
}

func (s *ssAEADCrypt) Decrypt(dst, src []byte) error {
	_, err := s.AEAD.Open(dst[:0], s.ssAEADNonce[:s.AEAD.NonceSize()], src, nil)
	s.ssAEADNonce.increment()
	return err
}

func (s *ssAEADCrypt) Encrypt(dst, src []byte) {
	_ = s.AEAD.Seal(dst[:0], s.ssAEADNonce[:s.AEAD.NonceSize()], src, nil)
	s.ssAEADNonce.increment()
}

type aeadCreater interface {
	NewAEAD(iv []byte) (cipher.AEAD, error)
}

type aeadCipherStream struct {
	baseCipherStream
	crypt   ssAEADCrypt
	creater aeadCreater
}

type AEADEncryptCipherStream struct {
	aeadCipherStream
}

func (a *AEADEncryptCipherStream) writeData(p []byte) (n int, err error) {
	b := getCipherMemBlock()
	defer putCipherMemBlock(b)
	dst := b.b[:]

	if a.crypt.AEAD == nil {
		if a.creater == nil {
			panic("creater is nil")
		}

		a.crypt.AEAD, err = a.creater.NewAEAD(a.iv)
		if err != nil {
			return
		}
	}

	bufs := make([][]byte, 0, len(p)/1024)
	for len(p) > 0 {
		if len(p) > 1024 {
			bufs = append(bufs, p[:1024])
			p = p[1024:]
		} else {
			bufs = append(bufs, p)
			p = nil
		}
	}

	for _, buf := range bufs {
		binary.BigEndian.PutUint16(dst[:2], uint16(len(buf)))
		a.crypt.Encrypt(dst, dst[:2])
		_, err = a.b.Write(dst[:2+a.crypt.Overhead()])
		if err != nil {
			return
		}
		a.crypt.Encrypt(dst, buf)
		_, err = a.b.Write(dst[:len(buf)+a.crypt.Overhead()])
		if err != nil {
			return
		}
		n += len(buf)
	}
	return
}

type AEADDecryptCipherStream struct {
	aeadCipherStream
	pb     bytes.Buffer
	tagLen int
}

func (a *AEADDecryptCipherStream) writeData(p []byte) (n int, err error) {
	if a.crypt.AEAD == nil {
		if a.creater == nil {
			panic("creater is nil")
		}

		a.crypt.AEAD, err = a.creater.NewAEAD(a.iv)
		if err != nil {
			return
		}
	}

	return a.b.Write(p)
}

func (a *AEADDecryptCipherStream) Read(p []byte) (n int, err error) {
	n, _ = io.ReadFull(&a.pb, p)
	p = p[n:]
	if len(p) == 0 {
		return
	}

	if a.crypt.AEAD == nil {
		err = fmt.Errorf("AEAD is nil")
		return
	}

	b := getCipherMemBlock()
	defer putCipherMemBlock(b)

RETRY:
	if a.tagLen == 0 {
		if a.b.Len() < a.crypt.Overhead()+2 {
			if n == 0 {
				err = io.EOF
			}
			return
		}

		tag := b.b[:a.crypt.Overhead()+2]
		io.ReadFull(&a.b, tag)

		err2 := a.crypt.Decrypt(tag, tag)
		if err2 != nil {
			err = fmt.Errorf("decrypt tag fail: %w", err2)
			return
		}

		a.tagLen = int(binary.BigEndian.Uint16(tag[:2]) & aeadSizeMask)
	}

	expected := a.tagLen + a.crypt.Overhead()
	if a.b.Len() < expected {
		if n == 0 {
			err = io.EOF
		}
		return
	}

	var data []byte
	if expected > cipherBlockLen {
		data = make([]byte, expected)
	} else {
		data = b.b[:expected]
	}

	io.ReadFull(&a.b, data)
	err2 := a.crypt.Decrypt(data, data)
	if err2 != nil {
		err = fmt.Errorf("decrypt data fail: %w", err2)
		return
	}
	plain := data[:a.tagLen]
	a.tagLen = 0

	nCopy := copy(p, plain)
	n += nCopy

	if nCopy < len(plain) {
		a.pb.Write(plain[nCopy:])
	}

	if len(p) > nCopy {
		p = p[nCopy:]
		goto RETRY
	}

	return
}

func NewAESGCMEncrypter(key, iv []byte) (CipherStream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	c, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	a := new(AEADEncryptCipherStream)
	a.initEncrypter(iv, a)
	a.crypt.AEAD = c
	return a, nil
}

func NewChacha20Poly1305Encrypter(key, iv []byte) (CipherStream, error) {
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	a := new(AEADEncryptCipherStream)
	a.initEncrypter(iv, a)
	a.crypt.AEAD = c
	return a, nil
}

func aeadKey(key, iv []byte) []byte {
	subKey := make([]byte, len(key))
	r := hkdf.New(sha1.New, key, iv, []byte("ss-subkey"))
	io.ReadFull(r, subKey)
	return subKey
}

type aesAEADCreater struct {
	key []byte
}

func (a *aesAEADCreater) NewAEAD(iv []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(aeadKey(a.key, iv))
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func NewAESGCMDecrypter(key []byte, ivLen int) (CipherStream, error) {
	a := new(AEADDecryptCipherStream)
	a.initDecrypter(ivLen, a)
	a.creater = &aesAEADCreater{key}
	return a, nil
}

type chacha20poly1305AEADCreater struct {
	key []byte
}

func (c *chacha20poly1305AEADCreater) NewAEAD(iv []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(aeadKey(c.key, iv))
}

func NewChacha20Poly1305Decrypter(key []byte, ivLen int) (CipherStream, error) {
	a := new(AEADDecryptCipherStream)
	a.initDecrypter(ivLen, a)
	a.creater = &chacha20poly1305AEADCreater{key}
	return a, nil
}

var zeroBuf [1024]byte

func EnsureCopy(dst, src []byte) []byte {
	if len(src) > len(dst) {
		dst = make([]byte, len(src))
	}

	copy(dst, src)

	if len(src) < len(dst) {
		dst = dst[:len(src)]
	}

	return dst
}

type CipherBlock interface {
	Encrypt(dst, src []byte) (ciphertext []byte, iv []byte, err error)

	Decrypt(dst, src []byte) (plaintext []byte, iv []byte, err error)
}

type PlainCipherBlock struct {
}

func (p *PlainCipherBlock) Encrypt(dst, src []byte) ([]byte, []byte, error) {
	return EnsureCopy(dst, src), nil, nil
}

func (p *PlainCipherBlock) Decrypt(dst, src []byte) ([]byte, []byte, error) {
	return EnsureCopy(dst, src), nil, nil
}

type AEADCipherBlock struct {
	creater aeadCreater
	ivlen   int
}

func (a *AEADCipherBlock) Decrypt(dst, src []byte) (plaintext []byte, iv []byte, err error) {
	if len(src) < a.ivlen {
		err = io.ErrShortBuffer
		return
	}

	iv = src[:a.ivlen]
	src = src[a.ivlen:]

	aead, err := a.creater.NewAEAD(iv)
	if err != nil {
		return
	}

	if len(src) < aead.Overhead() {
		err = io.ErrShortBuffer
		return
	}

	plaintext, err = aead.Open(dst[:0], zeroBuf[:aead.NonceSize()], src, nil)
	return
}

func (a *AEADCipherBlock) Encrypt(dst, src []byte) (ciphertext []byte, iv []byte, err error) {
	if len(dst) < a.ivlen {
		dst = make([]byte, a.ivlen, a.ivlen+len(src)+128)
	}

	PutRandomBytes(dst[:a.ivlen])
	iv = dst[:a.ivlen]

	aead, err := a.creater.NewAEAD(iv)
	if err != nil {
		return
	}

	b2 := aead.Seal(dst[a.ivlen:a.ivlen], zeroBuf[:aead.NonceSize()], src, nil)
	ciphertext = dst[:a.ivlen+len(b2)]
	return
}

func NewAESGCMCipherBlock(key []byte, ivlen int) (CipherBlock, error) {
	return &AEADCipherBlock{
		creater: &aesAEADCreater{key},
		ivlen:   ivlen,
	}, nil
}

func NewChaCha20Poly1305CipherBlock(key []byte, ivlen int) (CipherBlock, error) {
	return &AEADCipherBlock{
		creater: &chacha20poly1305AEADCreater{key},
		ivlen:   ivlen,
	}, nil
}

func NewPlainCipherBlock([]byte, int) (CipherBlock, error) {
	return &PlainCipherBlock{}, nil
}

func NewCipherBlock(method, password string) (cb CipherBlock, err error) {
	if password == "" && method != "plain" {
		err = fmt.Errorf("password cannot be empty")
		return
	}

	m, ok := cipherMethod[method]
	if !ok {
		m, _ = cipherMethod[defaultMethod]
	}

	key := kdf(password, m.keylen)
	cb, err = m.newCipherBlock(key, m.ivlen)
	return
}
