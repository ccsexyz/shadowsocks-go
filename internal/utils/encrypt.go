package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"sync"

	"golang.org/x/crypto/salsa20/salsa"

	"crypto/rc4"

	"github.com/aead/chacha20"
	"github.com/aead/chacha20/chacha"
)

type IV struct {
	iv []byte
}

func (iv *IV) GetIV() []byte {
	return iv.iv
}

type Encrypter interface {
	Encrypt(dst, src []byte)
	GetIV() []byte
}

type Decrypter interface {
	Decrypt(dst, src []byte)
	GetIV() []byte
}

type PlainEncDecrypter struct{}

func (p *PlainEncDecrypter) GetIV() (iv []byte) {
	return
}

func (p *PlainEncDecrypter) Encrypt(dst, src []byte) {
	copy(dst, src)
}

func (p *PlainEncDecrypter) Decrypt(dst, src []byte) {
	copy(dst, src)
}

type Salsa20EncDecrypter struct {
	iv      []byte
	key     [32]byte
	counter uint64
}

func (s *Salsa20EncDecrypter) GetIV() []byte {
	return s.iv
}

func (s *Salsa20EncDecrypter) Encrypt(dst, src []byte) {
	s.XORKeyStream(dst, src)
}

func (s *Salsa20EncDecrypter) Decrypt(dst, src []byte) {
	s.XORKeyStream(dst, src)
}

func (s *Salsa20EncDecrypter) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	var b [16]byte
	copy(b[:8], s.iv[:8])
	binary.LittleEndian.PutUint64(b[8:], s.counter/64)
	padLen := int(s.counter % 64)
	if padLen == 0 {
		salsa.XORKeyStream(dst, src, &b, &s.key)
		s.counter += uint64(len(src))
		return
	}
	var srcbuf [64]byte
	var dstbuf [64]byte
	n := copy(srcbuf[padLen:], src)
	salsa.XORKeyStream(dstbuf[:], srcbuf[:], &b, &s.key)
	copy(dst[:n], dstbuf[padLen:])
	s.counter += uint64(n)
	s.XORKeyStream(dst[n:], src[n:])
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

type BaseStreamCipher struct {
	stream cipher.Stream
}

func (c *BaseStreamCipher) Encrypt(dst, src []byte) {
	c.stream.XORKeyStream(dst, src)
}

func (c *BaseStreamCipher) Decrypt(dst, src []byte) {
	c.stream.XORKeyStream(dst, src)
}

type StreamEncrypter struct {
	IV
	BaseStreamCipher
}

func NewAESCFBEncrypter(key, iv []byte) (enc Encrypter, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	enc = &StreamEncrypter{
		IV:               IV{iv: iv},
		BaseStreamCipher: BaseStreamCipher{stream: cipher.NewCFBEncrypter(block, iv)},
	}
	return
}

func NewChaCha20Encrypter(key, iv []byte) (enc Encrypter, err error) {
	stream, err := chacha20.NewCipher(key, iv)
	if err != nil {
		return
	}
	enc = &StreamEncrypter{
		IV:               IV{iv: iv},
		BaseStreamCipher: BaseStreamCipher{stream: stream},
	}
	return
}

func NewAESCTREncrypter(key, iv []byte) (enc Encrypter, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	enc = &StreamEncrypter{
		IV:               IV{iv: iv},
		BaseStreamCipher: BaseStreamCipher{stream: cipher.NewCTR(block, iv)},
	}
	return
}

func NewRC4MD5Encrypter(key, iv []byte) (enc Encrypter, err error) {
	stream, err := newRC4MD5Stream(key, iv)
	if err != nil {
		return
	}
	enc = &StreamEncrypter{
		IV:               IV{iv: iv},
		BaseStreamCipher: BaseStreamCipher{stream: stream},
	}
	return
}

type StreamDecrypter struct {
	IV
	BaseStreamCipher
}

func NewAESCFBDecrypter(key, iv []byte) (dec Decrypter, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	dec = &StreamDecrypter{
		BaseStreamCipher: BaseStreamCipher{stream: cipher.NewCFBDecrypter(block, iv)},
		IV:               IV{iv: iv},
	}
	return
}

func NewChaCha20Decrypter(key, iv []byte) (dec Decrypter, err error) {
	stream, err := chacha20.NewCipher(key, iv)
	if err != nil {
		return
	}
	dec = &StreamDecrypter{
		BaseStreamCipher: BaseStreamCipher{stream: stream},
		IV:               IV{iv: iv},
	}
	return
}

func NewAESCTRDecrypter(key, iv []byte) (dec Decrypter, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	dec = &StreamDecrypter{
		BaseStreamCipher: BaseStreamCipher{stream: cipher.NewCTR(block, iv)},
		IV:               IV{iv: iv},
	}
	return
}

func NewRC4MD5Decrypter(key, iv []byte) (dec Decrypter, err error) {
	stream, err := newRC4MD5Stream(key, iv)
	if err != nil {
		return
	}
	dec = &StreamDecrypter{
		BaseStreamCipher: BaseStreamCipher{stream: stream},
		IV:               IV{iv: iv},
	}
	return
}

func newRC4MD5Stream(key, iv []byte) (cipher.Stream, error) {
	m := md5.New()
	m.Write(key)
	m.Write(iv)
	return rc4.NewCipher(m.Sum(nil))
}

func NewPlainEncrypter(_, _ []byte) (Encrypter, error) {
	return &PlainEncDecrypter{}, nil
}

func NewPlainDecrypter(_, _ []byte) (Decrypter, error) {
	return &PlainEncDecrypter{}, nil
}

func NewSalsa20EncDecrypter(key, iv []byte) (*Salsa20EncDecrypter, error) {
	var s Salsa20EncDecrypter
	s.counter = 0
	s.iv = iv
	copy(s.key[:], key)
	return &s, nil
}

func NewSalsa20Encrypter(key, iv []byte) (Encrypter, error) {
	return NewSalsa20EncDecrypter(key, iv)
}

func NewSalsa20Decrypter(key, iv []byte) (Decrypter, error) {
	return NewSalsa20EncDecrypter(key, iv)
}

var cipherMethod = map[string]struct {
	keylen       int
	ivlen        int
	newEncrypter func(key, iv []byte) (enc Encrypter, err error)
	newDecrypter func(key, iv []byte) (dec Decrypter, err error)
}{
	"aes-128-ctr":   {16, 16, NewAESCTREncrypter, NewAESCTRDecrypter},
	"aes-192-ctr":   {24, 16, NewAESCTREncrypter, NewAESCTRDecrypter},
	"aes-256-ctr":   {32, 16, NewAESCTREncrypter, NewAESCTRDecrypter},
	"aes-128-cfb":   {16, 16, NewAESCFBEncrypter, NewAESCFBDecrypter},
	"aes-192-cfb":   {24, 16, NewAESCFBEncrypter, NewAESCFBDecrypter},
	"aes-256-cfb":   {32, 16, NewAESCFBEncrypter, NewAESCFBDecrypter},
	"chacha20":      {32, 8, NewChaCha20Encrypter, NewChaCha20Decrypter},
	"chacha20-ietf": {32, 12, NewChaCha20Encrypter, NewChaCha20Decrypter},
	"rc4-md5":       {16, 16, NewRC4MD5Encrypter, NewRC4MD5Decrypter},
	"salsa20":       {32, 8, NewSalsa20Encrypter, NewSalsa20Decrypter},
	"plain":         {0, 0, NewPlainEncrypter, NewPlainDecrypter},
}

func NewEncrypter(method, password string) (enc Encrypter, err error) {
	if password == "" && method != "plain" {
		err = fmt.Errorf("password cannot be empty")
		return
	}
	m, ok := cipherMethod[method]
	if !ok {
		m, _ = cipherMethod[defaultMethod]
	}
	enc, err = m.newEncrypter(kdf(password, m.keylen), GetRandomBytes(m.ivlen))
	return
}

func NewDecrypter(method, password string, iv []byte) (dec Decrypter, err error) {
	if password == "" && method != "plain" {
		err = fmt.Errorf("password cannot be empty")
		return
	}
	m, ok := cipherMethod[method]
	if !ok {
		m, _ = cipherMethod[defaultMethod]
	}
	iv2 := make([]byte, len(iv))
	copy(iv2, iv)
	dec, err = m.newDecrypter(kdf(password, m.keylen), iv2)
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

type chacha20BlockCrypt struct {
	cipherPool sync.Pool
}

func NewChaCha20BlockCrypt(key []byte) (*chacha20BlockCrypt, error) {
	if _, err := chacha.NewCipher(initialVector[:8], key, 20); err != nil {
		return nil, err
	}

	c := new(chacha20BlockCrypt)

	c.cipherPool.New = func() interface{} {
		ciph, _ := chacha.NewCipher(initialVector[:8], key, 20)
		return ciph
	}

	return c, nil
}

func (c *chacha20BlockCrypt) Encrypt(dst, src []byte) {
	enc := c.cipherPool.Get().(*chacha.Cipher)
	defer c.cipherPool.Put(enc)
	enc.SetCounter(binary.LittleEndian.Uint64(src[:8]))
	enc.XORKeyStream(dst[8:], src[8:])
	copy(dst[:8], src[:8])
}
func (c *chacha20BlockCrypt) Decrypt(dst, src []byte) {
	dec := c.cipherPool.Get().(*chacha.Cipher)
	defer c.cipherPool.Put(dec)
	dec.SetCounter(binary.LittleEndian.Uint64(src[:8]))
	dec.XORKeyStream(dst[8:], src[8:])
	copy(dst[:8], src[:8])
}
