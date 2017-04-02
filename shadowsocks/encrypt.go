package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"fmt"

	"crypto/rc4"

	"github.com/Yawning/chacha20"
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
	"plain":         {0, 0, NewPlainEncrypter, NewPlainDecrypter},
}

func NewEncrypter(method, password string) (enc Encrypter, err error) {
	if password == "" {
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
	if password == "" {
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
