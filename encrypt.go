package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"fmt"

	"github.com/Yawning/chacha20"
)

type Encrypter interface {
	Encrypt(dst, src []byte)
	GetIV() []byte
}

type Decrypter interface {
	Decrypt(dst, src []byte)
	// SetIV([]byte)
}

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

type BaseEncrypter struct {
	iv []byte
}

func (e *BaseEncrypter) GetIV() []byte {
	return e.iv
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
	BaseEncrypter
	BaseStreamCipher
}

func NewAESCFBEncrypter(key, iv []byte) (enc Encrypter, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	enc = &StreamEncrypter{
		BaseEncrypter:    BaseEncrypter{iv: iv},
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
		BaseEncrypter:    BaseEncrypter{iv: iv},
		BaseStreamCipher: BaseStreamCipher{stream: stream},
	}
	return
}

type StreamDecrypter struct {
	BaseStreamCipher
}

func NewAESCFBDecrypter(key, iv []byte) (dec Decrypter, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	dec = &StreamDecrypter{
		BaseStreamCipher: BaseStreamCipher{stream: cipher.NewCFBDecrypter(block, iv)},
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
	}
	return
}

var cipherMethod = map[string]struct {
	keylen       int
	ivlen        int
	newEncrypter func(key, iv []byte) (enc Encrypter, err error)
	newDecrypter func(key, iv []byte) (dec Decrypter, err error)
}{
	"aes-128-cfb": {16, 16, NewAESCFBEncrypter, NewAESCFBDecrypter},
	"aes-192-cfb": {24, 16, NewAESCFBEncrypter, NewAESCFBDecrypter},
	"aes-256-cfb": {32, 16, NewAESCFBEncrypter, NewAESCFBDecrypter},
	"chacha20":    {32, 8, NewChaCha20Encrypter, NewChaCha20Decrypter},
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
	enc, err = m.newEncrypter(kdf(password, m.keylen), getRandBytes(m.ivlen))
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
	dec, err = m.newDecrypter(kdf(password, m.keylen), iv)
	return
}

func getIvLen(method string) int {
	m, ok := cipherMethod[method]
	if ok {
		return m.ivlen
	}
	return cipherMethod[defaultMethod].ivlen
}
