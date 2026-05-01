package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

var zeroBuf [1024]byte

const aead2022SubkeyInfo = "shadowsocks 2022 session subkey"

type CipherBlock interface {
	Encrypt(dst, src []byte) (ciphertext []byte, iv []byte, err error)
	Decrypt(dst, src []byte) (plaintext []byte, iv []byte, err error)
}

type PlainCipherBlock struct{}

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
		err = io.EOF
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
		cb, err = m.newCipherBlock(psk, m.ivlen)
		return
	}
	key := kdf(password, m.keylen)
	cb, err = m.newCipherBlock(key, m.ivlen)
	return
}

// AEAD-2022

func kdf2022(psk, salt []byte, keyLen int) []byte {
	material := make([]byte, len(psk)+len(salt))
	copy(material, psk)
	copy(material[len(psk):], salt)
	subKey := make([]byte, keyLen)
	blake3.DeriveKey(subKey, aead2022SubkeyInfo, material)
	return subKey
}

func DecodePSK(password string, keyLen int) ([]byte, error) {
	psk, err := base64.StdEncoding.DecodeString(password)
	if err == nil && len(psk) == keyLen {
		return psk, nil
	}
	psk2 := []byte(password)
	if len(psk2) == keyLen {
		return psk2, nil
	}
	if err == nil {
		return nil, errInvalidKeyLength
	}
	return nil, errInvalidKeyLength
}

type TcpCipher2022 struct {
	aead  cipher.AEAD
	nlen  int
	nonce [24]byte
}

func NewTcpCipher2022(method string, psk, salt []byte) (*TcpCipher2022, error) {
	sessionKey := kdf2022(psk, salt, len(psk))
	var aead cipher.AEAD
	switch method {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		block, err := aes.NewCipher(sessionKey)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case "2022-blake3-chacha20-poly1305":
		var err error
		aead, err = chacha20poly1305.New(sessionKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errInvalidMethod
	}
	return &TcpCipher2022{
		aead: aead,
		nlen: aead.NonceSize(),
	}, nil
}

func (c *TcpCipher2022) increaseNonce() {
	for i := 0; i < c.nlen; i++ {
		c.nonce[i]++
		if c.nonce[i] != 0 {
			return
		}
	}
}

func (c *TcpCipher2022) EncryptPacket(plaintext []byte) []byte {
	result := c.aead.Seal(plaintext[:0], c.nonce[:c.nlen], plaintext, nil)
	c.increaseNonce()
	return result
}

func (c *TcpCipher2022) DecryptPacket(ciphertext []byte) ([]byte, bool) {
	result, err := c.aead.Open(ciphertext[:0], c.nonce[:c.nlen], ciphertext, nil)
	if err != nil {
		return nil, false
	}
	c.increaseNonce()
	return result, true
}

func (c *TcpCipher2022) Overhead() int {
	return c.aead.Overhead()
}
