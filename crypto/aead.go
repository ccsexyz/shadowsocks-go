package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type ssAEADNonce [32]byte

func (s *ssAEADNonce) increment() {
	for i := range s {
		s[i]++
		if s[i] != 0 {
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
