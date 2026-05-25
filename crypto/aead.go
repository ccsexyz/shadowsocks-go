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

	bufs := make([][]byte, 0, len(p)/aeadSizeMask+1)
	for len(p) > 0 {
		if len(p) > aeadSizeMask {
			bufs = append(bufs, p[:aeadSizeMask])
			p = p[aeadSizeMask:]
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

func (a *AEADDecryptCipherStream) ReadFrame(buf []byte) ([]byte, error) {
	if a.pb.Len() > 0 {
		n := a.pb.Len()
		var out []byte
		if cap(buf) >= n {
			out = buf[:n]
		} else {
			out = make([]byte, n)
		}
		m, _ := a.pb.Read(out)
		if m == 0 {
			return nil, io.EOF
		}
		return out[:m], nil
	}

	if a.crypt.AEAD == nil {
		if len(a.iv) < a.ivLen {
			return nil, io.EOF
		}
		if a.creater == nil {
			return nil, fmt.Errorf("creater is nil")
		}
		var err error
		a.crypt.AEAD, err = a.creater.NewAEAD(a.iv)
		if err != nil {
			return nil, err
		}
	}

	if a.b.Len() == 0 {
		return nil, io.EOF
	}

	overhead := a.crypt.Overhead()
	var tagBuf [22]byte // overhead (max 16) + 2
	tag := tagBuf[:overhead+2]
	var dst []byte
	if cap(buf) >= a.b.Len() {
		dst = buf[:0]
	} else {
		dst = make([]byte, 0, a.b.Len())
	}
	offset := 0

	for {
		if a.tagLen == 0 {
			need := overhead + 2
			if a.b.Len() < need {
				break
			}
			io.ReadFull(&a.b, tag[:need])
			if err := a.crypt.Decrypt(tag[:need], tag[:need]); err != nil {
				return nil, fmt.Errorf("decrypt tag fail: %w", err)
			}
			a.tagLen = int(binary.BigEndian.Uint16(tag[:2]) & aeadSizeMask)
		}

		expected := a.tagLen + overhead
		if a.b.Len() < expected {
			break
		}

		if offset+a.tagLen > cap(dst) {
			bigger := make([]byte, offset+a.b.Len())
			copy(bigger, dst[:offset])
			dst = bigger
		}
		dst = dst[:offset+a.tagLen]

		blk := getCipherMemBlock()
		data := blk.b[:expected]
		io.ReadFull(&a.b, data)
		err := a.crypt.Decrypt(data, data)
		if err != nil {
			putCipherMemBlock(blk)
			return nil, fmt.Errorf("decrypt data fail: %w", err)
		}
		copy(dst[offset:], data[:a.tagLen])
		putCipherMemBlock(blk)
		offset += a.tagLen
		a.tagLen = 0
	}

	if offset == 0 {
		return nil, io.EOF
	}
	return dst[:offset], nil
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
