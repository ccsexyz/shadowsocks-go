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
	"golang.org/x/crypto/salsa20/salsa"

	"crypto/rc4"

	"github.com/aead/chacha20"
	"github.com/aead/chacha20/chacha"
)

const CipherBlockLen = 8192
const aeadSizeMask = 0x3FFF

type CipherBlock struct {
	b [CipherBlockLen]byte
}

var cipherBlockPool = sync.Pool{
	New: func() interface{} {
		return &CipherBlock{}
	},
}

func GetCipherBlock() *CipherBlock {
	return cipherBlockPool.Get().(*CipherBlock)
}

func PutCipherBlock(b *CipherBlock) {
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
		if len(p2) > CipherBlockLen {
			p2 = p2[:CipherBlockLen]
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

type Salsa20CipherStream struct {
	baseCipherStream

	key     [32]byte
	counter uint64
}

func (s *Salsa20CipherStream) writeData(p []byte) (n int, err error) {
	var ivb [16]byte
	copy(ivb[:8], s.iv[:8])
	binary.LittleEndian.PutUint64(ivb[8:], s.counter/64)

	padLen := int(s.counter % 64)
	if padLen == 0 {
		b := GetCipherBlock()
		defer PutCipherBlock(b)
		dst := b.b[:len(p)]

		salsa.XORKeyStream(dst, p, &ivb, &s.key)
		s.counter += uint64(len(p))
		n, err = s.b.Write(dst)
		return
	}

	var srcbuf [64]byte
	var dstbuf [64]byte
	n = copy(srcbuf[padLen:], p)
	salsa.XORKeyStream(dstbuf[:], srcbuf[:], &ivb, &s.key)
	s.counter += uint64(n)

	n, err = s.b.Write(dstbuf[padLen : padLen+n])
	if err != nil {
		return
	}

	if len(p) > n {
		var n2 int
		n2, err = s.writeData(p[n:])
		if err != nil {
			return
		}
		n += n2
	}

	return
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

type streamCreater interface {
	NewStream(iv []byte) (cipher.Stream, error)
}

type XORCipherStream struct {
	baseCipherStream
	stream  cipher.Stream
	creater streamCreater
}

func (x *XORCipherStream) writeData(p []byte) (n int, err error) {
	b := GetCipherBlock()
	defer PutCipherBlock(b)

	if x.stream == nil {
		if x.creater == nil {
			panic("creater is nil")
		}

		x.stream, err = x.creater.NewStream(x.iv)
		if err != nil {
			return
		}
	}

	dst := b.b[:len(p)]
	x.stream.XORKeyStream(dst, p)
	n, err = x.b.Write(dst)
	return
}

func newEncryptXORCipherStream(iv []byte, stream cipher.Stream) *XORCipherStream {
	x := new(XORCipherStream)
	x.initEncrypter(iv, x)
	x.stream = stream
	return x
}

func newDecryptXORCipherStream(ivLen int, creater streamCreater) *XORCipherStream {
	x := new(XORCipherStream)
	x.initDecrypter(ivLen, x)
	x.creater = creater
	return x
}

func NewAESCFBEncrypter(key, iv []byte) (rw CipherStream, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	rw = newEncryptXORCipherStream(iv, cipher.NewCFBEncrypter(block, iv))
	return
}

func NewChaCha20Encrypter(key, iv []byte) (rw CipherStream, err error) {
	stream, err := chacha20.NewCipher(iv, key)
	if err != nil {
		return
	}

	rw = newEncryptXORCipherStream(iv, stream)
	return
}

func NewAESCTREncrypter(key, iv []byte) (rw CipherStream, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	rw = newEncryptXORCipherStream(iv, cipher.NewCTR(block, iv))
	return
}

func NewRC4MD5Encrypter(key, iv []byte) (rw CipherStream, err error) {
	stream, err := newRC4MD5Stream(key, iv)
	if err != nil {
		return
	}

	rw = newEncryptXORCipherStream(iv, stream)
	return
}

type blockStreamCreater struct {
	block  cipher.Block
	create func(cipher.Block, []byte) cipher.Stream
}

func (b *blockStreamCreater) NewStream(iv []byte) (cipher.Stream, error) {
	return b.create(b.block, iv), nil
}

func NewAESCFBDecrypter(key []byte, ivLen int) (rw CipherStream, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	rw = newDecryptXORCipherStream(ivLen, &blockStreamCreater{block, cipher.NewCFBDecrypter})
	return
}

type chacha20StreamCreater struct {
	key []byte
}

func (c *chacha20StreamCreater) NewStream(iv []byte) (cipher.Stream, error) {
	return chacha20.NewCipher(iv, c.key)
}

func NewChaCha20Decrypter(key []byte, ivLen int) (rw CipherStream, err error) {
	rw = newDecryptXORCipherStream(ivLen, &chacha20StreamCreater{key: CopyBuffer(key)})
	return
}

func NewAESCTRDecrypter(key []byte, ivLen int) (rw CipherStream, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	rw = newDecryptXORCipherStream(ivLen, &blockStreamCreater{block, cipher.NewCTR})
	return
}

type rc4md5StreamCreater struct {
	key []byte
}

func (r *rc4md5StreamCreater) NewStream(iv []byte) (cipher.Stream, error) {
	return newRC4MD5Stream(r.key, iv)
}

func NewRC4MD5Decrypter(key []byte, ivLen int) (rw CipherStream, err error) {
	rw = newDecryptXORCipherStream(ivLen, &rc4md5StreamCreater{key: CopyBuffer(key)})
	return
}

func newRC4MD5Stream(key, iv []byte) (cipher.Stream, error) {
	m := md5.New()
	m.Write(key)
	m.Write(iv)
	return rc4.NewCipher(m.Sum(nil))
}

func NewPlainEncrypter(_, _ []byte) (CipherStream, error) {
	return &PlainCipherStream{}, nil
}

func NewPlainDecrypter(_ []byte, _ int) (CipherStream, error) {
	return &PlainCipherStream{}, nil
}

func NewSalsa20Encrypter(key, iv []byte) (CipherStream, error) {
	s := new(Salsa20CipherStream)
	copy(s.key[:], key)
	s.initEncrypter(iv, s)
	return s, nil
}

func NewSalsa20Decrypter(key []byte, ivLen int) (CipherStream, error) {
	s := new(Salsa20CipherStream)
	copy(s.key[:], key)
	s.initDecrypter(ivLen, s)
	return s, nil
}

var cipherMethod = map[string]struct {
	keylen       int
	ivlen        int
	newEncrypter func(key, iv []byte) (CipherStream, error)
	newDecrypter func(key []byte, ivLen int) (CipherStream, error)
}{
	"aes-128-gcm":      {16, 16, NewAESGCMEncrypter, NewAESGCMDecrypter},
	"aes-192-gcm":      {24, 24, NewAESGCMEncrypter, NewAESGCMDecrypter},
	"aes-256-gcm":      {32, 32, NewAESGCMEncrypter, NewAESGCMDecrypter},
	"aes-128-ctr":      {16, 16, NewAESCTREncrypter, NewAESCTRDecrypter},
	"aes-192-ctr":      {24, 16, NewAESCTREncrypter, NewAESCTRDecrypter},
	"aes-256-ctr":      {32, 16, NewAESCTREncrypter, NewAESCTRDecrypter},
	"aes-128-cfb":      {16, 16, NewAESCFBEncrypter, NewAESCFBDecrypter},
	"aes-192-cfb":      {24, 16, NewAESCFBEncrypter, NewAESCFBDecrypter},
	"aes-256-cfb":      {32, 16, NewAESCFBEncrypter, NewAESCFBDecrypter},
	"chacha20":         {32, 8, NewChaCha20Encrypter, NewChaCha20Decrypter},
	"chacha20-ietf":    {32, 12, NewChaCha20Encrypter, NewChaCha20Decrypter},
	"chacha20poly1305": {32, 32, NewChacha20Poly1305Encrypter, NewChacha20Poly1305Decrypter},
	"rc4-md5":          {16, 16, NewRC4MD5Encrypter, NewRC4MD5Decrypter},
	"salsa20":          {32, 8, NewSalsa20Encrypter, NewSalsa20Decrypter},
	"plain":            {0, 0, NewPlainEncrypter, NewPlainDecrypter},
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
	b := GetCipherBlock()
	defer PutCipherBlock(b)
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

	b := GetCipherBlock()
	defer PutCipherBlock(b)

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
	if expected > CipherBlockLen {
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
