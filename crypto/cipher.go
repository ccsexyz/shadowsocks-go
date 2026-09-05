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

const cipherBlockLen = 65536
const aeadSizeMask = 0x3FFF

type cipherMemBlock struct {
	b [cipherBlockLen]byte
}

var cipherBlockPool = sync.Pool{
	New: func() any {
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
	WriteFrame(data []byte) error
	ReadFrame(buf []byte) ([]byte, error)
	// WriteEncryptedTo writes any buffered encrypted data directly to w.
	WriteEncryptedTo(w io.Writer) (int64, error)
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

func (p *PlainCipherStream) WriteFrame(data []byte) error {
	_, err := p.b.Write(data)
	return err
}

func (p *PlainCipherStream) ReadFrame(buf []byte) ([]byte, error) {
	if p.b.Len() == 0 {
		return nil, io.EOF
	}
	n := p.b.Len()
	var out []byte
	if cap(buf) >= n {
		out = buf[:n]
	} else {
		out = make([]byte, n)
	}
	m, _ := p.b.Read(out)
	if m == 0 {
		return nil, io.EOF
	}
	return out[:m], nil
}

func (p *PlainCipherStream) WriteEncryptedTo(w io.Writer) (int64, error) {
	return writeBufferTo(&p.b, w)
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
	b.iv = make([]byte, 0, ivLen)
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

	// Pre-grow buffer to avoid repeated growSlice during encrypted writes.
	// Each 1024-byte AEAD chunk adds 2+2*overhead framing bytes.
	const estChunkSize = 1024
	numChunks := (len(p) + estChunkSize - 1) / estChunkSize
	if numChunks == 0 {
		numChunks = 1
	}
	if b.isEnc {
		extra := numChunks * 50 // generous estimate for per-chunk framing overhead
		b.b.Grow(len(p) + extra)
	} else {
		b.b.Grow(len(p))
	}

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

func (b *baseCipherStream) WriteFrame(data []byte) error {
	n1, err := b.writeIV(data)
	if err != nil {
		return err
	}
	data = data[n1:]
	if len(data) == 0 {
		return nil
	}
	numChunks := (len(data) + cipherBlockLen - 1) / cipherBlockLen
	if b.isEnc {
		b.b.Grow(len(data) + numChunks*50)
	} else {
		b.b.Grow(len(data))
	}
	for len(data) > 0 {
		p2 := data
		if len(p2) > cipherBlockLen {
			p2 = p2[:cipherBlockLen]
		}
		data = data[len(p2):]
		if _, err := b.dw.writeData(p2); err != nil {
			return err
		}
	}
	return nil
}

func (b *baseCipherStream) ReadFrame(buf []byte) ([]byte, error) {
	if b.b.Len() == 0 {
		return nil, io.EOF
	}
	n := b.b.Len()
	var out []byte
	if cap(buf) >= n {
		out = buf[:n]
	} else {
		out = make([]byte, n)
	}
	m, _ := b.b.Read(out)
	if m == 0 {
		return nil, io.EOF
	}
	return out[:m], nil
}

func (b *baseCipherStream) WriteEncryptedTo(w io.Writer) (int64, error) {
	return writeBufferTo(&b.b, w)
}

// writeBufferTo writes all data from buf to w without an intermediate scratch buffer.
// It handles partial writes correctly by using Bytes() to peek and Next() to consume.
func writeBufferTo(buf *bytes.Buffer, w io.Writer) (int64, error) {
	total := int64(0)
	for buf.Len() > 0 {
		data := buf.Bytes()
		n, err := w.Write(data)
		if n > 0 {
			buf.Next(n)
			total += int64(n)
		} else if err == nil {
			return total, io.ErrUnexpectedEOF
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (b *baseCipherStream) GetIV() []byte {
	if b.iv == nil {
		return []byte{}
	}
	return b.iv
}

var kdfCache sync.Map // map[string][]byte: "password:keyLen" → master key

func kdf(password string, keyLen int) []byte {
	cacheKey := fmt.Sprintf("%s:%d", password, keyLen)
	if v, ok := kdfCache.Load(cacheKey); ok {
		// Return a copy so callers can't mutate the cached value
		return append([]byte{}, v.([]byte)...)
	}

	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	result := b[:keyLen]
	kdfCache.Store(cacheKey, append([]byte{}, result...))
	return result
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
	"aes-128-gcm":                   {16, 16, NewAESGCMEncrypter, NewAESGCMDecrypter, NewAESGCMCipherBlock, false},
	"aes-192-gcm":                   {24, 24, NewAESGCMEncrypter, NewAESGCMDecrypter, NewAESGCMCipherBlock, false},
	"aes-256-gcm":                   {32, 32, NewAESGCMEncrypter, NewAESGCMDecrypter, NewAESGCMCipherBlock, false},
	"chacha20-ietf-poly1305":        {32, 32, NewChacha20Poly1305Encrypter, NewChacha20Poly1305Decrypter, NewChaCha20Poly1305CipherBlock, false},
	"chacha20-poly1305":             {32, 32, NewChacha20Poly1305Encrypter, NewChacha20Poly1305Decrypter, NewChaCha20Poly1305CipherBlock, false},
	"chacha20poly1305":              {32, 32, NewChacha20Poly1305Encrypter, NewChacha20Poly1305Decrypter, NewChaCha20Poly1305CipherBlock, false},
	"plain":                         {0, 0, NewPlainEncrypter, NewPlainDecrypter, NewPlainCipherBlock, false},
	"2022-blake3-aes-128-gcm":       {16, 16, newNotSupportedEncrypter, newNotSupportedDecrypter, newUdp2022AESCipherBlock, true},
	"2022-blake3-aes-256-gcm":       {32, 32, newNotSupportedEncrypter, newNotSupportedDecrypter, newUdp2022AESCipherBlock, true},
	"2022-blake3-chacha20-poly1305": {32, 32, newNotSupportedEncrypter, newNotSupportedDecrypter, newUdp2022ChaChaCipherBlock, true},
}

func IsAEAD(method string) bool {
	switch method {
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
		"chacha20-ietf-poly1305", "chacha20-poly1305", "chacha20poly1305",
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

// HasMethod reports whether method is a known cipher method name.
// "socks5" is a client-only pseudo method handled outside this package.
func HasMethod(method string) bool {
	_, ok := cipherMethod[method]
	return ok
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
		err = errInvalidMethod
		return
	}
	if m.is2022 {
		// 2022 methods do not support the CipherStream API; use TcpCipher2022.
		err = errInvalidMethod
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
		err = errInvalidMethod
		return
	}
	if m.is2022 {
		// 2022 methods do not support the CipherStream API; use TcpCipher2022.
		err = errInvalidMethod
		return
	}
	dec, err = m.newDecrypter(kdf(password, m.keylen), m.ivlen)
	return
}
