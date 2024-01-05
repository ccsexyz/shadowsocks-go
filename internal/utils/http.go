package utils

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
)

const (
	parsingFirstLine1   = iota
	parsingFirstLine2   = iota
	parsingFirstLine3   = iota
	parsingHeadersKey   = iota
	parsingHeadersValue = iota

	httpBufLen = 4096
)

var (
	httpMethods = map[string]bool{
		"GET":     true,
		"POST":    true,
		"OPTIONS": true,
		"HEAD":    true,
		"PUT":     true,
		"DELETE":  true,
		"CONNECT": true,
		"TRACE":   true,
		"PATCH":   true,
	}

	errInvalidChar   = fmt.Errorf("Invalid character")
	errInvalidHeader = fmt.Errorf("Invalid HTTP Header")
	errInsuffBuffer  = fmt.Errorf("Insufficient buffer")
)

// IsValidHTTPMethod indicates whether m is a valid http method
func IsValidHTTPMethod(m string) bool {
	_, ok := httpMethods[m]
	return ok
}

type littleSlice struct {
	index  int
	length int
}

func (s *littleSlice) valid() bool {
	return s.length > 0 && s.index >= 0
}

func (s *littleSlice) eat(i int) {
	if s.length == 0 {
		s.index = i
		s.length = 1
	} else {
		s.length = i - s.index + 1
	}
}

func (s *littleSlice) reset() {
	s.index = 0
	s.length = 0
}

type httpKV struct {
	key   littleSlice
	value littleSlice
}

// NewHTTPHeaderParser new a http parser
func NewHTTPHeaderParser(buf []byte) *HTTPHeaderParser {
	return &HTTPHeaderParser{
		buf:          buf,
		parserStatus: parsingFirstLine1,
		headersKV:    make([]httpKV, 0, 16),
	}
}

// HTTPHeaderParser is a parser for http request and reply header
type HTTPHeaderParser struct {
	buf      []byte
	bufSlice littleSlice

	parserStatus int
	headerLength int

	firstLine1Slice littleSlice
	firstLine2Slice littleSlice
	firstLine3Slice littleSlice

	parsingKeySlice   littleSlice
	parsingValueSlice littleSlice

	headersKV []httpKV
	ok        bool
}

func (p *HTTPHeaderParser) Ok() bool {
	return p.ok
}

// Reset reset the state of http header parser
func (p *HTTPHeaderParser) Reset() {
	p.bufSlice.reset()
	p.parserStatus = parsingFirstLine1
	p.firstLine1Slice.reset()
	p.firstLine2Slice.reset()
	p.firstLine3Slice.reset()
	p.parsingKeySlice.reset()
	p.parsingValueSlice.reset()
	if len(p.headersKV) > 0 {
		p.headersKV = p.headersKV[:0]
	}
}

func isValidChar(b byte) bool {
	if (b > 31 && b < 127) || isCR(b) || isEnter(b) {
		return true
	}
	return false
}

func isSpace(b byte) bool {
	if b == ' ' {
		return true
	}
	return false
}

func isCR(b byte) bool {
	if b == '\r' {
		return true
	}
	return false
}

func isEnter(b byte) bool {
	if b == '\n' {
		return true
	}
	return false
}

func isColon(b byte) bool {
	if b == ':' {
		return true
	}
	return false
}

// Read scan the bytes in buffer, ok == true if read a full http-header,
// err != nil if error occurs
func (p *HTTPHeaderParser) Read(b []byte) (ok bool, err error) {
	if len(p.buf) == 0 {
		p.buf = make([]byte, httpBufLen)
	}

	ok = false
	err = errInvalidHeader
	defer func() {
		if !p.ok && ok {
			p.ok = true
		}
	}()

	bufslice := &p.bufSlice
	buf := p.buf
	n := copy(buf[bufslice.length:], b)

	if n < len(b) {
		err = errInsuffBuffer
		return
	}

	for ; n > 0; n-- {
		it := bufslice.length
		c := buf[it]
		if !isValidChar(c) {
			err = errors.Wrapf(errInvalidChar, "%u %d", c, bufslice.length)
			return
		}
		bufslice.length++
		switch p.parserStatus {
		case parsingFirstLine1:
			if isSpace(c) {
				if !p.firstLine1Slice.valid() {
					return
				}
				p.parserStatus = parsingFirstLine2
			} else {
				p.firstLine1Slice.eat(it)
			}
		case parsingFirstLine2:
			if isSpace(c) {
				if !p.firstLine2Slice.valid() {
					return
				}
				p.parserStatus = parsingFirstLine3
			} else {
				p.firstLine2Slice.eat(it)
			}
		case parsingFirstLine3:
			if !p.firstLine3Slice.valid() {
				if isSpace(c) || isCR(c) || isEnter(c) {
					return
				}
				p.firstLine3Slice.eat(it)
			} else {
				if isEnter(c) {
					p.parserStatus = parsingHeadersKey
				} else if !isCR(c) {
					p.firstLine3Slice.eat(it)
				}
			}
		case parsingHeadersKey:
			if isEnter(c) {
				ok = true
				err = nil
				p.headerLength = bufslice.length
				return
			} else if isCR(c) || isSpace(c) {
			} else if isColon(c) {
				p.parserStatus = parsingHeadersValue
			} else {
				p.parsingKeySlice.eat(it)
			}
		case parsingHeadersValue:
			if isEnter(c) {
				p.parserStatus = parsingHeadersKey
				p.headersKV = append(p.headersKV, httpKV{
					key:   p.parsingKeySlice,
					value: p.parsingValueSlice,
				})
				p.parsingKeySlice.reset()
				p.parsingValueSlice.reset()
			} else if isCR(c) || isSpace(c) {

			} else {
				p.parsingValueSlice.eat(it)
			}
		}
		// bufslice.length++
	}
	err = nil
	return
}

// Delete deletes a key-value pair from http headers
func (p *HTTPHeaderParser) Delete(key []byte) (ok bool) {
	if len(p.buf) == 0 {
		return false
	}
	for it := 0; it < len(p.headersKV); it++ {
		kv := &p.headersKV[it]
		if !kv.key.valid() {
			continue
		}
		k := p.buf[kv.key.index : kv.key.index+kv.key.length]
		if !bytes.EqualFold(key, k) {
			continue
		}
		kv.key.reset()
		kv.value.reset()
	}
	return true
}

// Load returns the values in the http headers, or nil if no key is present.The OK indicates
// whether key-value was found in the headers
func (p *HTTPHeaderParser) Load(key []byte) (values [][]byte, ok bool) {
	if len(p.buf) == 0 {
		return
	}
	hkvlen := len(p.headersKV)
	for it := 0; it < hkvlen; it++ {
		kv := p.headersKV[it]
		if !kv.key.valid() {
			continue
		}
		k := p.buf[kv.key.index : kv.key.index+kv.key.length]
		if !bytes.EqualFold(key, k) {
			continue
		}
		v := p.buf[kv.value.index : kv.value.index+kv.value.length]
		values = append(values, v)
	}
	if len(values) > 0 {
		ok = true
	}
	return
}

// Store appends a key-value pair to the headers
func (p *HTTPHeaderParser) Store(key []byte, value []byte) (ok bool) {
	klen := len(key)
	vlen := len(value)

	if klen == 0 || p.bufSlice.length+klen+vlen > len(p.buf) {
		return false
	}
	copy(p.buf[p.bufSlice.length:], key)
	copy(p.buf[p.bufSlice.length+klen:], value)

	var kv httpKV
	kv.key.index = p.bufSlice.length
	kv.key.length = klen
	kv.value.index = p.bufSlice.length + klen
	kv.value.length = vlen
	p.bufSlice.length += klen + vlen
	p.headersKV = append(p.headersKV, kv)

	return true
}

// StoreFirstline1 store the first string of http first line
func (p *HTTPHeaderParser) StoreFirstline1(b []byte) (ok bool) {
	blen := len(b)

	if blen == 0 || p.bufSlice.length+blen > len(p.buf) {
		return false
	}
	copy(p.buf[p.bufSlice.length:], b)
	p.firstLine1Slice.index = p.bufSlice.length
	p.firstLine1Slice.length = blen
	p.bufSlice.length += blen

	return true
}

// StoreFirstline2 store the first string of http first line
func (p *HTTPHeaderParser) StoreFirstline2(b []byte) (ok bool) {
	blen := len(b)

	if blen == 0 || p.bufSlice.length+blen > len(p.buf) {
		return false
	}
	copy(p.buf[p.bufSlice.length:], b)
	p.firstLine2Slice.index = p.bufSlice.length
	p.firstLine2Slice.length = blen
	p.bufSlice.length += blen

	return true
}

// StoreFirstline3 store the first string of http first line
func (p *HTTPHeaderParser) StoreFirstline3(b []byte) (ok bool) {
	blen := len(b)

	if blen == 0 || p.bufSlice.length+blen > len(p.buf) {
		return false
	}
	copy(p.buf[p.bufSlice.length:], b)
	p.firstLine3Slice.index = p.bufSlice.length
	p.firstLine3Slice.length = blen
	p.bufSlice.length += blen

	return true
}

// GetFirstLine returns the first line of http request or reply
func (p *HTTPHeaderParser) GetFirstLine() (line []byte, err error) {
	if len(p.buf) == 0 || !p.firstLine1Slice.valid() || !p.firstLine2Slice.valid() || !p.firstLine3Slice.valid() {
		return nil, errInvalidHeader
	}
	left := p.firstLine1Slice.index
	right := p.firstLine3Slice.index + p.firstLine3Slice.length
	line = p.buf[left:right]
	return
}

// GetFirstLine1 returns the first string in the first line
func (p *HTTPHeaderParser) GetFirstLine1() ([]byte, error) {
	if len(p.buf) == 0 || !p.firstLine1Slice.valid() {
		return nil, errInvalidHeader
	}
	return p.buf[p.firstLine1Slice.index : p.firstLine1Slice.index+p.firstLine1Slice.length], nil
}

// GetFirstLine2 returns the second string in the first line
func (p *HTTPHeaderParser) GetFirstLine2() ([]byte, error) {
	if len(p.buf) == 0 || !p.firstLine2Slice.valid() {
		return nil, errInvalidHeader
	}
	return p.buf[p.firstLine2Slice.index : p.firstLine2Slice.index+p.firstLine2Slice.length], nil
}

// GetFirstLine3 returns the third string in the first line
func (p *HTTPHeaderParser) GetFirstLine3() ([]byte, error) {
	if len(p.buf) == 0 || !p.firstLine3Slice.valid() {
		return nil, errInvalidHeader
	}
	return p.buf[p.firstLine3Slice.index : p.firstLine3Slice.index+p.firstLine3Slice.length], nil
}

// Encode encodes the http message to a byte buffer
func (p *HTTPHeaderParser) Encode(b []byte) (n int, err error) {
	if len(p.buf) == 0 {
		err = errInsuffBuffer
		return
	}
	line1, err := p.GetFirstLine1()
	if err != nil {
		return
	}
	line2, err := p.GetFirstLine2()
	if err != nil {
		return
	}
	line3, err := p.GetFirstLine3()
	if err != nil {
		return
	}
	n = len(line1) + len(line2) + len(line3) + 4
	hkvlen := len(p.headersKV)
	keys := make([][]byte, 0, hkvlen)
	values := make([][]byte, 0, hkvlen)
	for it := 0; it < hkvlen; it++ {
		kv := p.headersKV[it]
		if !kv.key.valid() {
			continue
		}
		key := p.buf[kv.key.index : kv.key.index+kv.key.length]
		value := p.buf[kv.value.index : kv.value.index+kv.value.length]
		keys = append(keys, key)
		values = append(values, value)
		n += len(key) + len(value) + 4
	}
	n += 2
	if len(b) < n {
		n = 0
		err = errInsuffBuffer
		return
	}
	n = 0
	n += copy(b[n:], line1)
	b[n] = ' '
	n++
	n += copy(b[n:], line2)
	b[n] = ' '
	n++
	n += copy(b[n:], line3)
	n += copy(b[n:], []byte("\r\n"))
	for it := 0; it < len(keys); it++ {
		key := keys[it]
		value := values[it]
		n += copy(b[n:], key)
		n += copy(b[n:], []byte(": "))
		n += copy(b[n:], value)
		n += copy(b[n:], []byte("\r\n"))
	}
	n += copy(b[n:], []byte("\r\n"))
	return
}

// GetBuf return the buffer of parser
func (p *HTTPHeaderParser) GetBuf() []byte {
	return p.buf
}

// HeaderLen returns the hteader length of http message
func (p *HTTPHeaderParser) HeaderLen() int {
	return p.headerLength
}
