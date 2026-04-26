package crypto

import (
	"crypto/rand"
)

const DefaultMethod = "aes-128-gcm"

func PutRandomBytes(b []byte) {
	rand.Read(b)
}

func GetRandomBytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	data := make([]byte, n)
	PutRandomBytes(data)
	return data
}

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

// CopyBuffer returns a copy of b.
func CopyBuffer(b []byte) []byte {
	if b == nil {
		return nil
	}
	buf := make([]byte, len(b))
	copy(buf, b)
	return buf
}

// GetBuf gets a buffer with given length from pool
func GetBuf(length int) []byte {
	return make([]byte, length)
}

// PutBuf puts a buffer back to pool
func PutBuf(b []byte) {}
