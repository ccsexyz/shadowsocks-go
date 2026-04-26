package crypto

import (
	"crypto/rand"
)

const DefaultMethod = "aes-128-gcm"

func PutRandomBytes(b []byte) {
	rand.Read(b)
}

// GetRandomBytes returns a slice of n random bytes.
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
