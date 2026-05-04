package crypto

import (
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

const DefaultMethod = "aes-128-gcm"

func PutRandomBytes(b []byte) {
	utils.PutRandomBytes(b)
}

// GetRandomBytes returns a slice of n random bytes.
func GetRandomBytes(n int) []byte {
	return utils.GetRandomBytes(n)
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
