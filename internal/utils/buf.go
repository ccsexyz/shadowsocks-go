package utils

import (
	"sync"
)

var bufPools [11]sync.Pool

func init() {
	for it := 0; it < len(bufPools); it++ {
		getnew := func(i int) func() interface{} {
			length := 1 << uint(i+6)
			return func() interface{} {
				return make([]byte, length)
			}
		}
		bufPools[it].New = getnew(it)
	}
}

func getIndex(n int) int {
	ret := 0
	ones := 0
	for n > 0 {
		ret++
		if (n & 1) != 0 {
			ones++
		}
		n = n >> 1
	}
	if ones > 1 {
		ret++
	}
	if ret-7 < 0 {
		ret = 0
	} else {
		ret -= 7
	}
	return ret
}

func GetBuf(n int) []byte {
	if n > 0 && n <= 65536 {
		return bufPools[getIndex(n)].Get().([]byte)[:n]
	}
	return make([]byte, n)
}

func PutBuf(b []byte) {
	if len(b) > 65536 || len(b) == 0 {
		return
	}
	index := getIndex(len(b))
	bufPools[index].Put(b[:(1 << uint(index+6))])
}

func CopyBuffer(b []byte) []byte {
	b2 := GetBuf(len(b))
	copy(b2, b)
	return b2
}
