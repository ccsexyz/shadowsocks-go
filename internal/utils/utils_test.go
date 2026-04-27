package utils

import (
	"sync/atomic"
	"testing"
)

func BenchmarkAtomicAdd(b *testing.B) {
	n := int32(0)
	for i := 0; i < b.N; i++ {
		atomic.AddInt32(&n, 1)
	}
	b.SetBytes(int64(n))
	return
}
