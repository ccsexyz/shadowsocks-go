package utils

import (
	"sync/atomic"
	"testing"
)

func BenchmarkRunInRLock(b *testing.B) {
	var rwlock RWLock
	n := 0
	for i := 0; i < b.N; i++ {
		rwlock.RunInRLock(func() {
			n++
		})
	}
	b.SetBytes(int64(n))
	return
}

func BenchmarkRunInLock(b *testing.B) {
	var rwlock RWLock
	n := 0
	for i := 0; i < b.N; i++ {
		rwlock.RunInLock(func() {
			n++
		})
	}
	b.SetBytes(int64(n))
	return
}

func BenchmarkRLock(b *testing.B) {
	var rwlock RWLock
	n := 0
	for i := 0; i < b.N; i++ {
		rwlock.RLock()
		n++
		rwlock.RUnlock()
	}
	b.SetBytes(int64(n))
	return
}

func BenchmarkWLock(b *testing.B) {
	var rwlock RWLock
	n := 0
	for i := 0; i < b.N; i++ {
		rwlock.Lock()
		n++
		rwlock.Unlock()
	}
	b.SetBytes(int64(n))
	return
}

func BenchmarkAtomicAdd(b *testing.B) {
	n := int32(0)
	for i := 0; i < b.N; i++ {
		atomic.AddInt32(&n, 1)
	}
	b.SetBytes(int64(n))
	return
}
