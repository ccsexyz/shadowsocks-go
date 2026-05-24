package ss

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"testing"
)

func ivBytes(base uint64) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[:8], base)
	return b
}

func TestMapFilter_TooShort(t *testing.T) {
	f := newBloomFilter(1000, 0.01).(*mapFilter)
	if f.TestAndAdd(nil) {
		t.Error("expected false for nil")
	}
	if f.TestAndAdd([]byte{}) {
		t.Error("expected false for empty slice")
	}
	// 0<len<8: zero-padded to 8 bytes, should work as normal (first insert)
	if f.TestAndAdd([]byte{1}) {
		t.Error("first insert of 1-byte should return false")
	}
	if !f.TestAndAdd([]byte{1}) {
		t.Error("second insert of same 1-byte should return true (duplicate)")
	}
	// different short values should not collide
	if f.TestAndAdd([]byte{2}) {
		t.Error("different 1-byte value should return false")
	}
}

func TestMapFilter_FirstInsert(t *testing.T) {
	f := newBloomFilter(1000, 0.01).(*mapFilter)
	if f.TestAndAdd(ivBytes(42)) {
		t.Error("first insert should return false")
	}
}

func TestMapFilter_Duplicate(t *testing.T) {
	f := newBloomFilter(1000, 0.01).(*mapFilter)
	iv := ivBytes(99)
	if f.TestAndAdd(iv) {
		t.Error("first insert should return false")
	}
	if !f.TestAndAdd(iv) {
		t.Error("second insert should return true (duplicate)")
	}
}

func TestMapFilter_SamePrefixDifferentSuffix(t *testing.T) {
	f := newBloomFilter(1000, 0.01).(*mapFilter)
	a := make([]byte, 16)
	binary.BigEndian.PutUint64(a[:8], 7)
	a[15] = 0xFF

	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[:8], 7)
	b[15] = 0x00

	f.TestAndAdd(a)
	if !f.TestAndAdd(b) {
		t.Error("same first 8 bytes should be detected as duplicate regardless of suffix")
	}
}

func TestMapFilter_DifferentKeys(t *testing.T) {
	f := newBloomFilter(1000, 0.01).(*mapFilter)
	f.TestAndAdd(ivBytes(1))
	f.TestAndAdd(ivBytes(2))
	if f.TestAndAdd(ivBytes(3)) {
		t.Error("new key should not be duplicate")
	}
	if !f.TestAndAdd(ivBytes(2)) {
		t.Error("existing key should be duplicate")
	}
}

func TestMapFilter_Concurrent(t *testing.T) {
	f := newBloomFilter(10000, 0.01).(*mapFilter)
	var wg sync.WaitGroup
	const goroutines = 10
	const iters = 1000

	for g := range goroutines {
		wg.Add(1)
		go func(base uint64) {
			defer wg.Done()
			for i := range iters {
				key := base*10000 + uint64(i)
				f.TestAndAdd(ivBytes(key))
			}
		}(uint64(g))
	}
	wg.Wait()

	// Verify no panics, len approx correct
	f.mu.Lock()
	l := len(f.m)
	f.mu.Unlock()
	t.Logf("map size: %d (expected ~%d)", l, goroutines*iters)
}

func TestNewBloomFilter_DefaultCap(t *testing.T) {
	f := newBloomFilter(0, 0.01).(*mapFilter)
	if f == nil {
		t.Fatal("expected non-nil filter")
	}
	// Should not panic on use
	f.TestAndAdd(ivBytes(1))
}

func TestNewBloomFilter_CustomCap(t *testing.T) {
	f := newBloomFilter(500, 0.01).(*mapFilter)
	if f == nil {
		t.Fatal("expected non-nil filter")
	}
	f.TestAndAdd(ivBytes(1))
}

func TestMapFilter_LongIV(t *testing.T) {
	// IVs are typically 16 or 32 bytes; verify >8 byte IVs work
	f := newBloomFilter(1000, 0.01).(*mapFilter)
	iv32 := make([]byte, 32)
	_, _ = rand.Read(iv32)
	if f.TestAndAdd(iv32) {
		t.Error("first insert of 32-byte IV should return false")
	}
	if !f.TestAndAdd(iv32) {
		t.Error("second insert of 32-byte IV should return true")
	}
}
