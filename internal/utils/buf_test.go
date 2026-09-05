package utils

import (
	"log"
	"math/rand/v2"
	"sync"
	"testing"
)

// TestGetBufCoversBufferSize pins that the largest buffer class covers
// domain.BufferSize (65568): it used to fall through to make/discard,
// silently disabling pooling on accept and MultiUDP hot paths.
func TestGetBufCoversBufferSize(t *testing.T) {
	if idx := getIndex(65568); idx < 0 || 1<<uint(idx+6) < 65568 {
		t.Fatalf("getIndex(65568) = %d, class too small", idx)
	}
	b := GetBuf(65568)
	if len(b) != 65568 {
		t.Fatalf("GetBuf(65568) len = %d", len(b))
	}
	// PutBuf must accept the buffer back (its capacity must satisfy the
	// class size), then hand out a usable buffer again.
	PutBuf(b)
	b2 := GetBuf(65568)
	if len(b2) != 65568 {
		t.Fatalf("second GetBuf(65568) len = %d", len(b2))
	}
	PutBuf(b2)
}

// TestPutBufRejectsForeignBuffers guards the slice-extend in PutBuf: a
// buffer not produced by GetBuf (capacity below its size class) must be
// dropped instead of panicking.
func TestPutBufRejectsForeignBuffers(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PutBuf panicked on small-capacity buffer: %v", r)
		}
	}()
	PutBuf(make([]byte, 100))
	PutBuf(make([]byte, 65568)) // len in range, cap below the 128KB class
	small := GetBuf(64)
	PutBuf(small[:10]) // resliced below its class size
}

func TestBufBasicGetAndPut(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	f := func() {
		for it := 0; it < 100; it++ {
			n := rand.IntN(65536)
			b := GetBuf(n)
			if len(b) != n {
				t.Fail()
			}
			PutBuf(b)
		}
	}
	var wg sync.WaitGroup
	for it := 0; it < 1000; it++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}
	wg.Wait()
}
