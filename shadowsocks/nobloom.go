//go:build !bloom
// +build !bloom

package ss

import (
	"encoding/binary"
	"sync"
)

type mapFilter struct {
	mu sync.Mutex
	m  map[uint64]struct{}
}

func (f *mapFilter) Close() error {
	return nil
}

func (f *mapFilter) TestAndAdd(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	var key uint64
	if len(v) < 8 {
		var padded [8]byte
		copy(padded[:], v)
		key = binary.BigEndian.Uint64(padded[:])
	} else {
		key = binary.BigEndian.Uint64(v[:8])
	}
	f.mu.Lock()
	_, ok := f.m[key]
	if !ok {
		f.m[key] = struct{}{}
	}
	f.mu.Unlock()
	return ok
}

func newBloomFilter(cap int, _ float64) bytesFilter {
	if cap <= 0 {
		cap = 100000
	}
	return &mapFilter{m: make(map[uint64]struct{}, cap)}
}
