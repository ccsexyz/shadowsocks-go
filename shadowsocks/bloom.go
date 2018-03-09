package ss

import (
	"sync"

	"github.com/willf/bloom"
)

const (
	defaultFilterCapacity  = 100000
	defaultFilterFalseRate = 0.00001
)

type bloomFilter struct {
	f    *bloom.BloomFilter
	lock sync.Mutex
}

func newBloomFilter() bytesFilter {
	return &bloomFilter{
		f: bloom.NewWithEstimates(uint(defaultFilterCapacity), defaultFilterFalseRate),
	}
}

func (b *bloomFilter) Close() error {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.f.ClearAll()
	return nil
}

func (b *bloomFilter) TestAndAdd(v []byte) bool {
	b.lock.Lock()
	defer b.lock.Unlock()
	if b == nil || b.f == nil {
		return false
	}
	return b.f.TestAndAdd(v)
}
