// +build bloom

package ss

import (
	"github.com/willf/bloom"
)

type bloomFilter struct {
	f *bloom.BloomFilter
}

func newBloomFilter(cap int, fp float64) bytesFilter {
	return &bloomFilter{
		f: bloom.NewWithEstimates(uint(cap), fp),
	}
}

func (b *bloomFilter) Close() error {
	b.f.ClearAll()
	return nil
}

func (b *bloomFilter) TestAndAdd(v []byte) bool {
	if b == nil || b.f == nil {
		return false
	}
	return b.f.TestAndAdd(v)
}
