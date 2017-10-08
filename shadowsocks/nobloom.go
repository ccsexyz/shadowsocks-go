// +build !bloom

package ss

import "sync"

type mapFilter struct {
	m sync.Map
}

func (m *mapFilter) Close() error {
	return nil
}

func (m *mapFilter) TestAndAdd(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	_, ok := m.m.LoadOrStore(string(v), nil)
	return ok
}

func newBloomFilter(_ int, _ float64) bytesFilter {
	return &mapFilter{}
}
