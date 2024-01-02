package utils

import "sync/atomic"

// AtomicFlag is an atomic flag(or boolean)
type AtomicFlag uint32

// Set sets the atomic flag to flag and returns old value
func (a *AtomicFlag) Set(flag bool) bool {
	var old, new uint32
	if flag {
		new = 1
	} else {
		new = 0
	}

	for {
		old = atomic.LoadUint32((*uint32)(a))
		if atomic.CompareAndSwapUint32((*uint32)(a), old, new) {
			break
		}
	}

	return old != 0
}

// Test tests if flag is set to true
func (a *AtomicFlag) Test() bool {
	return atomic.LoadUint32((*uint32)(a)) != 0
}
