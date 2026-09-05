package utils

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
)

var bufPoolGets, bufPoolMisses atomic.Int64

// 12 size classes: 64B … 64KB plus a 128KB class. The largest class must
// cover domain.BufferSize (65568): anything above the 64KB classes used to
// fall through to make/PutBuf-discard, silently disabling pooling on the
// accept and MultiUDP hot paths.
var bufPools [12]sync.Pool

func init() {
	for it := 0; it < len(bufPools); it++ {
		i := it
		bufPools[i].New = func() any {
			bufPoolMisses.Add(1)
			return make([]byte, 1<<uint(i+6))
		}
	}
	http.HandleFunc("/debug/poolstats", func(w http.ResponseWriter, r *http.Request) {
		gets := bufPoolGets.Load()
		misses := bufPoolMisses.Load()
		rate := 0.0
		if gets > 0 {
			rate = float64(misses) / float64(gets) * 100
		}
		json.NewEncoder(w).Encode(map[string]any{
			"gets":    gets,
			"misses":  misses,
			"missPct": rate,
		})
	})
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
	if n > 0 && n <= 1<<17 {
		bufPoolGets.Add(1)
		return bufPools[getIndex(n)].Get().([]byte)[:n]
	}
	return make([]byte, n)
}

func PutBuf(b []byte) {
	if len(b) > 1<<17 || len(b) == 0 {
		return
	}
	index := getIndex(len(b))
	size := 1 << uint(index+6)
	// Defensive: the pool slice-extends to the full size class, so a buffer
	// with a smaller capacity (e.g. make([]byte, 100) or a resliced one)
	// would panic here instead of being rejected.
	if cap(b) < size {
		return
	}
	//lint:ignore SA6002 boxing []byte in any; negligible vs pooled buffer lifetime
	bufPools[index].Put(b[:size])
}

func CopyBuffer(b []byte) []byte {
	b2 := GetBuf(len(b))
	copy(b2, b)
	return b2
}

func CopyBuffers(bufs [][]byte) []byte {
	length := 0
	for _, b := range bufs {
		length += len(b)
	}
	ret := GetBuf(length)
	n := 0
	for _, b := range bufs {
		copy(ret[n:], b)
		n += len(b)
	}
	return ret
}
