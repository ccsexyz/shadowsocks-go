package utils

import "sync"

const (
	bufPoolChunkSize = 4096
	bufPoolLargeThr  = 2048
	bufPoolAlign     = 64
)

var chunkPool = sync.Pool{New: func() any { return &[bufPoolChunkSize]byte{} }}

// BufPool is a nginx-style bump allocator backed by sync.Pool of 4KB chunks.
type BufPool struct {
	chunks []*[bufPoolChunkSize]byte
	cur    *[bufPoolChunkSize]byte
	off    int
}

// NewBufPool creates a new BufPool.
func NewBufPool() *BufPool { return &BufPool{} }

func (p *BufPool) Get(n int) []byte {
	if n >= bufPoolLargeThr {
		return make([]byte, n)
	}
	if p.cur == nil {
		p.cur = chunkPool.Get().(*[bufPoolChunkSize]byte)
		p.off = 0
		p.chunks = append(p.chunks, p.cur)
	}
	aligned := (p.off + bufPoolAlign - 1) &^ (bufPoolAlign - 1)
	if aligned+n > bufPoolChunkSize {
		p.cur = chunkPool.Get().(*[bufPoolChunkSize]byte)
		p.off = 0
		p.chunks = append(p.chunks, p.cur)
		aligned = 0
	}
	b := p.cur[aligned : aligned+n]
	p.off = aligned + n
	return b
}

func (p *BufPool) Reset() {
	// Release all chunks except the current one back to the pool.
	// Keep one chunk so the next allocation cycle can reuse it
	// instead of acquiring from sync.Pool.
	for _, c := range p.chunks {
		if c != p.cur {
			chunkPool.Put(c)
		}
	}
	p.chunks = p.chunks[:0]
	if p.cur != nil {
		p.chunks = append(p.chunks, p.cur)
	}
	p.off = 0
}
