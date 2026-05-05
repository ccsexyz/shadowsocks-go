package crypto

import (
	"fmt"
	"testing"

	"github.com/ccsexyz/shadowsocks-go/zerocopy"
)

// --- helpers ---

var benchMethods = []struct {
	name     string
	password string
}{
	{"plain", ""},
	{"aes-256-gcm", "test-password-12345"},
	{"chacha20-ietf-poly1305", "test-password-12345"},
	{"2022-blake3-aes-256-gcm", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	{"2022-blake3-chacha20-poly1305", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
}

var benchPayloadSizes = []int{64, 512, 1400}

func makePayload(size int) []byte {
	b := make([]byte, size)
	PutRandomBytes(b)
	return b
}

// --- CipherBlock benchmarks (baseline, exists on both versions) ---

func BenchmarkCipherBlockEncrypt(b *testing.B) {
	for _, m := range benchMethods {
		for _, sz := range benchPayloadSizes {
			b.Run(fmt.Sprintf("%s/%d", m.name, sz), func(b *testing.B) {
				cb, err := NewCipherBlock(m.name, m.password)
				if err != nil {
					b.Fatal(err)
				}
				payload := makePayload(sz)
				b.SetBytes(int64(sz))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					_, _, err = cb.Encrypt(nil, payload)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkCipherBlockDecrypt(b *testing.B) {
	for _, m := range benchMethods {
		for _, sz := range benchPayloadSizes {
			b.Run(fmt.Sprintf("%s/%d", m.name, sz), func(b *testing.B) {
				cb, err := NewCipherBlock(m.name, m.password)
				if err != nil {
					b.Fatal(err)
				}
				payload := makePayload(sz)
				b.SetBytes(int64(sz))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					ct, _, err := cb.Encrypt(nil, payload)
					if err != nil {
						b.Fatal(err)
					}
					_, _, err = cb.Decrypt(nil, ct)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// --- Zero-copy Packer benchmarks ---

func BenchmarkPackerPackInPlace(b *testing.B) {
	for _, m := range benchMethods {
		for _, sz := range benchPayloadSizes {
			b.Run(fmt.Sprintf("%s/%d", m.name, sz), func(b *testing.B) {
				p, err := NewPacker(m.name, m.password, true)
				if err != nil {
					b.Fatal(err)
				}
				hr := p.Headroom()
				payload := makePayload(sz)
				buf := make([]byte, hr.Front+sz+hr.Rear)
				copy(buf[hr.Front:], payload)
				b.SetBytes(int64(sz))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					_, _, err = p.PackInPlace(buf, hr.Front, sz)
					if err != nil {
						b.Fatal(err)
					}
					// Refresh payload after encryption mutates it
					copy(buf[hr.Front:], payload)
				}
			})
		}
	}
}

func BenchmarkUnpackerUnpackInPlace(b *testing.B) {
	for _, m := range benchMethods {
		for _, sz := range benchPayloadSizes {
			b.Run(fmt.Sprintf("%s/%d", m.name, sz), func(b *testing.B) {
				u, err := NewUnpacker(m.name, m.password)
				if err != nil {
					b.Fatal(err)
				}
				p, err := NewPacker(m.name, m.password, true)
				if err != nil {
					b.Fatal(err)
				}
				hr := p.Headroom()
				payload := makePayload(sz)
				buf := make([]byte, hr.Front+sz+hr.Rear)
				copy(buf[hr.Front:], payload)
				_, packetLen, err := p.PackInPlace(buf, hr.Front, sz)
				if err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(sz))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					// Re-encrypt fresh packet for each iteration
					copy(buf[hr.Front:], payload)
					_, packetLen, err = p.PackInPlace(buf, hr.Front, sz)
					if err != nil {
						b.Fatal(err)
					}
					_, _, err = u.UnpackInPlace(buf, 0, packetLen)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// --- Full roundtrip: pack then unpack in same buffer ---

func BenchmarkZerocopyRoundtrip(b *testing.B) {
	for _, m := range benchMethods {
		for _, sz := range benchPayloadSizes {
			b.Run(fmt.Sprintf("%s/%d", m.name, sz), func(b *testing.B) {
				u, err := NewUnpacker(m.name, m.password)
				if err != nil {
					b.Fatal(err)
				}
				p, err := NewPacker(m.name, m.password, true)
				if err != nil {
					b.Fatal(err)
				}
				ph, uh := p.Headroom(), u.Headroom()
				hr := zerocopy.Headroom{Front: max(ph.Front, uh.Front), Rear: max(ph.Rear, uh.Rear)}
				payload := makePayload(sz)
				buf := make([]byte, hr.Front+sz+hr.Rear)
				b.SetBytes(int64(sz))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					copy(buf[hr.Front:], payload)
					packetStart, packetLen, err := p.PackInPlace(buf, hr.Front, sz)
					if err != nil {
						b.Fatal(err)
					}
					_, _, err = u.UnpackInPlace(buf, packetStart, packetLen)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// --- Sliding window benchmark ---

func BenchmarkSlidingWindowCheck(b *testing.B) {
	w := newSlidingWindow(udp2022WindowSize)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for i := uint64(0); i < 100; i++ {
			w.check(i)
		}
	}
}

func BenchmarkSlidingWindowCheckHighID(b *testing.B) {
	w := newSlidingWindow(udp2022WindowSize)
	// Prime the window to a high ID
	for i := uint64(0); i < 1000000; i++ {
		w.check(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for i := uint64(1000000); i < 1000100; i++ {
			w.check(i)
		}
	}
}

// --- throughput comparison: PackInPlace vs CipherBlock.Encrypt on shared buffer ---

func BenchmarkPackVsEncrypt(b *testing.B) {
	methods := []struct {
		name     string
		password string
	}{
		{"aes-256-gcm", "test-password-12345"},
		{"chacha20-ietf-poly1305", "test-password-12345"},
		{"2022-blake3-aes-256-gcm", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		{"2022-blake3-chacha20-poly1305", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}
	sizes := []int{64, 512, 1400}

	for _, m := range methods {
		for _, sz := range sizes {
			b.Run("PackInPlace/"+m.name+"/"+itoa(sz), func(b *testing.B) {
				p, err := NewPacker(m.name, m.password, true)
				if err != nil {
					b.Fatal(err)
				}
				hr := p.Headroom()
				payload := makePayload(sz)
				buf := make([]byte, hr.Front+sz+hr.Rear)
				copy(buf[hr.Front:], payload)
				b.SetBytes(int64(sz))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					copy(buf[hr.Front:], payload)
					_, _, err = p.PackInPlace(buf, hr.Front, sz)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("CipherBlock/"+m.name+"/"+itoa(sz), func(b *testing.B) {
				cb, err := NewCipherBlock(m.name, m.password)
				if err != nil {
					b.Fatal(err)
				}
				payload := makePayload(sz)
				b.SetBytes(int64(sz))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					_, _, err = cb.Encrypt(nil, payload)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
