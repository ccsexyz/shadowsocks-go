package utils

import (
	"log"
	"math/rand"
	"sync"
	"testing"
)

func TestBufBasicGetAndPut(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	f := func() {
		for it := 0; it < 100; it++ {
			n := rand.Intn(65536)
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
