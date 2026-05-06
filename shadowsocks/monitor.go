package ss

import (
	"encoding/json"
	rt "runtime"
	"sync"
	"time"
)

const monitorSize = 30           // 60s at 2s intervals
const monitorMinuteSize = 30     // 30min at 1min intervals
const monitorMinuteInterval = 30 // 30 × 2s = 1min

type processSample struct {
	Goroutines int     `json:"goroutines"`
	CPUPercent float64 `json:"cpuPercent"`
	HeapAlloc  int64   `json:"heapAlloc"`
	HeapSys    int64   `json:"heapSys"`
	NumFD      int     `json:"numFD"`
}

var processHistory = struct {
	mu     sync.Mutex
	buf    []processSample
	pos    int
	filled bool

	// minute-level aggregation
	minBuf    []processSample
	minPos    int
	minFilled bool
	minTick   int
	minAcc    processSample // running accumulation for current minute
	minCount  int
}{
	buf:    make([]processSample, monitorSize),
	minBuf: make([]processSample, monitorMinuteSize),
}

func sampleProcess() {
	processHistory.mu.Lock()
	s := processSample{
		Goroutines: rt.NumGoroutine(),
	}

	sampleCPU(&s)

	var ms rt.MemStats
	rt.ReadMemStats(&ms)
	s.HeapAlloc = int64(ms.HeapAlloc)
	s.HeapSys = int64(ms.HeapSys)
	s.NumFD = fdCount()

	// 2s buffer
	processHistory.buf[processHistory.pos] = s
	processHistory.pos++
	if processHistory.pos >= monitorSize {
		processHistory.pos = 0
		processHistory.filled = true
	}

	// Accumulate into minute-level history
	processHistory.minAcc.CPUPercent += s.CPUPercent
	processHistory.minAcc.HeapAlloc += s.HeapAlloc
	processHistory.minAcc.HeapSys += s.HeapSys
	processHistory.minAcc.NumFD += s.NumFD
	processHistory.minAcc.Goroutines += s.Goroutines
	processHistory.minCount++

	processHistory.minTick++
	if processHistory.minTick >= monitorMinuteInterval {
		processHistory.minTick = 0
		n := processHistory.minCount
		if n > 0 {
			avg := processSample{
				CPUPercent: processHistory.minAcc.CPUPercent / float64(n),
				HeapAlloc:  processHistory.minAcc.HeapAlloc / int64(n),
				HeapSys:    processHistory.minAcc.HeapSys / int64(n),
				NumFD:      processHistory.minAcc.NumFD / n,
				Goroutines: processHistory.minAcc.Goroutines / n,
			}
			processHistory.minBuf[processHistory.minPos] = avg
			processHistory.minPos++
			if processHistory.minPos >= monitorMinuteSize {
				processHistory.minPos = 0
				processHistory.minFilled = true
			}
		}
		processHistory.minAcc = processSample{}
		processHistory.minCount = 0
	}
	processHistory.mu.Unlock()

	b, _ := json.Marshal(s)
	sseHub.publish("process_updated", b)
}

func getProcessHistory() []processSample {
	processHistory.mu.Lock()
	defer processHistory.mu.Unlock()

	size := monitorSize
	if !processHistory.filled {
		size = processHistory.pos
	}
	out := make([]processSample, size)
	for i := 0; i < size; i++ {
		idx := i
		if processHistory.filled {
			idx = (processHistory.pos + i) % monitorSize
		}
		out[i] = processHistory.buf[idx]
	}
	return out
}

func getProcessMinuteHistory() []processSample {
	processHistory.mu.Lock()
	defer processHistory.mu.Unlock()

	size := monitorMinuteSize
	if !processHistory.minFilled {
		size = processHistory.minPos
	}
	out := make([]processSample, size)
	for i := 0; i < size; i++ {
		idx := i
		if processHistory.minFilled {
			idx = (processHistory.minPos + i) % monitorMinuteSize
		}
		out[i] = processHistory.minBuf[idx]
	}
	return out
}

var monitorOnce sync.Once

func StartProcessMonitor() {
	monitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				sampleProcess()
			}
		}()
	})
}
