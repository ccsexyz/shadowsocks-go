//go:build !windows

package ss

import (
	"bytes"
	"os"
	"os/exec"
	rt "runtime"
	"strconv"
	"syscall"
	"time"
)

// --- CPU tracking (Unix) ---

var (
	prevCPUTime int64
	prevWall    int64
)

func sampleCPU(s *processSample) {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err != nil {
		return
	}
	cpuNanos := rusage.Utime.Nano() + rusage.Stime.Nano()
	wallNanos := time.Now().UnixNano()
	if prevCPUTime > 0 && prevWall > 0 {
		cpuDelta := cpuNanos - prevCPUTime
		wallDelta := wallNanos - prevWall
		if wallDelta > 0 {
			s.CPUPercent = float64(cpuDelta) / float64(wallDelta) * 100
		}
	}
	prevCPUTime = cpuNanos
	prevWall = wallNanos
}

// --- FD count (Unix) ---

func fdCount() int {
	switch rt.GOOS {
	case "linux":
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return 0
		}
		return len(entries)
	case "darwin":
		return fdCountLsof()
	default:
		return 0
	}
}

func fdCountLsof() int {
	cmd := exec.Command("lsof", "-b", "-n", "-p", strconv.Itoa(os.Getpid()))
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	n := bytes.Count(out, []byte("\n"))
	if n > 5 {
		n -= 4 // header + ~3 pipe FDs from lsof itself
	}
	return n
}
