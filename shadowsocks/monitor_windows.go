//go:build windows

package ss

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	prevKernel uint64
	prevUser   uint64
	prevWallW  int64
)

func sampleCPU(s *processSample) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetProcessTimes")
	handle, _ := syscall.GetCurrentProcess()

	var creation, exit, kernel, user syscall.Filetime
	r, _, _ := proc.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r == 0 {
		return
	}

	kernelNanos := uint64(kernel.Nanoseconds())
	userNanos := uint64(user.Nanoseconds())
	cpuNanos := kernelNanos + userNanos
	wallNanos := time.Now().UnixNano()

	if prevWallW > 0 && cpuNanos > prevKernel+prevUser {
		cpuDelta := cpuNanos - (prevKernel + prevUser)
		wallDelta := uint64(wallNanos - prevWallW)
		if wallDelta > 0 {
			s.CPUPercent = float64(cpuDelta) / float64(wallDelta) * 100
		}
	}
	prevKernel = kernelNanos
	prevUser = userNanos
	prevWallW = wallNanos
}

func fdCount() int {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetProcessHandleCount")
	handle, _ := syscall.GetCurrentProcess()
	var count uint32
	r, _, _ := proc.Call(uintptr(handle), uintptr(unsafe.Pointer(&count)))
	if r == 0 {
		return 0
	}
	return int(count)
}
