// +build !goprof

package utils

// RunProfileHTTPServer do nothing
func RunProfileHTTPServer(addr string) {
}

// PprofEnabled returns whether pprof is enabled
func PprofEnabled() bool {
	return false
}
