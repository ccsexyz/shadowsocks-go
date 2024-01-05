// +build goprof

package utils

import (
	"log"
	"net/http"

	_ "net/http/pprof"
)

// http://wayslog.com/2016/11/09/golang-profile/

// RunProfileHTTPServer run pprof http server at addr
func RunProfileHTTPServer(addr string) {
	if len(addr) == 0 {
		return
	}
	go func() {
		log.Fatal(http.ListenAndServe(addr, nil))
	}()
}

// PprofEnabled returns whether pprof is enabled
func PprofEnabled() bool {
	return true
}
