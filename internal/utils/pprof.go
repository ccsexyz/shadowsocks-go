package utils

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

// RunProfileHTTPServer starts a pprof HTTP server at addr.
// If addr is empty, it does nothing.
func RunProfileHTTPServer(addr string) {
	if len(addr) == 0 {
		return
	}
	go func() {
		log.Fatal(http.ListenAndServe(addr, nil))
	}()
}
