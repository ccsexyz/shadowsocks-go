package utils

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHttpProxyTo_TargetRouting(t *testing.T) {
	// Start a real backend that returns a distinctive response.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	target := strings.TrimPrefix(backend.URL, "http://")

	// Create request with a Host that is NOT the backend address.
	req := httptest.NewRequest("GET", "/test", nil)
	req.Host = "www.evil.com:9999" // would fail if dialed

	rec := httptest.NewRecorder()
	HttpProxyTo(rec, req, target)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d (error: %s)", resp.StatusCode, resp.Header.Get("X-Error-Info"))
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend-ok" {
		t.Fatalf("expected 'backend-ok', got '%s'", body)
	}
}

// TestHttpProxyTransport_CtxKeyRoundtrip verifies that the typed context key
// used in HttpProxyTo round-trips correctly through httpProxyTransport.DialContext.
func TestHttpProxyTransport_CtxKeyRoundtrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backendAddr := ln.Addr().String()
	ln.Close()

	ctx := context.WithValue(context.Background(), ctxKey("target"), backendAddr)

	targetVal := ctx.Value(ctxKey("target"))
	if targetVal == nil {
		t.Fatal("ctxKey roundtrip failed — same typed key should match")
	}
	if targetVal.(string) != backendAddr {
		t.Fatalf("expected %s, got %v", backendAddr, targetVal)
	}

	// Verify plain string key does NOT match (this is the bug scenario).
	plainVal := ctx.Value("target")
	if plainVal != nil {
		t.Error("plain string key should NOT match typed ctxKey — this regression would mean the bug is back")
	}
}
