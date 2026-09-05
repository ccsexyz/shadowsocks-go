package ss

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConnLoggerWriteAndRotate(t *testing.T) {
	dir := t.TempDir()
	today := time.Now().Format("2006-01-02")
	logPath := filepath.Join(dir, "connections")

	tracker := newConnTracker()
	tracker.SetConnLogger(logPath)
	if tracker.logger == nil {
		t.Fatal("SetConnLogger failed: logger is nil")
	}
	defer tracker.logger.Close()

	// Register and close a connection. Unregister triggers the write.
	rec := tracker.Register("192.168.1.1:12345", "10.0.0.1:443", "example.com")
	tracker.Unregister(rec)

	// Verify the log file was created with today's date.
	logFile := filepath.Join(dir, "connections-"+today+".jsonl")
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read log file %s: %v", logFile, err)
	}

	// Parse the JSON Lines entry.
	var got ConnRecord
	if err := json.Unmarshal(data[:len(data)-1], &got); err != nil {
		t.Fatalf("failed to unmarshal log entry: %v", err)
	}

	if got.SrcAddr != "192.168.1.1:12345" {
		t.Errorf("SrcAddr = %q, want %q", got.SrcAddr, "192.168.1.1:12345")
	}
	if got.DstAddr != "10.0.0.1:443" {
		t.Errorf("DstAddr = %q, want %q", got.DstAddr, "10.0.0.1:443")
	}
	if got.Host != "example.com" {
		t.Errorf("Host = %q, want %q", got.Host, "example.com")
	}
	// endTime is produced by the custom MarshalJSON; verify it survives the
	// round trip.
	var aux struct {
		EndTime *time.Time `json:"endTime"`
	}
	if err := json.Unmarshal(data[:len(data)-1], &aux); err != nil {
		t.Fatalf("failed to unmarshal endTime: %v", err)
	}
	if aux.EndTime == nil {
		t.Error("endTime should be present in logged JSON")
	}
}

func TestConnLoggerSetTwiceIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "connections")

	tracker := newConnTracker()
	tracker.SetConnLogger(logPath)
	if tracker.logger == nil {
		t.Fatal("first SetConnLogger failed")
	}

	// Second call should overwrite silently, not panic or leak.
	tracker.SetConnLogger(logPath)
	if tracker.logger == nil {
		t.Fatal("second SetConnLogger should not nil out logger")
	}

	tracker.logger.Close()
}

func TestConnLoggerEmptyPathIsNoop(t *testing.T) {
	tracker := newConnTracker()
	tracker.SetConnLogger("")
	if tracker.logger != nil {
		t.Error("logger should be nil when logPath is empty")
	}
}

func timePtr(t time.Time) *time.Time { return &t }
