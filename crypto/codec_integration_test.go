package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

)

// TestBidirectionalNewMethods reproduces the full proxy data flow:
// Client (encC→decC) and Server (decS→encS) using new WriteBuffer/ReadFrame.
// This is the exact scenario where cipherStreamCodec integration was failing.
func TestBidirectionalNewMethods(t *testing.T) {
	encC, _ := NewEncrypter("aes-256-gcm", "test-password")
	decC, _ := NewDecrypter("aes-256-gcm", "test-password")
	decS, _ := NewDecrypter("aes-256-gcm", "test-password")
	encS, _ := NewEncrypter("aes-256-gcm", "test-password")

	payload := make([]byte, 4096)
	rand.Read(payload)

	// Client → Server (encrypt with WriteBuffer, send via ReadFrame)
	if err := encC.WriteFrame(payload); err != nil {
		t.Fatal("encC.WriteBuffer:", err)
	}
	var wireCS bytes.Buffer
	drainFrames(t, encC, &wireCS)

	// Server receives — simulate accept handler: old Write + Read for first frame
	// (ssAcceptHandler hasn't been changed yet, uses old io.ReadWriter methods)
	decS.Write(wireCS.Bytes())
	dbuf := make([]byte, 8192)
	dn, err := decS.Read(dbuf)
	if err != nil && err != io.EOF {
		t.Fatal("decS.Read:", err)
	}
	if dn != len(payload) {
		t.Errorf("server decrypted %d bytes, want %d", dn, len(payload))
	}

	// Server → Client (echo): encrypt with WriteBuffer
	echoPayload := dbuf[:dn]
	if err := encS.WriteFrame(echoPayload); err != nil {
		t.Fatal("encS.WriteBuffer:", err)
	}
	var wireSC bytes.Buffer
	drainFrames(t, encS, &wireSC)

	// Client receives — simulate cipherStreamCodec.ReadFrame with new methods.
	// Feed wire data in chunks (simulating TCP reads), decrypt with
	// WriteBuffer + ReadFrame in a loop.
	feedAndDecrypt(t, decC, wireSC.Bytes(), payload)
}

// TestBidirectionalOldDecrypt tests the case where server decryption uses old
// methods (accept handler) and client decryption uses new methods.
func TestBidirectionalOldDecrypt(t *testing.T) {
	encC, _ := NewEncrypter("aes-256-gcm", "test-password")
	decC, _ := NewDecrypter("aes-256-gcm", "test-password")
	decS, _ := NewDecrypter("aes-256-gcm", "test-password")
	encS, _ := NewEncrypter("aes-256-gcm", "test-password")

	payload := make([]byte, 4096)
	rand.Read(payload)

	// Client: encrypt with new WriteBuffer
	encC.WriteFrame(payload)
	var wireCS bytes.Buffer
	drainFrames(t, encC, &wireCS)

	// Server: decrypt with old Write+Read (accept handler path)
	decS.Write(wireCS.Bytes())
	dbuf := make([]byte, 8192)
	dn, _ := decS.Read(dbuf)
	if dn != len(payload) {
		t.Fatalf("server decrypted %d bytes, want %d", dn, len(payload))
	}

	// Server: encrypt echo with new WriteBuffer
	encS.WriteFrame(dbuf[:dn])
	var wireSC bytes.Buffer
	drainFrames(t, encS, &wireSC)

	// Client: decrypt echo with old Write+Read (mimicking old cipherStreamCodec)
	decC.Write(wireSC.Bytes())
	dbuf2 := make([]byte, 8192)
	dn2, _ := decC.Read(dbuf2)
	if !bytes.Equal(dbuf2[:dn2], payload) {
		t.Errorf("client decrypted %d bytes, want %d", dn2, len(payload))
	}
}

// TestReadFrameDrainAfterEOF verifies that ReadFrame correctly drains buffered
// frames after the underlying reader returns EOF (all data has been read).
func TestReadFrameDrainAfterEOF(t *testing.T) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	dec, _ := NewDecrypter("aes-256-gcm", "test-password")

	// Write 4 frames worth of data
	plaintext := make([]byte, 4096)
	rand.Read(plaintext)
	enc.WriteFrame(plaintext)
	var wire bytes.Buffer
	drainFrames(t, enc, &wire)

	// Feed ALL wire data at once, then call ReadFrame in a loop until EOF.
	dec.WriteFrame(wire.Bytes())

	var recovered []byte
	for {
		frame, err := dec.ReadFrame(nil)
		if frame != nil {
			for _, seg := range [][]byte{frame} {
				recovered = append(recovered, seg...)
			}
			
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("ReadFrame:", err)
		}
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("got %d bytes, want %d", len(recovered), len(plaintext))
	}
}

// helpers

func drainFrames(t *testing.T, c CipherStream, buf *bytes.Buffer) {
	t.Helper()
	for {
		frame, err := c.ReadFrame(nil)
		if frame != nil {
			for _, seg := range [][]byte{frame} {
				buf.Write(seg)
			}
			
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("drainFrames:", err)
		}
	}
}

// feedAndDecrypt simulates cipherStreamCodec.ReadFrame loop:
// feed wire data in 1500-byte chunks (like TCP MSS), decrypt via
// WriteBuffer + ReadFrame. WriteBuffer must be called before ReadFrame
// so that the IV is collected before AEAD initialization.
func feedAndDecrypt(t *testing.T, dec CipherStream, wire []byte, expect []byte) {
	t.Helper()
	pos := 0
	var recovered []byte
	for {
		// Feed more wire data if available
		if pos < len(wire) {
			chunkSize := min(len(wire)-pos, 1500)
			chunk := wire[pos:pos+chunkSize]
			pos += chunkSize
			if err := dec.WriteFrame([][]byte{chunk}[0]); err != nil {
				t.Fatal("WriteBuffer:", err)
			}
		}

		frame, err := dec.ReadFrame(nil)
		if frame != nil {
			for _, seg := range [][]byte{frame} {
				recovered = append(recovered, seg...)
			}
			
			continue
		}
		if err != nil && err != io.EOF {
			t.Fatal("ReadFrame:", err)
		}

		// No more data AND no frame — we're done
		if pos >= len(wire) && err == io.EOF {
			break
		}
	}

	if !bytes.Equal(recovered, expect) {
		t.Errorf("got %d bytes, want %d", len(recovered), len(expect))
	}
}

// TestAcceptThenCodec tests the exact flow in the proxy:
// 1. Accept handler uses old Write+Read to parse the first frame (address)
// 2. The SAME dec is passed to cipherStreamCodec using new WriteBuffer+ReadFrame
// 3. Second frame arrives and is decrypted with the new methods
func TestAcceptThenCodec(t *testing.T) {
	enc, _ := NewEncrypter("aes-256-gcm", "test-password")
	dec, _ := NewDecrypter("aes-256-gcm", "test-password")

	// Frame 1: address (simulates client's first encrypted frame with address)
	addrPayload := []byte("target-address:443")
	enc.Write(addrPayload)
	var wire1 bytes.Buffer
	drainOld(t, enc, &wire1)

	// Accept handler: old Write + Read
	dec.Write(wire1.Bytes())
	dbuf := make([]byte, 8192)
	dn, err := dec.Read(dbuf)
	if err != nil && err != io.EOF {
		t.Fatal("accept Read:", err)
	}
	if string(dbuf[:dn]) != "target-address:443" {
		t.Errorf("accept got %q", dbuf[:dn])
	}

	// Frame 2: data payload (simulates subsequent data after accept)
	dataPayload := make([]byte, 8192)
	rand.Read(dataPayload)
	enc.Write(dataPayload)
	var wire2 bytes.Buffer
	drainOld(t, enc, &wire2)

	// cipherStreamCodec.ReadFrame: new WriteBuffer + ReadFrame on the same dec
	feedAndDecrypt(t, dec, wire2.Bytes(), dataPayload)
}

func drainOld(t *testing.T, enc CipherStream, buf *bytes.Buffer) {
	t.Helper()
	for {
		tmp := make([]byte, 8192)
		n, err := enc.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}
