package crypto

import (
	"bytes"
	"testing"
)

// TestUDPPackerChachaAliases pins the UDP packer/unpacker method resolution:
// the chacha aliases must resolve to chacha, not silently fall through to
// AES-GCM (they used to — TCP used chacha while UDP used AES for the same
// configured method name).
func TestUDPPackerChachaAliases(t *testing.T) {
	pw := "shared-password"
	payload := []byte("hello udp packet over chacha alias")

	pack := func(method string) ([]byte, int, int, error) {
		p, err := NewPacker(method, pw, true)
		if err != nil {
			return nil, 0, 0, err
		}
		h := p.Headroom()
		b := make([]byte, h.Front+len(payload)+h.Rear)
		copy(b[h.Front:], payload)
		ps, pl, err := p.PackInPlace(b, h.Front, len(payload))
		if err != nil {
			return nil, 0, 0, err
		}
		return b, ps, pl, nil
	}

	unpack := func(method string, b []byte, ps, pl int) ([]byte, error) {
		u, err := NewUnpacker(method, pw)
		if err != nil {
			return nil, err
		}
		// UnpackInPlace decrypts in place, so each attempt needs its own
		// copy of the packet buffer.
		bb := append([]byte{}, b...)
		s, l, err := u.UnpackInPlace(bb, ps, pl)
		if err != nil {
			return nil, err
		}
		return bb[s : s+l], nil
	}

	// Aliases pack; both the alias itself and the canonical name unpack.
	for _, alias := range []string{"chacha20-poly1305", "chacha20poly1305"} {
		b, ps, pl, err := pack(alias)
		if err != nil {
			t.Fatalf("pack(%q): %v", alias, err)
		}
		for _, peer := range []string{alias, "chacha20-ietf-poly1305"} {
			got, err := unpack(peer, b, ps, pl)
			if err != nil {
				t.Fatalf("alias %q unpacked by %q: %v", alias, peer, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("alias %q unpacked by %q: payload mismatch", alias, peer)
			}
		}
	}

	// Canonical name packs; aliases unpack it.
	b, ps, pl, err := pack("chacha20-ietf-poly1305")
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"chacha20-poly1305", "chacha20poly1305"} {
		got, err := unpack(alias, b, ps, pl)
		if err != nil {
			t.Fatalf("canonical unpacked by %q: %v", alias, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("canonical unpacked by %q: payload mismatch", alias)
		}
	}

	// Cross-check that chacha and AES actually disagree: a chacha-packed
	// packet must NOT open under an AES-GCM unpacker, and vice versa.
	chachaB, ps, pl, err := pack("chacha20-ietf-poly1305")
	if err != nil {
		t.Fatal(err)
	}
	aesB, aps, apl, err := pack("aes-256-gcm")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unpack("aes-256-gcm", chachaB, ps, pl); err == nil {
		t.Fatal("chacha packet opened under aes-256-gcm unpacker")
	}
	if _, err := unpack("chacha20-ietf-poly1305", aesB, aps, apl); err == nil {
		t.Fatal("aes packet opened under chacha unpacker")
	}
}
