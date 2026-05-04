// Package zerocopy provides interfaces for zero-allocation packet encryption.
// Instead of allocating new buffers per packet, PackInPlace and UnpackInPlace
// operate on pre-allocated buffers with headroom for protocol headers and AEAD tags.
package zerocopy

// Headroom describes the extra space needed before and after the payload
// for protocol headers (Front) and AEAD tags (Rear).
type Headroom struct {
	Front int
	Rear  int
}

// Packer encrypts a plaintext payload in-place within a pre-allocated buffer.
// Protocol headers and nonces are written into the Front headroom;
// AEAD tags extend into the Rear headroom.
type Packer interface {
	Headroom() Headroom
	// PackInPlace encrypts b[payloadStart:payloadStart+payloadLen] in-place.
	// Returns the start and length of the encrypted packet within b.
	PackInPlace(b []byte, payloadStart, payloadLen int) (packetStart, packetLen int, err error)
}

// Unpacker decrypts an encrypted packet in-place within a buffer.
// The plaintext overwrites the ciphertext starting at the returned payloadStart.
type Unpacker interface {
	Headroom() Headroom
	// UnpackInPlace decrypts b[packetStart:packetStart+packetLen] in-place.
	// Returns the start and length of the plaintext payload within b.
	UnpackInPlace(b []byte, packetStart, packetLen int) (payloadStart, payloadLen int, err error)
}

// IVUnpacker is an optional interface implemented by Unpackers that expose
// an IV for replay detection. Non-2022 ciphers use the IV/salt for bloom
// filter checking; 2022 ciphers use packet IDs (sliding window) instead.
type IVUnpacker interface {
	Unpacker
	IV() []byte
}
