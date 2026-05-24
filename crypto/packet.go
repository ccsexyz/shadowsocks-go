package crypto

// Headroom describes the extra space needed before and after the payload
// for protocol headers (Front) and AEAD tags (Rear).
type Headroom struct {
	Front int
	Rear  int
}

// Packer encrypts a plaintext payload in-place within a pre-allocated buffer.
type Packer interface {
	Headroom() Headroom
	PackInPlace(b []byte, payloadStart, payloadLen int) (packetStart, packetLen int, err error)
}

// Unpacker decrypts an encrypted packet in-place within a buffer.
type Unpacker interface {
	Headroom() Headroom
	UnpackInPlace(b []byte, packetStart, packetLen int) (payloadStart, payloadLen int, err error)
}

// IVUnpacker is an optional interface implemented by Unpackers that expose
// an IV for replay detection.
type IVUnpacker interface {
	Unpacker
	IV() []byte
}
