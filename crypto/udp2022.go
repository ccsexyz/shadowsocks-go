package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"math/bits"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// SIP022 UDP session management with sliding-window replay protection.

const (
	udp2022SessionTimeout = 60 * time.Second
	udp2022WindowSize     = 8192 // bits (matches shadowsocks-rust)
)

// --- sliding window (ring buffer) ---

const swfBlockBits = 64

type slidingWindow struct {
	mu   sync.Mutex
	last uint64
	ring []uint64
	mask uint64
}

func newSlidingWindow(size uint64) *slidingWindow {
	ringBits := uint64(1 << bits.Len64(size+swfBlockBits-1))
	ringBlocks := ringBits / swfBlockBits
	return &slidingWindow{
		ring: make([]uint64, ringBlocks),
		mask: ringBlocks - 1,
	}
}

func (w *slidingWindow) check(id uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	unmaskedBlock := id / swfBlockBits
	blockIdx := unmaskedBlock & w.mask
	bitIdx := id % swfBlockBits

	if id > w.last {
		// Clear blocks that have fallen out between last and id.
		lastBlock := w.last / swfBlockBits
		clearCount := min(int(unmaskedBlock-lastBlock), len(w.ring))
		for range clearCount {
			lastBlock = (lastBlock + 1) & w.mask
			w.ring[lastBlock] = 0
		}
		w.last = id
	} else {
		if w.last-id >= udp2022WindowSize {
			return false
		}
		if w.ring[blockIdx]&(1<<bitIdx) != 0 {
			return false
		}
	}

	w.ring[blockIdx] |= 1 << bitIdx
	return true
}

// --- session ---

type udpSession struct {
	sessionKey []byte
	sendPID    uint64         // next packet ID for outgoing packets
	recvWindow *slidingWindow // sliding window for incoming packets
	lastSeen   time.Time
	clientAddr string
}

// --- global session manager ---

var udp2022Sessions sync.Map // uint64 (sessionID) → *udpSession

func udp2022GetSession(id uint64) *udpSession {
	v, ok := udp2022Sessions.Load(id)
	if !ok {
		return nil
	}
	s := v.(*udpSession)
	s.lastSeen = time.Now()
	return s
}

func udp2022CreateSession(id uint64, sessionKey []byte) *udpSession {
	s := &udpSession{
		sessionKey: sessionKey,
		lastSeen:   time.Now(),
		recvWindow: newSlidingWindow(udp2022WindowSize),
	}
	udp2022Sessions.Store(id, s)
	return s
}

func udp2022CleanupSessions() {
	now := time.Now()
	udp2022Sessions.Range(func(key, value any) bool {
		s := value.(*udpSession)
		if now.Sub(s.lastSeen) > udp2022SessionTimeout {
			udp2022Sessions.Delete(key)
		}
		return true
	})
}

func init() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			udp2022CleanupSessions()
		}
	}()
}

// strip2022Header removes the SIP022 UDP main header (type + timestamp + paddingLen + padding)
// from b, returning the remaining bytes (ATYP + address + port + payload).
// Returns b unchanged if the header doesn't look like a valid 2022 header.
func strip2022Header(b []byte) []byte {
	if len(b) < 12 || (b[0] != 0 && b[0] != 1) {
		return b
	}
	// Timestamp check: ±30 seconds as required by spec
	ts := int64(binary.BigEndian.Uint64(b[1:9]))
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > 30 {
		return b // timestamp too far off, not a valid 2022 header
	}
	padLen := int(binary.BigEndian.Uint16(b[9:11]))
	if padLen > 900 {
		return b // padding exceeds SIP022 max
	}
	skip := 11 + padLen
	if len(b) < skip+1 {
		return b
	}
	return b[skip:]
}

func randomSessionID() uint64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		// Fallback to timestamp if crypto/rand fails (should never happen)
		return randomSessionID()
	}
	return binary.BigEndian.Uint64(b[:])
}

// --- per-PSK session persistence ---
// CipherBlock instances are created per-packet; outgoing session IDs
// must persist outside the CipherBlock. Client and server use separate
// maps so they don't share session IDs (per SIP022 §5.2).

var clientOutSIDs sync.Map // string(psk) → uint64
var serverOutSIDs sync.Map // string(psk) → uint64

// SessionRole marks a CipherBlock as client-side or server-side.
type SessionRole interface {
	SetServer()
}

func outSIDsFor(role byte) *sync.Map {
	if role == 0 {
		return &clientOutSIDs
	}
	return &serverOutSIDs
}

// --- cipher block implementations ---

// udp2022AESCipherBlock handles SIP022 UDP for AES-GCM methods.
// Wire format: [encrypted separate header (16 bytes)] [encrypted body (+16 byte tag)]
type udp2022AESCipherBlock struct {
	psk   []byte
	block cipher.Block // AES block cipher for separate header
	role  byte         // 0=client, 1=server
}

func (a *udp2022AESCipherBlock) SetServer() { a.role = 1 }

func newUdp2022AESCipherBlock(psk []byte, _ int) (CipherBlock, error) {
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}
	return &udp2022AESCipherBlock{psk: psk, block: block}, nil
}

func (a *udp2022AESCipherBlock) Decrypt(dst, src []byte) (plaintext []byte, iv []byte, err error) {
	if len(src) < 32 { // separate header (16) + at least one AEAD tag (16)
		err = io.ErrShortBuffer
		return
	}

	// decrypt separate header
	var sepHdr [16]byte
	a.block.Decrypt(sepHdr[:], src[:16])
	sessionID := binary.BigEndian.Uint64(sepHdr[0:8])
	packetID := binary.BigEndian.Uint64(sepHdr[8:16])

	body := src[16:]

	// lookup or create session
	s := udp2022GetSession(sessionID)
	if s == nil {
		sessionKey := kdf2022(a.psk, sepHdr[:8], len(a.psk))
		s = udp2022CreateSession(sessionID, sessionKey)
	}

	// replay check on incoming packet
	if !s.recvWindow.check(packetID) {
		// Replay: silently drop (ErrShortBuffer triggers retry in readImpl)
		err = io.ErrShortBuffer
		return
	}

	// decrypt body
	aead := a.getAEAD(s.sessionKey)
	if aead == nil {
		err = io.ErrShortBuffer
		return
	}
	nonce := make([]byte, aead.NonceSize())
	copy(nonce, sepHdr[4:16]) // 12 bytes: sessionID[4:8] + packetID[0:8]
	plaintext, err = aead.Open(dst[:0], nonce, body, nil)
	return
}

func (a *udp2022AESCipherBlock) Encrypt(dst, src []byte) (ciphertext []byte, iv []byte, err error) {
	pskKey := string(a.psk)
	sidAny, _ := outSIDsFor(a.role).LoadOrStore(pskKey, randomSessionID())
	sid := sidAny.(uint64)

	// Lookup or create session; use sendPID for outgoing packet numbering
	s := udp2022GetSession(sid)
	if s == nil {
		sessionKey := kdf2022(a.psk, uint64ToBytes(sid), len(a.psk))
		s = udp2022CreateSession(sid, sessionKey)
	}
	packetID := s.sendPID
	s.sendPID++

	// construct separate header
	var sepHdr [16]byte
	binary.BigEndian.PutUint64(sepHdr[0:8], sid)
	binary.BigEndian.PutUint64(sepHdr[8:16], packetID)

	// encrypt body
	aead := a.getAEAD(s.sessionKey)
	if aead == nil {
		err = io.ErrShortBuffer
		return
	}
	nonce := make([]byte, aead.NonceSize())
	copy(nonce, sepHdr[4:16])
	body := aead.Seal(nil, nonce, src, nil)

	// assemble: encrypted separate header + encrypted body
	outLen := 16 + len(body)
	if len(dst) < outLen {
		dst = make([]byte, outLen)
	}
	var encHdr [16]byte
	a.block.Encrypt(encHdr[:], sepHdr[:])
	copy(dst, encHdr[:])
	copy(dst[16:], body)
	ciphertext = dst[:outLen]
	return
}

func (a *udp2022AESCipherBlock) getAEAD(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	return aead
}

// udp2022ChaChaCipherBlock handles SIP022 UDP for ChaCha20-Poly1305.
// Wire format: [24-byte nonce] [encrypted body]
// Session ID + packet ID are embedded in the plaintext header.
//
// Note: sessionKey is never derived or stored because ChaCha20 uses
// the PSK directly (via chacha20poly1305.NewX), not a derived sub-key.
// The session is used only for sendPID tracking and recvWindow replay protection.
type udp2022ChaChaCipherBlock struct {
	psk  []byte
	role byte // 0=client, 1=server
}

func (c *udp2022ChaChaCipherBlock) SetServer() { c.role = 1 }

func newUdp2022ChaChaCipherBlock(psk []byte, _ int) (CipherBlock, error) {
	return &udp2022ChaChaCipherBlock{psk: psk}, nil
}

func (c *udp2022ChaChaCipherBlock) Decrypt(dst, src []byte) (plaintext []byte, iv []byte, err error) {
	if len(src) < 24+16 { // nonce (24) + at least one AEAD tag
		err = io.ErrShortBuffer
		return
	}

	nonce := src[:24]
	body := src[24:]

	aead, eerr := chacha20poly1305.NewX(c.psk)
	if eerr != nil {
		err = eerr
		return
	}

	full, err := aead.Open(dst[:0], nonce, body, nil)
	if err != nil {
		return
	}

	// Decrypted format: sessionID(8) + packetID(8) + mainHeader + payload
	// Extract and verify session/packet, then strip the 16-byte prefix
	if len(full) < 17 {
		plaintext = full
		return
	}
	sessionID := binary.BigEndian.Uint64(full[0:8])
	packetID := binary.BigEndian.Uint64(full[8:16])

	s := udp2022GetSession(sessionID)
	if s == nil {
		s = udp2022CreateSession(sessionID, nil)
	}

	if !s.recvWindow.check(packetID) {
		err = io.ErrShortBuffer
		return
	}

	plaintext = full[16:]
	return
}

func (c *udp2022ChaChaCipherBlock) Encrypt(dst, src []byte) (ciphertext []byte, iv []byte, err error) {
	pskKey := string(c.psk)
	sidAny, _ := outSIDsFor(c.role).LoadOrStore(pskKey, randomSessionID())
	sid := sidAny.(uint64)

	s := udp2022GetSession(sid)
	if s == nil {
		s = udp2022CreateSession(sid, nil)
	}
	packetID := s.sendPID
	s.sendPID++

	// Prepend session ID + packet ID to plaintext before encrypting
	hdr := make([]byte, 16+len(src))
	binary.BigEndian.PutUint64(hdr[0:8], sid)
	binary.BigEndian.PutUint64(hdr[8:16], packetID)
	copy(hdr[16:], src)

	aead, eerr := chacha20poly1305.NewX(c.psk)
	if eerr != nil {
		err = eerr
		return
	}

	nonce := make([]byte, 24)
	PutRandomBytes(nonce)

	body := aead.Seal(nil, nonce, hdr, nil)

	outLen := 24 + len(body)
	if len(dst) < outLen {
		dst = make([]byte, outLen)
	}
	copy(dst, nonce)
	copy(dst[24:], body)
	ciphertext = dst[:outLen]
	return
}

func uint64ToBytes(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
