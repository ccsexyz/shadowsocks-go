package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"math/bits"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// SIP022 UDP session management with sliding-window replay protection.

const (
	udp2022SessionTimeout = 60 * time.Second
	udp2022WindowSize     = 8192 // bits (matches shadowsocks-rust)
)

// Cap on the number of live receive sessions, matching the capacity of
// shadowsocks-rust's CIPHER_CACHE. A var so tests can shrink it.
var udp2022MaxSessions = 102400

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
	recvWindow *slidingWindow // sliding window for incoming packets
	lastSeen   atomic.Int64   // UnixNano of last activity
}

// --- global session manager ---

var udp2022Sessions sync.Map // uint64 (sessionID) → *udpSession
var udp2022SessionCount atomic.Int64
var udp2022Trimming atomic.Bool

func udp2022GetSession(id uint64) *udpSession {
	v, ok := udp2022Sessions.Load(id)
	if !ok {
		return nil
	}
	s := v.(*udpSession)
	s.lastSeen.Store(time.Now().UnixNano())
	return s
}

func udp2022CreateSession(id uint64, sessionKey []byte) *udpSession {
	s := &udpSession{
		sessionKey: sessionKey,
		recvWindow: newSlidingWindow(udp2022WindowSize),
	}
	s.lastSeen.Store(time.Now().UnixNano())
	actual, loaded := udp2022Sessions.LoadOrStore(id, s)
	if loaded {
		return actual.(*udpSession)
	}
	// Bound the table at insert time, not only at the 30s janitor: entries
	// are fed by unauthenticated session IDs (AES separate headers are ECB,
	// not authenticated), so between janitor runs a flood of garbage headers
	// could otherwise grow the table without limit.
	if udp2022SessionCount.Add(1) > int64(udp2022MaxSessions) {
		udp2022TrimSessions()
	}
	return s
}

// udp2022DeleteSession removes a session and keeps the size counter honest.
func udp2022DeleteSession(key any) {
	if _, ok := udp2022Sessions.LoadAndDelete(key); ok {
		udp2022SessionCount.Add(-1)
	}
}

// udp2022TrimSessions evicts the least recently active sessions down to 90%
// of the cap. A flood of new sessions pays at most one O(n log n) pass per
// ~10% of headroom: concurrent trim attempts are collapsed via CAS.
//
// Security note: an evicted session that later receives traffic is recreated
// with an empty replay window, so packets replayed within the ±30s timestamp
// window become acceptable once more. This is the standard tradeoff of a
// bounded session cache (shadowsocks-rust's CIPHER_CACHE behaves the same);
// active sessions keep refreshing lastSeen on every packet, so eviction
// under pressure targets idle ones first.
func udp2022TrimSessions() {
	if !udp2022Trimming.CompareAndSwap(false, true) {
		return
	}
	defer udp2022Trimming.Store(false)
	limit := udp2022MaxSessions - udp2022MaxSessions/10
	type sessionEntry struct {
		key      any
		lastSeen int64
	}
	entries := make([]sessionEntry, 0, 1024)
	udp2022Sessions.Range(func(key, value any) bool {
		entries = append(entries, sessionEntry{key, value.(*udpSession).lastSeen.Load()})
		return true
	})
	if len(entries) <= limit {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].lastSeen < entries[j].lastSeen })
	for _, e := range entries[:len(entries)-limit] {
		udp2022DeleteSession(e.key)
	}
}

func udp2022CleanupSessions() {
	now := time.Now()
	udp2022Sessions.Range(func(key, value any) bool {
		s := value.(*udpSession)
		if now.Sub(time.Unix(0, s.lastSeen.Load())) > udp2022SessionTimeout {
			udp2022DeleteSession(key)
		}
		return true
	})
	if udp2022SessionCount.Load() > int64(udp2022MaxSessions) {
		udp2022TrimSessions()
	}
}

func init() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			udp2022CleanupSessions()
		}
	}()
}

func randomSessionID() uint64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		// crypto/rand does not fail on supported platforms; fall back to the
		// clock instead of recursing.
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(b[:])
}

// --- per-PSK send state ---
// CipherBlock instances are created per-packet, so the outgoing session ID
// and the packet ID counter must persist outside them. The packet ID stays
// monotonic even when the peer-side session entry (udp2022Sessions) expires
// and is recreated: a reset would make the peer's replay window reject every
// subsequent packet. Client and server use separate maps so they don't share
// session IDs (per SIP022 §5.2).

type udpSendState struct {
	sid        uint64
	pid        atomic.Uint64
	keyOnce    sync.Once
	sessionKey []byte // AES methods only: kdf2022(psk, sid), computed once
}

func (st *udpSendState) sessionKeyFor(psk []byte) []byte {
	st.keyOnce.Do(func() {
		st.sessionKey = kdf2022(psk, uint64ToBytes(st.sid), len(psk))
	})
	return st.sessionKey
}

var clientSendStates = map[string]*udpSendState{} // string(psk) → *udpSendState
var serverSendStates = map[string]*udpSendState{} // string(psk) → *udpSendState
var sendStatesMu sync.RWMutex

// sendStateFor returns the per-PSK send state, creating it on first use.
// A plain RWMutex-guarded map (instead of sync.Map) keeps the per-packet
// hit path allocation-free: the map index optimizes string(psk) away, while
// sync.Map's any-typed key/value would box both on every packet.
func sendStateFor(role byte, psk []byte) *udpSendState {
	m := &clientSendStates
	if role != 0 {
		m = &serverSendStates
	}
	sendStatesMu.RLock()
	st, ok := (*m)[string(psk)]
	sendStatesMu.RUnlock()
	if ok {
		return st
	}
	sendStatesMu.Lock()
	defer sendStatesMu.Unlock()
	if st, ok := (*m)[string(psk)]; ok {
		return st
	}
	st = &udpSendState{sid: randomSessionID()}
	(*m)[string(psk)] = st
	return st
}

// --- cipher block implementations ---

// udp2022AESCipherBlock handles SIP022 UDP for AES-GCM methods.
// Wire format: [encrypted separate header (16 bytes)] [encrypted body (+16 byte tag)]
type udp2022AESCipherBlock struct {
	psk   []byte
	block cipher.Block // AES block cipher for separate header
	role  byte         // 0=client, 1=server
}

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

	// decrypt body
	aead := a.getAEAD(s.sessionKey)
	if aead == nil {
		err = io.ErrShortBuffer
		return
	}
	nonce := make([]byte, aead.NonceSize())
	copy(nonce, sepHdr[4:16]) // 12 bytes: sessionID[4:8] + packetID[0:8]
	plaintext, err = aead.Open(dst[:0], nonce, body, nil)
	if err != nil {
		return
	}
	// SIP022: the replay window must not advance before the packet has been
	// authenticated and its main header validated.
	if !validateUDP2022Packet(plaintext) || !s.recvWindow.check(packetID) {
		plaintext = nil
		err = io.ErrShortBuffer
		return
	}
	return
}

func (a *udp2022AESCipherBlock) Encrypt(dst, src []byte) (ciphertext []byte, iv []byte, err error) {
	st := sendStateFor(a.role, a.psk)
	sid := st.sid
	packetID := st.pid.Add(1) - 1
	sessionKey := st.sessionKeyFor(a.psk)

	// construct separate header
	var sepHdr [16]byte
	binary.BigEndian.PutUint64(sepHdr[0:8], sid)
	binary.BigEndian.PutUint64(sepHdr[8:16], packetID)

	// encrypt body
	aead := a.getAEAD(sessionKey)
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

	// Decrypted format: sessionID(8) + packetID(8) + SIP022 packet
	if len(full) < 16 {
		// Too short to carry the session/packet ID prefix: drop it instead
		// of bypassing the replay filter.
		err = io.ErrShortBuffer
		return
	}
	sessionID := binary.BigEndian.Uint64(full[0:8])
	packetID := binary.BigEndian.Uint64(full[8:16])

	s := udp2022GetSession(sessionID)
	if s == nil {
		s = udp2022CreateSession(sessionID, nil)
	}

	// SIP022: the replay window must not advance before the packet has been
	// authenticated and its main header validated.
	if !validateUDP2022Packet(full[16:]) || !s.recvWindow.check(packetID) {
		err = io.ErrShortBuffer
		return
	}

	plaintext = full[16:]
	return
}

func (c *udp2022ChaChaCipherBlock) Encrypt(dst, src []byte) (ciphertext []byte, iv []byte, err error) {
	st := sendStateFor(c.role, c.psk)
	sid := st.sid
	packetID := st.pid.Add(1) - 1

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
