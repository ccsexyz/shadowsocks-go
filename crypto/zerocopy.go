package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/ccsexyz/shadowsocks-go/zerocopy"
	"golang.org/x/crypto/chacha20poly1305"
)

// --- plain (no-op) ---

type plainPacker struct{}

func (plainPacker) Headroom() zerocopy.Headroom { return zerocopy.Headroom{} }

func (plainPacker) PackInPlace(b []byte, payloadStart, payloadLen int) (packetStart, packetLen int, err error) {
	return payloadStart, payloadLen, nil
}

type plainUnpacker struct{}

func (plainUnpacker) Headroom() zerocopy.Headroom { return zerocopy.Headroom{} }

func (plainUnpacker) UnpackInPlace(b []byte, packetStart, packetLen int) (payloadStart, payloadLen int, err error) {
	return packetStart, packetLen, nil
}

// --- AEAD (aes-*-gcm, chacha20-ietf-poly1305) ---

type aeadPacker struct {
	key     []byte
	ivlen   int
	newAEAD func(key []byte) (cipher.AEAD, error)
}

func (p *aeadPacker) Headroom() zerocopy.Headroom {
	return zerocopy.Headroom{Front: p.ivlen, Rear: 16}
}

func (p *aeadPacker) PackInPlace(b []byte, payloadStart, payloadLen int) (packetStart, packetLen int, err error) {
	ivLen := p.ivlen
	ivBuf := b[payloadStart-ivLen : payloadStart]
	PutRandomBytes(ivBuf)

	subKey := aeadKey(p.key, ivBuf)
	aead, err := p.newAEAD(subKey)
	if err != nil {
		return 0, 0, err
	}

	plaintext := b[payloadStart : payloadStart+payloadLen]
	aead.Seal(plaintext[:0], zeroBuf[:aead.NonceSize()], plaintext, nil)
	return payloadStart - ivLen, ivLen + payloadLen + aead.Overhead(), nil
}

type aeadUnpacker struct {
	key     []byte
	ivlen   int
	newAEAD func(key []byte) (cipher.AEAD, error)
	iv      []byte
}

func (u *aeadUnpacker) Headroom() zerocopy.Headroom {
	return zerocopy.Headroom{Front: u.ivlen, Rear: 16}
}

func (u *aeadUnpacker) UnpackInPlace(b []byte, packetStart, packetLen int) (payloadStart, payloadLen int, err error) {
	ivLen := u.ivlen
	u.iv = b[packetStart : packetStart+ivLen]

	subKey := aeadKey(u.key, u.iv)
	aead, err := u.newAEAD(subKey)
	if err != nil {
		return 0, 0, err
	}

	body := b[packetStart+ivLen : packetStart+packetLen]
	_, err = aead.Open(body[:0], zeroBuf[:aead.NonceSize()], body, nil)
	if err != nil {
		return 0, 0, err
	}
	return packetStart + ivLen, packetLen - ivLen - aead.Overhead(), nil
}

func (u *aeadUnpacker) IV() []byte { return u.iv }

var _ zerocopy.IVUnpacker = (*aeadUnpacker)(nil)

// --- 2022 AES-GCM ---

type udp2022AESPacker struct {
	psk  []byte
	role byte
}

func (p *udp2022AESPacker) Headroom() zerocopy.Headroom {
	return zerocopy.Headroom{Front: 16, Rear: 16}
}

func (p *udp2022AESPacker) PackInPlace(b []byte, payloadStart, payloadLen int) (packetStart, packetLen int, err error) {
	pskKey := string(p.psk)
	sidAny, _ := outSIDsFor(p.role).LoadOrStore(pskKey, randomSessionID())
	sid := sidAny.(uint64)

	s := udp2022GetSession(sid)
	if s == nil {
		sessionKey := kdf2022(p.psk, uint64ToBytes(sid), len(p.psk))
		s = udp2022CreateSession(sid, sessionKey)
	}
	pid := s.sendPID
	s.sendPID++

	sepHdr := b[payloadStart-16 : payloadStart]
	binary.BigEndian.PutUint64(sepHdr[0:8], sid)
	binary.BigEndian.PutUint64(sepHdr[8:16], pid)

	nonce := sepHdr[4:16]

	aead := getAESGCM(s.sessionKey)
	if aead == nil {
		return 0, 0, io.ErrShortBuffer
	}

	plaintext := b[payloadStart : payloadStart+payloadLen]
	aead.Seal(plaintext[:0], nonce, plaintext, nil)

	block, _ := aes.NewCipher(p.psk)
	block.Encrypt(sepHdr, sepHdr)

	return payloadStart - 16, 16 + payloadLen + aead.Overhead(), nil
}

type udp2022AESUnpacker struct {
	psk     []byte
	session *udpSession
}

func (u *udp2022AESUnpacker) Headroom() zerocopy.Headroom {
	return zerocopy.Headroom{Front: 16, Rear: 16}
}

func (u *udp2022AESUnpacker) UnpackInPlace(b []byte, packetStart, packetLen int) (payloadStart, payloadLen int, err error) {
	if packetLen < 32 {
		return 0, 0, io.ErrShortBuffer
	}

	sepHdr := b[packetStart : packetStart+16]
	var decHdr [16]byte
	block, _ := aes.NewCipher(u.psk)
	block.Decrypt(decHdr[:], sepHdr)

	sessionID := binary.BigEndian.Uint64(decHdr[0:8])
	packetID := binary.BigEndian.Uint64(decHdr[8:16])

	s := udp2022GetSession(sessionID)
	if s == nil {
		sessionKey := kdf2022(u.psk, decHdr[:8], len(u.psk))
		s = udp2022CreateSession(sessionID, sessionKey)
	}
	u.session = s

	if !s.recvWindow.check(packetID) {
		return 0, 0, io.ErrShortBuffer
	}

	aead := getAESGCM(s.sessionKey)
	if aead == nil {
		return 0, 0, io.ErrShortBuffer
	}

	nonce := decHdr[4:16]
	body := b[packetStart+16 : packetStart+packetLen]
	plaintext, err := aead.Open(body[:0], nonce, body, nil)
	if err != nil {
		return 0, 0, err
	}

	return packetStart + 16 + (len(body) - len(plaintext) - aead.Overhead()), len(plaintext), nil
}

// --- 2022 ChaCha20-Poly1305 ---

type udp2022ChaChaPacker struct {
	psk  []byte
	role byte
}

func (p *udp2022ChaChaPacker) Headroom() zerocopy.Headroom {
	return zerocopy.Headroom{Front: 40, Rear: 16}
}

func (p *udp2022ChaChaPacker) PackInPlace(b []byte, payloadStart, payloadLen int) (packetStart, packetLen int, err error) {
	pskKey := string(p.psk)
	sidAny, _ := outSIDsFor(p.role).LoadOrStore(pskKey, randomSessionID())
	sid := sidAny.(uint64)

	s := udp2022GetSession(sid)
	if s == nil {
		s = udp2022CreateSession(sid, nil)
	}
	pid := s.sendPID
	s.sendPID++

	nonce := b[payloadStart-40 : payloadStart-16]
	PutRandomBytes(nonce)

	prefixed := b[payloadStart-16 : payloadStart+payloadLen]
	binary.BigEndian.PutUint64(prefixed[0:8], sid)
	binary.BigEndian.PutUint64(prefixed[8:16], pid)

	aead, err := chacha20poly1305.NewX(p.psk)
	if err != nil {
		return 0, 0, err
	}

	body := aead.Seal(prefixed[:0], nonce, prefixed, nil)
	return payloadStart - 40, 24 + len(body), nil
}

type udp2022ChaChaUnpacker struct {
	psk     []byte
	session *udpSession
}

func (u *udp2022ChaChaUnpacker) Headroom() zerocopy.Headroom {
	return zerocopy.Headroom{Front: 40, Rear: 16}
}

func (u *udp2022ChaChaUnpacker) UnpackInPlace(b []byte, packetStart, packetLen int) (payloadStart, payloadLen int, err error) {
	if packetLen < 56 {
		return 0, 0, io.ErrShortBuffer
	}

	nonce := b[packetStart : packetStart+24]
	body := b[packetStart+24 : packetStart+packetLen]

	aead, err := chacha20poly1305.NewX(u.psk)
	if err != nil {
		return 0, 0, err
	}

	full, err := aead.Open(body[:0], nonce, body, nil)
	if err != nil {
		return 0, 0, err
	}

	if len(full) < 17 {
		return packetStart + 24, len(full), nil
	}

	sessionID := binary.BigEndian.Uint64(full[0:8])
	packetID := binary.BigEndian.Uint64(full[8:16])

	s := udp2022GetSession(sessionID)
	if s == nil {
		s = udp2022CreateSession(sessionID, nil)
	}
	u.session = s

	if !s.recvWindow.check(packetID) {
		return 0, 0, io.ErrShortBuffer
	}

	plaintext := full[16:]
	return packetStart + 24 + (len(body) - len(plaintext) - aead.Overhead()), len(plaintext), nil
}

// --- helpers ---

func getAESGCM(key []byte) cipher.AEAD {
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

func getAESGCMErr(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// --- factory functions ---

// NewPacker returns a Packer for the given method.
func NewPacker(method, password string, isServer bool) (zerocopy.Packer, error) {
	m, ok := cipherMethod[method]
	if !ok {
		m = cipherMethod[DefaultMethod]
	}

	if m.is2022 {
		psk, err := DecodePSK(password, m.keylen)
		if err != nil {
			return nil, err
		}
		role := byte(0)
		if isServer {
			role = 1
		}
		switch method {
		case "2022-blake3-chacha20-poly1305":
			return &udp2022ChaChaPacker{psk: psk, role: role}, nil
		default:
			return &udp2022AESPacker{psk: psk, role: role}, nil
		}
	}

	if method == "plain" {
		return plainPacker{}, nil
	}

	key := kdf(password, m.keylen)
	var newAEAD func(key []byte) (cipher.AEAD, error)
	switch method {
	case "chacha20-ietf-poly1305":
		newAEAD = chacha20poly1305.New
	default:
		newAEAD = func(k []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(k)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	}

	return &aeadPacker{key: key, ivlen: m.ivlen, newAEAD: newAEAD}, nil
}

// NewUnpacker returns an Unpacker for the given method.
func NewUnpacker(method, password string) (zerocopy.Unpacker, error) {
	m, ok := cipherMethod[method]
	if !ok {
		m = cipherMethod[DefaultMethod]
	}

	if m.is2022 {
		psk, err := DecodePSK(password, m.keylen)
		if err != nil {
			return nil, err
		}
		switch method {
		case "2022-blake3-chacha20-poly1305":
			return &udp2022ChaChaUnpacker{psk: psk}, nil
		default:
			return &udp2022AESUnpacker{psk: psk}, nil
		}
	}

	if method == "plain" {
		return plainUnpacker{}, nil
	}

	key := kdf(password, m.keylen)
	var newAEAD func(key []byte) (cipher.AEAD, error)
	switch method {
	case "chacha20-ietf-poly1305":
		newAEAD = chacha20poly1305.New
	default:
		newAEAD = func(k []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(k)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	}

	return &aeadUnpacker{key: key, ivlen: m.ivlen, newAEAD: newAEAD}, nil
}
