package utils

import (
	"crypto/tls"
	"encoding/binary"
	"strings"
	"time"
)

// copy from crypto/tls

// CurveID is the type of a TLS identifier for an elliptic curve. See
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type CurveID uint16

const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
	X25519    CurveID = 29
)

// Hash functions for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	hashSHA1   uint8 = 2
	hashSHA256 uint8 = 4
	hashSHA384 uint8 = 5
)

// Signature algorithms for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	signatureRSA   uint8 = 1
	signatureECDSA uint8 = 3
)

// signatureAndHash mirrors the TLS 1.2, SignatureAndHashAlgorithm struct. See
// RFC 5246, section A.4.1.
type signatureAndHash struct {
	hash, signature uint8
}

// supportedSignatureAlgorithms contains the signature and hash algorithms that
// the code advertises as supported in a TLS 1.2 ClientHello and in a TLS 1.2
// CertificateRequest.
var supportedSignatureAlgorithms = []signatureAndHash{
	{hashSHA256, signatureRSA},
	{hashSHA256, signatureECDSA},
	{hashSHA384, signatureRSA},
	{hashSHA384, signatureECDSA},
	{hashSHA1, signatureRSA},
	{hashSHA1, signatureECDSA},
}

const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
)

const (
	maxPlaintext    = 16384        // maximum plaintext payload length
	maxCiphertext   = 16384 + 2048 // maximum ciphertext payload length
	recordHeaderLen = 5            // record header length
	maxHandshake    = 65536        // maximum handshake we support (protocol max is 16 MB)

	minVersion = VersionTLS10
	maxVersion = VersionTLS12
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeHelloRequest       uint8 = 0
	typeClientHello        uint8 = 1
	typeServerHello        uint8 = 2
	typeNewSessionTicket   uint8 = 4
	typeCertificate        uint8 = 11
	typeServerKeyExchange  uint8 = 12
	typeCertificateRequest uint8 = 13
	typeServerHelloDone    uint8 = 14
	typeCertificateVerify  uint8 = 15
	typeClientKeyExchange  uint8 = 16
	typeFinished           uint8 = 20
	typeCertificateStatus  uint8 = 22
	typeNextProtocol       uint8 = 67 // Not IANA assigned
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
const (
	extensionServerName          uint16 = 0
	extensionStatusRequest       uint16 = 5
	extensionSupportedCurves     uint16 = 10
	extensionSupportedPoints     uint16 = 11
	extensionSignatureAlgorithms uint16 = 13
	extensionALPN                uint16 = 16
	extensionSCT                 uint16 = 18 // https://tools.ietf.org/html/rfc6962#section-6
	extensionSessionTicket       uint16 = 35
	extensionNextProtoNeg        uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo   uint16 = 0xff01
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

type ClientHelloMsg struct {
	Raw                          []byte
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuites                 []uint16
	CompressionMethods           []uint8
	NextProtoNeg                 bool
	ServerName                   string
	OcspStapling                 bool
	Scts                         bool
	SupportedCurves              []CurveID
	SupportedPoints              []uint8
	TicketSupported              bool
	SessionTicket                []uint8
	SignatureAndHashes           []signatureAndHash
	SecureRenegotiation          []byte
	SecureRenegotiationSupported bool
	AlpnProtocols                []string
}

func (m *ClientHelloMsg) Unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.Raw = data
	m.Vers = uint16(data[4])<<8 | uint16(data[5])
	m.Random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.SessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 2 {
		return false
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}
	numCipherSuites := cipherSuiteLen / 2
	m.CipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.CipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
		if m.CipherSuites[i] == scsvRenegotiation {
			m.SecureRenegotiationSupported = true
		}
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false
	}
	m.CompressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]

	m.NextProtoNeg = false
	m.ServerName = ""
	m.OcspStapling = false
	m.TicketSupported = false
	m.SessionTicket = nil
	m.SignatureAndHashes = nil
	m.AlpnProtocols = nil
	m.Scts = false

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionServerName:
			d := data[:length]
			if len(d) < 2 {
				return false
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return false
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return false
				}
				if nameType == 0 {
					m.ServerName = string(d[:nameLen])
					// An SNI value may not include a
					// trailing dot. See
					// https://tools.ietf.org/html/rfc6066#section-3.
					if strings.HasSuffix(m.ServerName, ".") {
						return false
					}
					break
				}
				d = d[nameLen:]
			}
		case extensionNextProtoNeg:
			if length > 0 {
				return false
			}
			m.NextProtoNeg = true
		case extensionStatusRequest:
			m.OcspStapling = length > 0 && data[0] == statusTypeOCSP
		case extensionSupportedCurves:
			// http://tools.ietf.org/html/rfc4492#section-5.5.1
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l%2 == 1 || length != l+2 {
				return false
			}
			numCurves := l / 2
			m.SupportedCurves = make([]CurveID, numCurves)
			d := data[2:]
			for i := 0; i < numCurves; i++ {
				m.SupportedCurves[i] = CurveID(d[0])<<8 | CurveID(d[1])
				d = d[2:]
			}
		case extensionSupportedPoints:
			// http://tools.ietf.org/html/rfc4492#section-5.5.2
			if length < 1 {
				return false
			}
			l := int(data[0])
			if length != l+1 {
				return false
			}
			m.SupportedPoints = make([]uint8, l)
			copy(m.SupportedPoints, data[1:])
		case extensionSessionTicket:
			// http://tools.ietf.org/html/rfc5077#section-3.2
			m.TicketSupported = true
			m.SessionTicket = data[:length]
		case extensionSignatureAlgorithms:
			// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
			if length < 2 || length&1 != 0 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			n := l / 2
			d := data[2:]
			m.SignatureAndHashes = make([]signatureAndHash, n)
			for i := range m.SignatureAndHashes {
				m.SignatureAndHashes[i].hash = d[0]
				m.SignatureAndHashes[i].signature = d[1]
				d = d[2:]
			}
		case extensionRenegotiationInfo:
			if length == 0 {
				return false
			}
			d := data[:length]
			l := int(d[0])
			d = d[1:]
			if l != len(d) {
				return false
			}

			m.SecureRenegotiation = d
			m.SecureRenegotiationSupported = true
		case extensionALPN:
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			d := data[2:length]
			for len(d) != 0 {
				stringLen := int(d[0])
				d = d[1:]
				if stringLen == 0 || stringLen > len(d) {
					return false
				}
				m.AlpnProtocols = append(m.AlpnProtocols, string(d[:stringLen]))
				d = d[stringLen:]
			}
		case extensionSCT:
			m.Scts = true
			if length != 0 {
				return false
			}
		}
		data = data[length:]
	}

	return true
}

func (m *ClientHelloMsg) Marshal() []byte {
	if m.Raw != nil {
		return m.Raw
	}

	length := 2 + 32 + 1 + len(m.SessionId) + 2 + len(m.CipherSuites)*2 + 1 + len(m.CompressionMethods)
	numExtensions := 0
	extensionsLength := 0
	if m.NextProtoNeg {
		numExtensions++
	}
	if m.OcspStapling {
		extensionsLength += 1 + 2 + 2
		numExtensions++
	}
	if len(m.ServerName) > 0 {
		extensionsLength += 5 + len(m.ServerName)
		numExtensions++
	}
	if len(m.SupportedCurves) > 0 {
		extensionsLength += 2 + 2*len(m.SupportedCurves)
		numExtensions++
	}
	if len(m.SupportedPoints) > 0 {
		extensionsLength += 1 + len(m.SupportedPoints)
		numExtensions++
	}
	if m.TicketSupported {
		extensionsLength += len(m.SessionTicket)
		numExtensions++
	}
	if len(m.SignatureAndHashes) > 0 {
		extensionsLength += 2 + 2*len(m.SignatureAndHashes)
		numExtensions++
	}
	if m.SecureRenegotiationSupported {
		extensionsLength += 1 + len(m.SecureRenegotiation)
		numExtensions++
	}
	if len(m.AlpnProtocols) > 0 {
		extensionsLength += 2
		for _, s := range m.AlpnProtocols {
			if l := len(s); l == 0 || l > 255 {
				panic("invalid ALPN protocol")
			}
			extensionsLength++
			extensionsLength += len(s)
		}
		numExtensions++
	}
	if m.Scts {
		numExtensions++
	}
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeClientHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.Vers >> 8)
	x[5] = uint8(m.Vers)
	copy(x[6:38], m.Random)
	x[38] = uint8(len(m.SessionId))
	copy(x[39:39+len(m.SessionId)], m.SessionId)
	y := x[39+len(m.SessionId):]
	y[0] = uint8(len(m.CipherSuites) >> 7)
	y[1] = uint8(len(m.CipherSuites) << 1)
	for i, suite := range m.CipherSuites {
		y[2+i*2] = uint8(suite >> 8)
		y[3+i*2] = uint8(suite)
	}
	z := y[2+len(m.CipherSuites)*2:]
	z[0] = uint8(len(m.CompressionMethods))
	copy(z[1:], m.CompressionMethods)

	z = z[1+len(m.CompressionMethods):]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.NextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg & 0xff)
		// The length is always 0
		z = z[4:]
	}
	if m.TicketSupported {
		// http://tools.ietf.org/html/rfc5077#section-3.2
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		l := len(m.SessionTicket)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]
		copy(z, m.SessionTicket)
		z = z[len(m.SessionTicket):]
	}
	if len(m.ServerName) > 0 {
		z[0] = byte(extensionServerName >> 8)
		z[1] = byte(extensionServerName & 0xff)
		l := len(m.ServerName) + 5
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		// RFC 3546, section 3.1
		//
		// struct {
		//     NameType name_type;
		//     select (name_type) {
		//         case host_name: HostName;
		//     } name;
		// } ServerName;
		//
		// enum {
		//     host_name(0), (255)
		// } NameType;
		//
		// opaque HostName<1..2^16-1>;
		//
		// struct {
		//     ServerName server_name_list<1..2^16-1>
		// } ServerNameList;

		z[0] = byte((len(m.ServerName) + 3) >> 8)
		z[1] = byte(len(m.ServerName) + 3)
		z[3] = byte(len(m.ServerName) >> 8)
		z[4] = byte(len(m.ServerName))
		copy(z[5:], []byte(m.ServerName))
		z = z[l:]
	}
	if m.OcspStapling {
		// RFC 4366, section 3.6
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z[2] = 0
		z[3] = 5
		z[4] = 1 // OCSP type
		// Two zero valued uint16s for the two lengths.
		z = z[9:]
	}
	if len(m.SupportedCurves) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.1
		z[0] = byte(extensionSupportedCurves >> 8)
		z[1] = byte(extensionSupportedCurves)
		l := 2 + 2*len(m.SupportedCurves)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		z = z[6:]
		for _, curve := range m.SupportedCurves {
			z[0] = byte(curve >> 8)
			z[1] = byte(curve)
			z = z[2:]
		}
	}
	if len(m.SupportedPoints) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.2
		z[0] = byte(extensionSupportedPoints >> 8)
		z[1] = byte(extensionSupportedPoints)
		l := 1 + len(m.SupportedPoints)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l--
		z[4] = byte(l)
		z = z[5:]
		for _, pointFormat := range m.SupportedPoints {
			z[0] = pointFormat
			z = z[1:]
		}
	}
	if len(m.SignatureAndHashes) > 0 {
		// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		z[0] = byte(extensionSignatureAlgorithms >> 8)
		z[1] = byte(extensionSignatureAlgorithms)
		l := 2 + 2*len(m.SignatureAndHashes)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		l -= 2
		z[0] = byte(l >> 8)
		z[1] = byte(l)
		z = z[2:]
		for _, sigAndHash := range m.SignatureAndHashes {
			z[0] = sigAndHash.hash
			z[1] = sigAndHash.signature
			z = z[2:]
		}
	}
	if m.SecureRenegotiationSupported {
		z[0] = byte(extensionRenegotiationInfo >> 8)
		z[1] = byte(extensionRenegotiationInfo & 0xff)
		z[2] = 0
		z[3] = byte(len(m.SecureRenegotiation) + 1)
		z[4] = byte(len(m.SecureRenegotiation))
		z = z[5:]
		copy(z, m.SecureRenegotiation)
		z = z[len(m.SecureRenegotiation):]
	}
	if len(m.AlpnProtocols) > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN & 0xff)
		lengths := z[2:]
		z = z[6:]

		stringsLength := 0
		for _, s := range m.AlpnProtocols {
			l := len(s)
			z[0] = byte(l)
			copy(z[1:], s)
			z = z[1+l:]
			stringsLength += 1 + l
		}

		lengths[2] = byte(stringsLength >> 8)
		lengths[3] = byte(stringsLength)
		stringsLength += 2
		lengths[0] = byte(stringsLength >> 8)
		lengths[1] = byte(stringsLength)
	}
	if m.Scts {
		// https://tools.ietf.org/html/rfc6962#section-3.3.1
		z[0] = byte(extensionSCT >> 8)
		z[1] = byte(extensionSCT)
		// zero uint16 for the zero-length extension_data
		z = z[4:]
	}

	m.Raw = x

	return x
}

// ParseTLSClientHelloMsg scan the buffer and try to parse TLS Client Hello Message
// ok returns false if it's not tls hello msg
func ParseTLSClientHelloMsg(b []byte) (ok bool, n int, msg *ClientHelloMsg) {
	if len(b) < 5 {
		return
	}

	rtype := recordType(b[0])
	if rtype != recordTypeHandshake {
		return
	}

	version := int(binary.BigEndian.Uint16(b[1:3]))
	if version < VersionSSL30 || version > VersionTLS12+1 {
		return
	}

	n = int(binary.BigEndian.Uint16(b[3:5])) + 5
	if len(b) < n {
		return
	}

	msg = new(ClientHelloMsg)
	ok = msg.Unmarshal(b[5:n])

	if !ok {
		msg = nil
	}

	return
}

type Extension struct {
	Type   uint16
	Length uint16
	Data   []byte
}

type ServerHelloMsg struct {
	Raw                          []byte
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuite                  uint16
	CompressionMethod            uint8
	NextProtoNeg                 bool
	NextProtos                   []string
	OcspStapling                 bool
	Scts                         [][]byte
	TicketSupported              bool
	SecureRenegotiation          []byte
	SecureRenegotiationSupported bool
	AlpnProtocol                 string
	OtherExtensions              []Extension
}

func (m *ServerHelloMsg) Marshal() []byte {
	if m.Raw != nil {
		return m.Raw
	}

	length := 38 + len(m.SessionId)
	numExtensions := 0
	extensionsLength := 0

	nextProtoLen := 0
	if m.NextProtoNeg {
		numExtensions++
		for _, v := range m.NextProtos {
			nextProtoLen += len(v)
		}
		nextProtoLen += len(m.NextProtos)
		extensionsLength += nextProtoLen
	}
	for _, ext := range m.OtherExtensions {
		numExtensions++
		extensionsLength += int(ext.Length)
	}
	if m.OcspStapling {
		numExtensions++
	}
	if m.TicketSupported {
		numExtensions++
	}
	if m.SecureRenegotiationSupported {
		extensionsLength += 1 + len(m.SecureRenegotiation)
		numExtensions++
	}
	if alpnLen := len(m.AlpnProtocol); alpnLen > 0 {
		if alpnLen >= 256 {
			panic("invalid ALPN protocol")
		}
		extensionsLength += 2 + 1 + alpnLen
		numExtensions++
	}
	sctLen := 0
	if len(m.Scts) > 0 {
		for _, sct := range m.Scts {
			sctLen += len(sct) + 2
		}
		extensionsLength += 2 + sctLen
		numExtensions++
	}

	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeServerHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.Vers >> 8)
	x[5] = uint8(m.Vers)
	copy(x[6:38], m.Random)
	x[38] = uint8(len(m.SessionId))
	copy(x[39:39+len(m.SessionId)], m.SessionId)
	z := x[39+len(m.SessionId):]
	z[0] = uint8(m.CipherSuite >> 8)
	z[1] = uint8(m.CipherSuite)
	z[2] = m.CompressionMethod

	z = z[3:]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.NextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg & 0xff)
		z[2] = byte(nextProtoLen >> 8)
		z[3] = byte(nextProtoLen)
		z = z[4:]

		for _, v := range m.NextProtos {
			l := len(v)
			if l > 255 {
				l = 255
			}
			z[0] = byte(l)
			copy(z[1:], []byte(v[0:l]))
			z = z[1+l:]
		}
	}
	if m.OcspStapling {
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z = z[4:]
	}
	if m.TicketSupported {
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		z = z[4:]
	}
	if m.SecureRenegotiationSupported {
		z[0] = byte(extensionRenegotiationInfo >> 8)
		z[1] = byte(extensionRenegotiationInfo & 0xff)
		z[2] = 0
		z[3] = byte(len(m.SecureRenegotiation) + 1)
		z[4] = byte(len(m.SecureRenegotiation))
		z = z[5:]
		copy(z, m.SecureRenegotiation)
		z = z[len(m.SecureRenegotiation):]
	}
	if alpnLen := len(m.AlpnProtocol); alpnLen > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN & 0xff)
		l := 2 + 1 + alpnLen
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		l -= 1
		z[6] = byte(l)
		copy(z[7:], []byte(m.AlpnProtocol))
		z = z[7+alpnLen:]
	}
	if sctLen > 0 {
		z[0] = byte(extensionSCT >> 8)
		z[1] = byte(extensionSCT)
		l := sctLen + 2
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z[4] = byte(sctLen >> 8)
		z[5] = byte(sctLen)

		z = z[6:]
		for _, sct := range m.Scts {
			z[0] = byte(len(sct) >> 8)
			z[1] = byte(len(sct))
			copy(z[2:], sct)
			z = z[len(sct)+2:]
		}
	}
	for _, ext := range m.OtherExtensions {
		z[0] = byte(ext.Type >> 8)
		z[1] = byte(ext.Type & 0xff)
		z[2] = byte(ext.Length >> 8)
		z[3] = byte(ext.Length & 0xff)
		nc := copy(z[4:], ext.Data)
		z = z[4+nc:]
	}

	m.Raw = x

	return x
}

func (m *ServerHelloMsg) Unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.Raw = data
	m.Vers = uint16(data[4])<<8 | uint16(data[5])
	m.Random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.SessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 3 {
		return false
	}
	m.CipherSuite = uint16(data[0])<<8 | uint16(data[1])
	m.CompressionMethod = data[2]
	data = data[3:]

	m.NextProtoNeg = false
	m.NextProtos = nil
	m.OcspStapling = false
	m.Scts = nil
	m.TicketSupported = false
	m.AlpnProtocol = ""

	if len(data) == 0 {
		// ServerHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) != extensionsLength {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionNextProtoNeg:
			m.NextProtoNeg = true
			d := data[:length]
			for len(d) > 0 {
				l := int(d[0])
				d = d[1:]
				if l == 0 || l > len(d) {
					return false
				}
				m.NextProtos = append(m.NextProtos, string(d[:l]))
				d = d[l:]
			}
		case extensionStatusRequest:
			if length > 0 {
				return false
			}
			m.OcspStapling = true
		case extensionSessionTicket:
			if length > 0 {
				return false
			}
			m.TicketSupported = true
		case extensionRenegotiationInfo:
			if length == 0 {
				return false
			}
			d := data[:length]
			l := int(d[0])
			d = d[1:]
			if l != len(d) {
				return false
			}

			m.SecureRenegotiation = d
			m.SecureRenegotiationSupported = true
		case extensionALPN:
			d := data[:length]
			if len(d) < 3 {
				return false
			}
			l := int(d[0])<<8 | int(d[1])
			if l != len(d)-2 {
				return false
			}
			d = d[2:]
			l = int(d[0])
			if l != len(d)-1 {
				return false
			}
			d = d[1:]
			if len(d) == 0 {
				// ALPN protocols must not be empty.
				return false
			}
			m.AlpnProtocol = string(d)
		case extensionSCT:
			d := data[:length]

			if len(d) < 2 {
				return false
			}
			l := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != l || l == 0 {
				return false
			}

			m.Scts = make([][]byte, 0, 3)
			for len(d) != 0 {
				if len(d) < 2 {
					return false
				}
				sctLen := int(d[0])<<8 | int(d[1])
				d = d[2:]
				if sctLen == 0 || len(d) < sctLen {
					return false
				}
				m.Scts = append(m.Scts, d[:sctLen])
				d = d[sctLen:]
			}
		default:
			m.OtherExtensions = append(m.OtherExtensions, Extension{
				Type:   extension,
				Length: uint16(length),
				Data:   data[:length],
			})
		}
		data = data[length:]
	}

	return true
}

// ParseTLSServerHelloMsg scan the buffer and try to parse TLS ServerHello Message
// ok returns false if it's not tls server hello msg
func ParseTLSServerHelloMsg(b []byte) (ok bool, n int, msg *ServerHelloMsg) {
	if len(b) < 5 {
		return
	}

	rtype := recordType(b[0])
	if rtype != recordTypeHandshake {
		return
	}

	version := int(binary.BigEndian.Uint16(b[1:3]))
	if version < VersionSSL30 || version > VersionTLS12+1 {
		return
	}

	n = int(binary.BigEndian.Uint16(b[3:5])) + 5
	if len(b) < n {
		return
	}

	msg = new(ServerHelloMsg)
	ok = msg.Unmarshal(b[5:n])

	if !ok {
		msg = nil
	}

	return
}

// GenTLSServerHello generate tls server hello for simple-obfs
// note: the function don't check the length of buffer
func GenTLSServerHello(b []byte, l int, sessionID []byte) int {
	n := 0
	msg := new(ServerHelloMsg)
	msg.CipherSuite = tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
	msg.Vers = tls.VersionTLS12
	msg.SecureRenegotiationSupported = true
	msg.OtherExtensions = []Extension{
		{Type: 0x17, Length: 0},
		{Type: 0x0B, Length: 2, Data: []byte{1, 0}},
	}
	if len(sessionID) != 0 {
		msg.SessionId = sessionID
	} else {
		msg.SessionId = GetRandomBytes(32)
	}
	msg.Random = GetRandomBytes(32)
	binary.BigEndian.PutUint32(msg.Random, uint32(time.Now().Unix()))

	b[0] = 0x16
	binary.BigEndian.PutUint16(b[1:], VersionTLS10)
	binary.BigEndian.PutUint16(b[3:], uint16(len(msg.Marshal())))
	copy(b[5:], msg.Marshal())
	n = len(msg.Marshal()) + 5
	b = b[n:]

	b[0] = 0x14
	binary.BigEndian.PutUint16(b[1:], VersionTLS12)
	binary.BigEndian.PutUint16(b[3:], 1)
	b[6] = 0x1
	n += 6
	b = b[6:]

	b[0] = 0x16
	binary.BigEndian.PutUint16(b[1:], VersionTLS12)
	binary.BigEndian.PutUint16(b[3:], uint16(l))
	n += 5

	return n
}

func GenTLSClientHello(b []byte, serverName string, sessionID []byte, sessionTicket []byte) int {
	n := 0
	msg := new(ClientHelloMsg)
	msg.Vers = tls.VersionTLS12
	msg.CipherSuites = []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,

		// dirty hack to make simple-obfs happy
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}
	msg.CompressionMethods = []uint8{0}
	msg.SessionId = sessionID
	msg.SessionTicket = sessionTicket
	msg.TicketSupported = true
	msg.ServerName = serverName
	msg.SupportedCurves = []CurveID{
		CurveP256,
		CurveP384,
		CurveP521,
		X25519,
	}
	msg.SupportedPoints = []uint8{0x01, 0x00, 0x02}
	msg.SignatureAndHashes = []signatureAndHash{
		{hashSHA256, signatureRSA},
		{hashSHA256, signatureECDSA},
		{hashSHA384, signatureRSA},
		{hashSHA384, signatureECDSA},
		{hashSHA1, signatureRSA},
		{hashSHA1, signatureECDSA},
	}
	msg.Random = GetRandomBytes(32)
	binary.BigEndian.PutUint32(msg.Random, uint32(time.Now().Unix()))
	b[0] = 0x16
	binary.BigEndian.PutUint16(b[1:], VersionTLS10)
	binary.BigEndian.PutUint16(b[3:], uint16(len(msg.Marshal())))
	copy(b[5:], msg.Marshal())
	n = len(msg.Marshal()) + 5
	return n
}
