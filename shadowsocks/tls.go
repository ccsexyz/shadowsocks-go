package ss

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ccsexyz/utils"
	"github.com/dustin/randbo"
)

var (
	errNotTLS = errors.New("not tls protocol")
)

type TLSAcceptor struct {
	valid        bool
	calts        tls.Certificate
	ca           *x509.Certificate
	certsMap     map[string]tls.Certificate
	certsMapLock sync.RWMutex
}

func NewTLSAcceptor(rootCa, rootKey string) Acceptor {
	acc := &TLSAcceptor{}
	var err error
	acc.calts, err = tls.LoadX509KeyPair(rootCa, rootKey)
	if err != nil {
		return acc
	}
	acc.ca, err = x509.ParseCertificate(acc.calts.Certificate[0])
	if err != nil {
		return acc
	}
	acc.certsMap = make(map[string]tls.Certificate)
	acc.valid = true
	return acc
}

func (t *TLSAcceptor) genCertificate(serverName string) (tls.Certificate, error) {
	rdbuf := utils.GetRandomBytes(8)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(binary.BigEndian.Uint64(rdbuf))),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{""},
			OrganizationalUnit: []string{""},
			Province:           []string{"CN"},
			CommonName:         serverName,
			Locality:           []string{"CN"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		DNSNames:    []string{serverName},
	}

	priv, _ := rsa.GenerateKey(randbo.New(), 1024)
	pub := &priv.PublicKey

	certB, err := x509.CreateCertificate(rand.Reader, cert, t.ca, pub, t.calts.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certB,
	}
	certM := pem.EncodeToMemory(certPem)

	buf := x509.MarshalPKCS1PrivateKey(priv)
	keyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	}
	keyM := pem.EncodeToMemory(keyPem)

	xcert, err := tls.X509KeyPair(certM, keyM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return xcert, nil
}

func (t *TLSAcceptor) getCertificate(serverName string) (tls.Certificate, error) {
	t.certsMapLock.RLock()
	cert, ok := t.certsMap[serverName]
	t.certsMapLock.RUnlock()
	if ok {
		return cert, nil
	}
	cert, err := t.genCertificate(serverName)
	if err != nil {
		return tls.Certificate{}, err
	}
	t.certsMapLock.Lock()
	certB, ok := t.certsMap[serverName]
	if ok {
		t.certsMapLock.Unlock()
		return certB, nil
	}
	t.certsMap[serverName] = cert
	t.certsMapLock.Unlock()
	return cert, nil
}

func (t *TLSAcceptor) NewTLSServerConn(conn Conn, serverName string) (Conn, error) {
	cert, err := t.getCertificate(serverName)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConn := tls.Server(NewNetConnFromConn(conn), config)
	return NewConnFromNetConn(tlsConn), nil
}

func (t *TLSAcceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	if !t.valid {
		return conn, nil
	}
	buf := utils.GetBuf(bufferSize)
	defer utils.PutBuf(buf)
	b, err := conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	rconn := NewRemainConn(conn, b, nil)
	ok, _, msg := utils.ParseTLSClientHelloMsg(b)
	if !ok || len(msg.ServerName) == 0 {
		return rconn, nil
	}
	log.Println(msg.ServerName)
	conn, err = t.NewTLSServerConn(rconn, msg.ServerName)
	if err != nil {
		return rconn, nil
	}
	ctx.Store("ServerName", msg.ServerName)
	v, ok := ctx.Get(CtxTarget)
	if !ok {
		if !strings.Contains(msg.ServerName, ":") {
			msg.ServerName += ":443"
		}
		ctx.Store(CtxTarget, DstAddr{hostport: msg.ServerName})
	}
	addr := v.(DstAddr)
	addrstr := addr.String()
	ctx.Store(CtxTarget, DstAddr{hostport: "tls://" + addrstr})
	return conn, err
}
