package ss

import (
	"bytes"
	"net"
	"strings"

	"github.com/ccsexyz/utils"
)

type HTTPProxyAcceptor struct{}

func NewHTTPProxyAcceptor() Acceptor {
	return &HTTPProxyAcceptor{}
}

func (h *HTTPProxyAcceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	parser := utils.NewHTTPHeaderParser(utils.GetBuf(bufferSize))
	defer utils.PutBuf(parser.GetBuf())
	buf := utils.GetBuf(bufferSize)
	defer utils.PutBuf(buf)
	b, err := conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	ok, err := parser.Read(b)
	if err != nil {
		return NewRemainConn(conn, b, nil), err
	}
	var requestMethod, requestURI []byte
	if ok {
		requestMethod, err = parser.GetFirstLine1()
		if err == nil {
			requestURI, err = parser.GetFirstLine2()
		}
	}
	if !ok || err != nil {
		return NewRemainConn(conn, b, nil), errNotHTTPPorxy
	}
	uri := utils.SliceToString(requestURI)
	var host, port string
	if bytes.Equal(requestMethod, []byte("CONNECT")) {
		host, port, err = net.SplitHostPort(uri)
		if err != nil {
			return nil, err
		}
		err = WriteString(conn, "HTTP/1.0 200 Connection Established\r\n\r\n")
		if err != nil {
			return nil, err
		}
		ctx.Store(CtxTarget, DstAddr{host: host, port: port})
		return conn, nil
	}
	if bytes.HasPrefix(requestURI, []byte("http://")) {
		requestURI = requestURI[7:]
	}
	it := bytes.IndexByte(requestURI, '/')
	if it < 0 {
		return nil, errNotHTTPPorxy
	}
	ok = parser.StoreFirstline2(requestURI[it:])
	if !ok {
		return nil, errNotHTTPPorxy
	}
	hosts, ok := parser.Load([]byte("Host"))
	if !ok || len(hosts) == 0 || len(hosts[0]) == 0 {
		return nil, errNotHTTPPorxy
	}
	dst := string(hosts[0])
	it = strings.Index(dst, ":")
	if it < 0 {
		dst = dst + ":80"
	}
	host, port, err = net.SplitHostPort(dst)
	if err != nil {
		return nil, err
	}
	proxys, ok := parser.Load([]byte("Proxy-Connection"))
	if ok && len(proxys) > 0 && len(proxys[0]) > 0 {
		parser.Store([]byte("Connection"), proxys[0])
		parser.Delete([]byte("Proxy-Connection"))
	}
	n, err := parser.Encode(buf)
	if err != nil {
		return nil, err
	}
	conn = NewRemainConn(conn, buf[:n], nil)
	ctx.Store(CtxTarget, DstAddr{host: host, port: port})
	return conn, nil
}

type HTTPProxyDialer struct {
	Dialer
	raddr string
}

func NewHTTPProxyDialer(d Dialer, raddr string) Dialer {
	if d == nil {
		d = NewNetDialer()
	}
	return &HTTPProxyDialer{
		Dialer: d,
		raddr:  raddr,
	}
}

func (h *HTTPProxyDialer) Dial(network, target string) (Conn, error) {
	conn, err := h.Dialer.Dial(network, h.raddr)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	err = WriteString(conn, "CONNECT "+target+" HTTP/1.0\r\nUser-agent: shadowsocks-go\r\n\r\n")
	if err != nil {
		return nil, err
	}
	buf := utils.GetBuf(bufferSize)
	defer utils.PutBuf(buf)
	parser := utils.NewHTTPHeaderParser(utils.GetBuf(bufferSize))
	defer utils.PutBuf(parser.GetBuf())
	b, err := conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	ok, err := parser.Read(b)
	if err != nil {
		return nil, err
	}
	if !ok {
		err = errNotHTTPPorxy
		return nil, err
	}
	line2, err := parser.GetFirstLine2()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(line2, []byte("200")) {
		err = errNotHTTPPorxy
		return nil, err
	}
	n := parser.HeaderLen()
	if n < len(b) {
		data := b[n:]
		conn = NewRemainConn(conn, data, nil)
	}
	return conn, nil
}
