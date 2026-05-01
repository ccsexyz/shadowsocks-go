package ss

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	"github.com/ccsexyz/shadowsocks-go/redir"
	"github.com/ccsexyz/shadowsocks-go/zerocopy"
)

var udpWriteBufPool = sync.Pool{
	New: func() any { return make([]byte, 2048) },
}

// Note: UDPConn will drop any packet that is longer than 1500

type UDPConn struct {
	net.PacketConn
	net.Conn
	cfg  *Config
	dst  Addr
	host string

	packerOnce   sync.Once
	cachedPacker zerocopy.Packer
	packerErr    error

	unpackerOnce   sync.Once
	cachedUnpacker zerocopy.Unpacker
	unpackerErr    error
}

func (c *UDPConn) GetCfg() *Config     { return c.cfg }
func (c *UDPConn) SetDst(dst Addr)     { c.dst = dst }
func (c *UDPConn) SetHost(host string) { c.host = host }
func (c *UDPConn) GetDst() Addr        { return c.dst }
func (c *UDPConn) GetHost() string     { return c.host }

func NewUDPConn2(conn net.Conn, c *Config) *UDPConn {
	return &UDPConn{
		Conn: conn,
		cfg:  c,
	}
}

func NewUDPConn3(conn net.PacketConn, c *Config) *UDPConn {
	return &UDPConn{
		PacketConn: conn,
		cfg:        c,
	}
}

func (c *UDPConn) LocalAddr() net.Addr {
	if c.Conn != nil {
		return c.Conn.LocalAddr()
	}
	return c.PacketConn.LocalAddr()
}

func (c *UDPConn) Close() error {
	if c.Conn != nil {
		c.Conn.Close()
	}
	if c.PacketConn != nil {
		c.PacketConn.Close()
	}
	return nil
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *UDPConn) SetDeadline(t time.Time) error {
	if c.PacketConn != nil {
		return c.PacketConn.SetDeadline(t)
	}
	return c.Conn.SetDeadline(t)
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	if c.PacketConn != nil {
		return c.PacketConn.SetReadDeadline(t)
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	if c.PacketConn != nil {
		return c.PacketConn.SetWriteDeadline(t)
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *UDPConn) fakeReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(b)
	return n, nil, err
}

func (c *UDPConn) getPacker() (zerocopy.Packer, error) {
	c.packerOnce.Do(func() {
		c.cachedPacker, c.packerErr = crypto.NewPacker(c.cfg.Method, c.cfg.Password, c.PacketConn != nil)
	})
	return c.cachedPacker, c.packerErr
}

func (c *UDPConn) getUnpacker() (zerocopy.Unpacker, error) {
	c.unpackerOnce.Do(func() {
		c.cachedUnpacker, c.unpackerErr = crypto.NewUnpacker(c.cfg.Method, c.cfg.Password)
	})
	return c.cachedUnpacker, c.unpackerErr
}

func (c *UDPConn) readImpl(b []byte, readfrom func([]byte) (int, net.Addr, error)) (int, net.Addr, error) {
	unpacker, err := c.getUnpacker()
	if err != nil {
		return 0, nil, err
	}

	for {
		n, addr, err := readfrom(b)
		if err != nil {
			return 0, addr, err
		}

		payloadStart, payloadLen, err := unpacker.UnpackInPlace(b, 0, n)
		if err != nil {
			if err == io.ErrShortBuffer {
				continue
			}
			log.Printf("udp readImpl: decrypt error method=%s len=%d err=%v", c.cfg.Method, n, err)
			return 0, addr, err
		}

		if iu, ok := unpacker.(zerocopy.IVUnpacker); ok {
			if iv := iu.IV(); len(iv) > 0 {
				if c.cfg.udpFilterTestAndAdd(iv) {
					continue
				}
			}
		}

		if payloadStart > 0 {
			n = copy(b, b[payloadStart:payloadStart+payloadLen])
			return n, addr, nil
		}
		return payloadLen, addr, nil
	}
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return c.readImpl(b, c.PacketConn.ReadFrom)
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.readImpl(b, c.fakeReadFrom)
	return
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	packer, err := c.getPacker()
	if err != nil {
		log.Printf("udp WriteTo: NewPacker failed method=%s err=%v", c.cfg.Method, err)
		return
	}

	hr := packer.Headroom()
	buf := udpWriteBufPool.Get().([]byte)
	defer udpWriteBufPool.Put(buf)

	totalLen := hr.Front + len(b) + hr.Rear
	if cap(buf) < totalLen {
		buf = make([]byte, totalLen)
	} else {
		buf = buf[:totalLen]
	}

	copy(buf[hr.Front:], b)

	packetStart, packetLen, err := packer.PackInPlace(buf, hr.Front, len(b))
	if err != nil {
		log.Printf("udp WriteTo: PackInPlace failed method=%s len=%d err=%v", c.cfg.Method, len(b), err)
		return
	}

	pkt := buf[packetStart : packetStart+packetLen]
	if addr != nil {
		_, err = c.PacketConn.WriteTo(pkt, addr)
	} else {
		_, err = c.Conn.Write(pkt)
	}
	if err == nil {
		n = len(b)
	}
	return
}

func (c *UDPConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, nil)
}

func (c *UDPConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	var nbytes int
	for _, buf := range bufs {
		nbytes, err = c.Write(buf)
		n += nbytes
		if err != nil {
			return
		}
	}
	return
}

type MultiUDPConn struct {
	net.PacketConn
	c        *Config
	sessions sync.Map
}

func NewMultiUDPConn(conn net.PacketConn, c *Config) *MultiUDPConn {
	return &MultiUDPConn{
		PacketConn: conn,
		c:          c,
	}
}

type multiSession struct {
	cfg      *Config
	packer   zerocopy.Packer
	unpacker zerocopy.Unpacker
	once     sync.Once
	initErr  error
}

func (c *MultiUDPConn) getSession(addrStr string, cfg *Config) *multiSession {
	v, _ := c.sessions.LoadOrStore(addrStr, &multiSession{cfg: cfg})
	s := v.(*multiSession)
	s.once.Do(func() {
		s.packer, s.initErr = crypto.NewPacker(cfg.Method, cfg.Password, true)
		if s.initErr != nil {
			return
		}
		s.unpacker, s.initErr = crypto.NewUnpacker(cfg.Method, cfg.Password)
	})
	return s
}

func (c *MultiUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	b2 := utils.GetBuf(buffersize)
	defer utils.PutBuf(b2)
	for {
		n, addr, err = c.PacketConn.ReadFrom(b2)
		if err != nil {
			return
		}
		v, ok := c.sessions.Load(addr.String())
		if !ok {
			ctx, perr := ParseAddrWithMultipleBackendsForUDP(b2[:n], c.c.Backends)
			if perr != nil {
				log.Printf("udp multi ReadFrom: ParseAddrWithMultipleBackendsForUDP failed: %v", perr)
				continue
			}
			if len(ctx.iv) > 0 {
				if ctx.chs.udpFilterTestAndAdd(ctx.iv) {
					continue
				}
			}
			c.getSession(addr.String(), ctx.chs)
			ctx.chs.LogD("udp mode choose", ctx.chs.Method, ctx.chs.Password)
			n = copy(b, ctx.addr.Hdr)
			n += copy(b[n:], ctx.data)
		} else {
			s := v.(*multiSession)
			if s.initErr != nil {
				log.Printf("udp multi ReadFrom: session init failed: %v", s.initErr)
				err = s.initErr
				return
			}
			payloadStart, payloadLen, uerr := s.unpacker.UnpackInPlace(b2, 0, n)
			if uerr != nil {
				log.Printf("udp multi ReadFrom: decrypt failed method=%s err=%v", s.cfg.Method, uerr)
				err = uerr
				return
			}
			if iu, ok := s.unpacker.(zerocopy.IVUnpacker); ok {
				if iv := iu.IV(); len(iv) > 0 {
					if s.cfg.udpFilterTestAndAdd(iv) {
						continue
					}
				}
			}
			n = copy(b, b2[payloadStart:payloadStart+payloadLen])
		}
		return
	}
}

func (c *MultiUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	v, ok := c.sessions.Load(addr.String())
	if !ok {
		return 0, nil
	}
	s := v.(*multiSession)
	if s.initErr != nil {
		return 0, s.initErr
	}

	hr := s.packer.Headroom()
	buf := udpWriteBufPool.Get().([]byte)
	defer udpWriteBufPool.Put(buf)

	totalLen := hr.Front + len(b) + hr.Rear
	if cap(buf) < totalLen {
		buf = make([]byte, totalLen)
	} else {
		buf = buf[:totalLen]
	}

	copy(buf[hr.Front:], b)

	packetStart, packetLen, perr := s.packer.PackInPlace(buf, hr.Front, len(b))
	if perr != nil {
		return 0, perr
	}
	_, err := c.PacketConn.WriteTo(buf[packetStart:packetStart+packetLen], addr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *MultiUDPConn) RemoveAddr(addr net.Addr) {
	c.sessions.Delete(addr.String())
}

type UDPTProxyConn struct {
	*net.UDPConn
}

func NewUDPTProxyConn(conn *net.UDPConn) (*UDPTProxyConn, error) {
	c := &UDPTProxyConn{UDPConn: conn}
	if err := redir.EnableUDPTProxy(conn); err != nil {
		return nil, err
	}
	return c, nil
}

func (conn *UDPTProxyConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if len(b) < 6 {
		err = fmt.Errorf("the buffer length should be greater than 6")
		return
	}

	header := b[:6]
	b = b[6:]
	oob := make([]byte, 512)

	n, oobn, _, addr, err := conn.UDPConn.ReadMsgUDP(b, oob)
	if err != nil {
		return
	}
	orig, err := redir.GetOrigDstFromOob(oob[:oobn])
	if err != nil {
		return
	}
	copy(header, []byte(orig.IP.To4()))
	binary.BigEndian.PutUint16(header[4:6], uint16(orig.Port))
	n += 6
	return
}

func (conn *UDPTProxyConn) Read(b []byte) (n int, err error) {
	n, _, err = conn.ReadFrom(b)
	return
}
