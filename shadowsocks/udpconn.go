package ss

import (
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
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
	cachedPacker crypto.Packer
	packerErr    error

	unpackerOnce   sync.Once
	cachedUnpacker crypto.Unpacker
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

func (c *UDPConn) getPacker() (crypto.Packer, error) {
	c.packerOnce.Do(func() {
		c.cachedPacker, c.packerErr = crypto.NewPacker(c.cfg.Method, c.cfg.Password, c.PacketConn != nil)
	})
	return c.cachedPacker, c.packerErr
}

func (c *UDPConn) getUnpacker() (crypto.Unpacker, error) {
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
			// Any unpack failure (bad tag, replay, malformed) is a per-packet
			// condition: drop the datagram and keep the socket alive instead
			// of tearing down the relay.
			if err != io.ErrShortBuffer {
				log.Printf("udp readImpl: drop packet method=%s len=%d err=%v", c.cfg.Method, n, err)
			}
			continue
		}

		if iu, ok := unpacker.(crypto.IVUnpacker); ok {
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

func (c *UDPConn) Read(buf []byte, pool *utils.BufPool) (segs [][]byte, err error) {
	var n int
	n, _, err = c.readImpl(buf, c.fakeReadFrom)
	if err != nil {
		return
	}
	return [][]byte{buf[:n]}, nil
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	packer, err := c.getPacker()
	if err != nil {
		log.Printf("udp WriteTo: NewPacker failed method=%s err=%v", c.cfg.Method, err)
		return
	}

	hr := packer.Headroom()
	buf := udpWriteBufPool.Get().([]byte)
	//lint:ignore SA6002 see PutBuf in buf.go
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

func (c *UDPConn) Write(bufs ...[]byte) (n int, err error) {
	for _, b := range bufs {
		n += len(b)
	}
	b := flatten(bufs)
	_, err = c.WriteTo(b, nil)
	return
}

type MultiUDPConn struct {
	net.PacketConn
	c         *Config
	sessions  sync.Map
	die       chan struct{}
	closeOnce sync.Once
}

func NewMultiUDPConn(conn net.PacketConn, c *Config) *MultiUDPConn {
	mc := &MultiUDPConn{
		PacketConn: conn,
		c:          c,
		die:        make(chan struct{}),
	}
	go mc.cleanupLoop()
	return mc
}

func (c *MultiUDPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.die)
		err = c.PacketConn.Close()
	})
	return err
}

func (c *MultiUDPConn) cleanupLoop() {
	const sessionTimeout = 5 * time.Minute
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.die:
			return
		case <-ticker.C:
		}
		now := time.Now()
		c.sessions.Range(func(key, value any) bool {
			s := value.(*multiSession)
			if now.Sub(s.lastSeen()) > sessionTimeout {
				c.sessions.Delete(key)
			}
			return true
		})
	}
}

type multiSession struct {
	cfg      *Config
	packer   crypto.Packer
	unpacker crypto.Unpacker
	once     sync.Once
	initErr  error
	lastUsed atomic.Int64 // unix nano timestamp
}

func (s *multiSession) lastSeen() time.Time {
	return time.Unix(0, s.lastUsed.Load())
}

func (s *multiSession) touch() {
	s.lastUsed.Store(time.Now().UnixNano())
}

func (c *MultiUDPConn) getSession(addrStr string, cfg *Config) *multiSession {
	v, _ := c.sessions.LoadOrStore(addrStr, &multiSession{cfg: cfg})
	s := v.(*multiSession)
	s.touch()
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
			ctx, perr := ParseAddrWithMultipleBackendsForUDP(b2[:n], c.c.SnapshotBackends())
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
			ctx.chs.LogD("udp mode choose", ctx.chs.Method)
			n = copy(b, ctx.addr.Hdr)
			n += copy(b[n:], ctx.data)
		} else {
			s := v.(*multiSession)
			s.touch()
			if s.initErr != nil {
				log.Printf("udp multi ReadFrom: session init failed: %v", s.initErr)
				err = s.initErr
				return
			}
			payloadStart, payloadLen, uerr := s.unpacker.UnpackInPlace(b2, 0, n)
			if uerr != nil {
				// Replay, bad tag or malformed packet: drop it and keep
				// reading. Escaping the error would end the shared UDP read
				// loop in runUDPServer and take down every session.
				if uerr != io.ErrShortBuffer {
					log.Printf("udp multi ReadFrom: drop packet method=%s len=%d err=%v", s.cfg.Method, n, uerr)
				}
				continue
			}
			if iu, ok := s.unpacker.(crypto.IVUnpacker); ok {
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
	s.touch()
	if s.initErr != nil {
		return 0, s.initErr
	}

	hr := s.packer.Headroom()
	buf := udpWriteBufPool.Get().([]byte)
	//lint:ignore SA6002 see PutBuf in buf.go
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

func listenUDP(c *Config) (net.PacketConn, error) {
	return utils.NewUDPListener(c.Localaddr)
}

func dialUDP(c *Config) (net.Conn, error) {
	return net.Dial("udp", c.Remoteaddr)
}
