package utils

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bits-and-blooms/bitset"
)

// UDPConn is the union set of net.Conn and net.PacketConn
type UDPConn interface {
	// Read reads data from the connection.
	// Read can be made to time out and return an Error with Timeout() == true
	// after a fixed time limit; see SetDeadline and SetReadDeadline.
	Read(b []byte) (n int, err error)

	// Write writes data to the connection.
	// Write can be made to time out and return an Error with Timeout() == true
	// after a fixed time limit; see SetDeadline and SetWriteDeadline.
	Write(b []byte) (n int, err error)

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error

	// LocalAddr returns the local network address.
	LocalAddr() net.Addr

	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr

	// SetDeadline sets the read and write deadlines associated
	// with the connection. It is equivalent to calling both
	// SetReadDeadline and SetWriteDeadline.
	//
	// A deadline is an absolute time after which I/O operations
	// fail with a timeout (see type Error) instead of
	// blocking. The deadline applies to all future and pending
	// I/O, not just the immediately following call to Read or
	// Write. After a deadline has been exceeded, the connection
	// can be refreshed by setting a deadline in the future.
	//
	// An idle timeout can be implemented by repeatedly extending
	// the deadline after successful Read or Write calls.
	//
	// A zero value for t means I/O operations will not time out.
	SetDeadline(t time.Time) error

	// SetReadDeadline sets the deadline for future Read calls
	// and any currently-blocked Read call.
	// A zero value for t means Read will not time out.
	SetReadDeadline(t time.Time) error

	// SetWriteDeadline sets the deadline for future Write calls
	// and any currently-blocked Write call.
	// Even if write times out, it may return n > 0, indicating that
	// some of the data was successfully written.
	// A zero value for t means Write will not time out.
	SetWriteDeadline(t time.Time) error

	// ReadFrom reads a packet from the connection,
	// copying the payload into b. It returns the number of
	// bytes copied into b and the return address that
	// was on the packet.
	// ReadFrom can be made to time out and return
	// an Error with Timeout() == true after a fixed time limit;
	// see SetDeadline and SetReadDeadline.
	ReadFrom(b []byte) (n int, addr net.Addr, err error)

	// WriteTo writes a packet with payload b to addr.
	// WriteTo can be made to time out and return
	// an Error with Timeout() == true after a fixed time limit;
	// see SetDeadline and SetWriteDeadline.
	// On packet-oriented connections, write timeouts are rare.
	WriteTo(b []byte, addr net.Addr) (n int, err error)
}

// Conn represents a net.Conn that implement WriteBuffers method
// WriteBuffers can write serveral buffers at a time
type Conn interface {
	net.Conn
	WriteBuffers([][]byte) (int, error)
}

// CopyConn implements Conn
type CopyConn struct {
	net.Conn
}

// WriteBuffers directly copy all buffers into a larger buf and send it
func (conn *CopyConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	for _, v := range bufs {
		n += len(v)
	}
	buf := GetBuf(n)
	defer PutBuf(buf)
	n = 0
	for _, v := range bufs {
		n += copy(buf[n:], v)
	}
	n, err = conn.Conn.Write(buf)
	return
}

// UtilsConn is a net.Conn that implement the interface Conn
type UtilsConn struct {
	net.Conn
}

// GetTCPConn try to get the underlying TCPConn
func (conn *UtilsConn) GetTCPConn() (t *net.TCPConn, ok bool) {
	t, ok = conn.Conn.(*net.TCPConn)
	return
}

// WriteBuffers can send serveral buffers at a time
func (conn *UtilsConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	buffers := net.Buffers(bufs)
	var n2 int64
	n2, err = buffers.WriteTo(conn.Conn)
	n = int(n2)
	return
}

// DialTCP calls net.DialTCP and returns *UtilsConn
func DialTCP(network string, laddr, raddr *net.TCPAddr) (conn *UtilsConn, err error) {
	netconn, err := net.DialTCP(network, laddr, raddr)
	if err == nil {
		conn = &UtilsConn{Conn: netconn}
	}
	return
}

// NewConn returns *UtilsConn from net.Conn
func NewConn(conn net.Conn) *UtilsConn {
	return &UtilsConn{Conn: conn}
}

type tmpBuf struct {
	buf []byte
	off int
}

// SubConn is the child connection of a net.PacketConn
type SubConn struct {
	die     chan bool
	pdie    chan bool
	lock    sync.Mutex
	sigch   chan int
	rbuf    []byte
	tmpbufs []tmpBuf
	net.PacketConn
	connsMap *sync.Map
	mtu      int
	raddr    net.Addr
	rtime    time.Time
}

func newSubConn(c net.PacketConn, ctx *UDPServerCtx, raddr net.Addr) *SubConn {
	return &SubConn{
		die:        make(chan bool),
		pdie:       ctx.die,
		sigch:      make(chan int),
		PacketConn: c,
		connsMap:   ctx.connsMap,
		mtu:        ctx.Mtu,
		raddr:      raddr,
	}
}

func (conn *SubConn) input(b []byte) {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	var n int
	if conn.rbuf != nil {
		n = copy(conn.rbuf, b)
		conn.rbuf = nil
		conn.sigch <- n
		return
	}
	var tmpbuf tmpBuf
	tmpbuf.buf = GetBuf(conn.mtu)
	tmpbuf.off = copy(tmpbuf.buf, b)
	conn.tmpbufs = append(conn.tmpbufs, tmpbuf)
}

// Close close the connection and delete it from connsMap
func (conn *SubConn) Close() error {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	select {
	case <-conn.die:
	default:
		close(conn.die)
	}
	if conn.connsMap != nil && conn.raddr != nil {
		conn.connsMap.Delete(conn.raddr.String())
	}
	if len(conn.tmpbufs) != 0 {
		for _, tmpbuf := range conn.tmpbufs {
			PutBuf(tmpbuf.buf)
		}
		conn.tmpbufs = nil
	}
	return nil
}

// RemoteAddr return the address of peer
func (conn *SubConn) RemoteAddr() net.Addr {
	return conn.raddr
}

func (conn *SubConn) Read(b []byte) (n int, err error) {
	conn.lock.Lock()
	if len(conn.tmpbufs) != 0 {
		tmpbuf := conn.tmpbufs[0]
		conn.tmpbufs = conn.tmpbufs[1:]
		n = copy(b, tmpbuf.buf[:tmpbuf.off])
		conn.lock.Unlock()
		PutBuf(tmpbuf.buf)
		return
	}
	conn.rbuf = b
	conn.lock.Unlock()
	var rtch <-chan time.Time
	now := time.Now()
	if !conn.rtime.Equal(time.Time{}) {
		if now.After(conn.rtime) {
			err = fmt.Errorf("timeout")
			return
		}
		rtimer := time.NewTimer(conn.rtime.Sub(now))
		rtch = rtimer.C
		defer rtimer.Stop()
	}
	// defer func() {
	// 	conn.lock.Lock()
	// 	defer conn.lock.Unlock()
	// 	conn.rbuf = nil
	// }()
	select {
	case <-rtch:
		err = fmt.Errorf("timeout")
		return
	case <-conn.die:
		err = fmt.Errorf("closed connection")
		return
	case <-conn.pdie:
		err = fmt.Errorf("closed PacketConn")
		return
	case n = <-conn.sigch:
	}
	return
}

func (conn *SubConn) Write(b []byte) (n int, err error) {
	return conn.PacketConn.WriteTo(b, conn.raddr)
}

// SetReadDeadline set the dealdine of read
func (conn *SubConn) SetReadDeadline(t time.Time) error {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	conn.rtime = t
	return nil
}

// WriteBuffers directly copy all buffers into a larger buf and send it
func (conn *SubConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	for _, v := range bufs {
		n += len(v)
	}
	buf := GetBuf(n)
	defer PutBuf(buf)
	n = 0
	for _, v := range bufs {
		n += copy(buf[n:], v)
	}
	n, err = conn.Write(buf)
	return
}

// FecConn implements FEC decoder and encoder
type FecConn struct {
	net.Conn
	// *config
	fecDecoder *fecDecoder
	fecEncoder *fecEncoder
	checker    *packetIDChecker
	pktid      uint64
	recovers   [][]byte
}

func (c *FecConn) doRead(b []byte) (n int, err error) {
	for n == 0 {
		for len(c.recovers) != 0 {
			r := c.recovers[0]
			c.recovers = c.recovers[1:]
			if len(r) < 2 {
				continue
			}
			sz := int(binary.LittleEndian.Uint16(r))
			if sz < 2 || sz > len(r) {
				continue
			}
			n = copy(b, r[2:sz])
			return
		}
		buf := b
		var num int
		num, err = c.Conn.Read(buf)
		if err != nil || num == 0 {
			return
		}
		if num < fecHeaderSize {
			continue
		}
		f := c.fecDecoder.decodeBytes(buf[:num])
		if f.flag == typeData {
			n = copy(b, buf[fecHeaderSizePlus2:num])
		}
		if f.flag == typeData || f.flag == typeFEC {
			c.recovers = c.fecDecoder.decode(f)
		}
	}
	return
}

func (c *FecConn) Read(b []byte) (n int, err error) {
	for {
		var nr int
		nr, err = c.doRead(b)
		if err != nil {
			return
		}
		if nr < 8 {
			continue
		}
		pktid := binary.BigEndian.Uint64(b[nr-8:])
		if c.checker.test(pktid) == false {
			continue
		}
		n = nr - 8
		return
	}
}

func (c *FecConn) Write(b []byte) (n int, err error) {
	blen := len(b)
	ext := GetBuf(fecHeaderSizePlus2 + blen + 8)
	defer PutBuf(ext)
	ext = ext[:fecHeaderSizePlus2+blen+8]
	copy(ext[fecHeaderSizePlus2:fecHeaderSizePlus2+blen], b)
	pktid := atomic.AddUint64(&c.pktid, 1)
	binary.BigEndian.PutUint64(ext[fecHeaderSizePlus2+blen:], pktid)
	ecc := c.fecEncoder.encode(ext)

	_, err = c.Conn.Write(ext)
	if err != nil {
		return
	}

	for _, e := range ecc {
		_, err = c.Conn.Write(e)
		if err != nil {
			return
		}
	}

	n = blen
	return
}

const maxConv = 4096

type packetIDChecker struct {
	currHead  uint64
	oldIdsSet *bitset.BitSet
	curIdsSet *bitset.BitSet
	lock      sync.Mutex
}

func newPacketIDChecker() *packetIDChecker {
	p := new(packetIDChecker)
	p.oldIdsSet = bitset.New(maxConv)
	p.curIdsSet = bitset.New(maxConv)
	return p
}

func (p *packetIDChecker) testWithLock(id uint64) bool {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.test(id)
}

func (p *packetIDChecker) test(id uint64) bool {
	if id > p.currHead+2*maxConv || id+maxConv < p.currHead {
		return false
	}
	if id < p.currHead {
		off := uint(id + maxConv - p.currHead)
		if p.oldIdsSet.Test(off) {
			return false
		}
		p.oldIdsSet.Set(off)
		return true
	}
	if id >= p.currHead && id < p.currHead+maxConv {
		off := uint(id - p.currHead)
		if p.curIdsSet.Test(off) {
			return false
		}
		p.curIdsSet.Set(off)
		return true
	}
	o := p.oldIdsSet.ClearAll()
	p.oldIdsSet = p.curIdsSet
	p.curIdsSet = o
	p.currHead += maxConv
	return p.test(id)
}

func NewFecConn(conn net.Conn, datashard, parityshard int) *FecConn {
	return &FecConn{
		Conn:       conn,
		fecDecoder: newFECDecoder(3*(datashard+parityshard), datashard, parityshard),
		fecEncoder: newFECEncoder(datashard, parityshard, 0),
		checker:    newPacketIDChecker(),
	}
}

type DupConn struct {
	net.Conn
	magnification int
	pktid         uint64
	checker       *packetIDChecker
}

func (c *DupConn) Read(b []byte) (n int, err error) {
AGAIN:
	nr, err := c.Conn.Read(b)
	if err != nil {
		return
	}
	if nr < 8 {
		goto AGAIN
	}
	pktid := binary.BigEndian.Uint64(b[nr-8 : nr])
	if c.checker.test(pktid) == false {
		goto AGAIN
	}
	n = nr - 8
	return
}

func (c *DupConn) Write(b []byte) (n int, err error) {
	blen := len(b)
	b2 := GetBuf(blen + 8)
	defer PutBuf(b2)
	copy(b2, b)
	for it := 0; it < c.magnification; it++ {
		pktid := atomic.AddUint64(&c.pktid, 1)
		binary.BigEndian.PutUint64(b2[blen:], pktid)
		_, err = c.Conn.Write(b2)
		if err != nil {
			return
		}
	}
	n = blen
	return
}

func NewDupConn(conn net.Conn, magnification int) *DupConn {
	return &DupConn{
		Conn:          conn,
		magnification: magnification,
		checker:       newPacketIDChecker(),
	}
}

// packet
// <pktid 1 byte> -- <pktver 1 byte> -- <pktindex 2 byte>

type SliceConn struct {
	net.Conn
	mtu     int
	pktid   uint8
	pktvers [256]uint8
	rcvpkts [256]struct {
		ver  uint8
		last bool
		bufs [][]byte
	}
}

func decodeSliceConnPacket(pkt []byte) (pktid uint8, pktver uint8, pktindex uint16, last bool) {
	pktid = pkt[0]
	pktver = pkt[1]
	pktindex = binary.BigEndian.Uint16(pkt[2:4])
	if pktindex&1 != 0 {
		last = true
		pktindex--
	}
	pktindex /= 2
	return
}

func encodeSliceConnPacket(pkt []byte, pktid uint8, pktver uint8, pktindex uint16, last bool) {
	pkt[0] = pktid
	pkt[1] = pktver
	pktindex *= 2
	if last {
		pktindex++
	}
	binary.BigEndian.PutUint16(pkt[2:4], pktindex)
}

func (conn *SliceConn) Read(b []byte) (n int, err error) {
	rbuf := GetBuf(65536)
	defer PutBuf(rbuf)
AGAIN:
	nm, err := conn.Conn.Read(rbuf)
	if err != nil {
		return
	}
	if nm < 4 {
		goto AGAIN
	}
	pktid, pktver, index, last := decodeSliceConnPacket(rbuf[nm-4 : nm])
	// log.Println(pktid, pktver, index, last, nm)
	if last && index == 0 {
		n = copy(b, rbuf[:nm-4])
		return
	}
	p := &conn.rcvpkts[pktid]
	if p.ver != pktver {
		p.last = false
		for _, buf := range p.bufs {
			if len(buf) == 0 {
				continue
			}
			PutBuf(buf)
		}
		p.bufs = nil
		p.ver = pktver
	}
	if last {
		p.last = true
	}
	for int(index)+1 > len(p.bufs) {
		p.bufs = append(p.bufs, nil)
	}
	p.bufs[int(index)] = CopyBuffer(rbuf[:nm-4])
	if !p.last {
		goto AGAIN
	}
	for _, buf := range p.bufs {
		if buf == nil {
			goto AGAIN
		}
	}
	for _, buf := range p.bufs {
		n += copy(b[n:], buf)
	}
	p.last = false
	for _, buf := range p.bufs {
		if len(buf) == 0 {
			continue
		}
		PutBuf(buf)
	}
	p.bufs = nil
	return
}

func (conn *SliceConn) Write(b []byte) (n int, err error) {
	wbuf := GetBuf(conn.mtu)
	defer PutBuf(wbuf)
	index := 0
	for len(b) > 0 {
		nm := copy(wbuf[:conn.mtu-4], b)
		b = b[nm:]
		encodeSliceConnPacket(wbuf[nm:nm+4], conn.pktid, conn.pktvers[conn.pktid], uint16(index), len(b) == 0)
		index++
		var nw int
		nw, err = conn.Conn.Write(wbuf[:nm+4])
		if err == nil && nw != nm+4 {
			err = io.ErrShortWrite
		}
		if err != nil {
			return
		}
		n += nm
	}
	conn.pktvers[conn.pktid]++
	conn.pktid++
	return
}

func NewSliceConn(conn net.Conn, mtu int) *SliceConn {
	return &SliceConn{Conn: conn, mtu: mtu}
}

type RandomDropConn struct {
	net.Conn
	rate int
}

func NewRandomDropConn(conn net.Conn, dropRate int) *RandomDropConn {
	if dropRate < 0 {
		dropRate = 0
	} else if dropRate > 100 {
		dropRate = 100
	}
	return &RandomDropConn{Conn: conn, rate: dropRate}
}

func (conn *RandomDropConn) Read(b []byte) (n int, err error) {
AGAIN:
	n, err = conn.Conn.Read(b)
	if err != nil {
		return
	}
	r := rand.Intn(100)
	if r < conn.rate {
		goto AGAIN
	}
	return
}

func (conn *RandomDropConn) Write(b []byte) (n int, err error) {
	r := rand.Intn(100)
	if r < conn.rate {
		return len(b), nil
	}
	return conn.Conn.Write(b)
}

type RateLogConn struct {
	net.Conn
	die  chan struct{}
	nm   sync.Mutex
	name string
	nr   int
	nw   int
}

func (conn *RateLogConn) Close() error {
	conn.nm.Lock()
	defer conn.nm.Unlock()
	select {
	case <-conn.die:
	default:
		close(conn.die)
	}
	return nil
}

func (conn *RateLogConn) Read(b []byte) (n int, err error) {
	defer func() {
		conn.nm.Lock()
		defer conn.nm.Unlock()
		conn.nr += n
	}()
	n, err = conn.Conn.Read(b)
	return
}

func (conn *RateLogConn) Write(b []byte) (n int, err error) {
	defer func() {
		conn.nm.Lock()
		defer conn.nm.Unlock()
		conn.nw += n
	}()
	n, err = conn.Conn.Write(b)
	return
}

func (conn *RateLogConn) GetAndClearNRW() (int, int) {
	conn.nm.Lock()
	defer conn.nm.Unlock()
	nr, nw := conn.nr, conn.nw
	conn.nr, conn.nw = 0, 0
	return nr, nw
}

func NewRateLogConn(conn net.Conn, name string) *RateLogConn {
	rc := &RateLogConn{
		Conn: conn,
		die:  make(chan struct{}),
		name: name,
	}
	return rc
}
