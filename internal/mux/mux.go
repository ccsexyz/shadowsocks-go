package mux

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

const (
	msyn = iota
	mpsh = iota
	mnop = iota
	mrst = iota
	mpse = iota // pause
	mrep = iota // reply
)

// mux packet
// Type (1byte) -- ID (2bytes) -- Version (1 byte) -- Len (2bytes) -- Data (n bytes)

const (
	pktHdrlen  = 6
	buffersize = 65536
	maxSeglen  = 32768
)

type packet struct {
	pktype   uint8
	pktid    uint16
	pktver   uint8
	pktlen   uint16
	payloads [][]byte
	die      chan bool
	sig      chan bool
}

func packetUnmarshal(b []byte) packet {
	return packet{
		pktype: b[0],
		pktid:  binary.BigEndian.Uint16(b[1:]),
		pktver: b[3],
		pktlen: binary.BigEndian.Uint16(b[4:]),
	}
}

func (p *packet) marshal(b []byte) {
	b[0] = p.pktype
	binary.BigEndian.PutUint16(b[1:], p.pktid)
	b[3] = p.pktver
	binary.BigEndian.PutUint16(b[4:], p.pktlen)
}

type Mux struct {
	net.Conn  // underlying connection, must be reliable
	lock      sync.Mutex
	wlock     sync.Mutex
	writech   chan packet
	die       chan bool
	destroy   bool
	avalid    uint16
	acceptch  chan *MuxConn
	async     utils.AsyncRunner
	connsLock sync.Mutex
	conns     map[uint16]*MuxConn
	connVers  map[uint16]uint8
	pool      sync.Pool
}

func NewMux(conn net.Conn) (mux *Mux, err error) {
	mux = &Mux{
		Conn:     conn,
		die:      make(chan bool),
		writech:  make(chan packet, 16),
		acceptch: make(chan *MuxConn),
		conns:    make(map[uint16]*MuxConn),
		connVers: make(map[uint16]uint8),
		pool:     sync.Pool{New: func() interface{} { return make([]byte, 4096) }},
	}
	go mux.writeLoop()
	defer func() {
		if err != nil {
			mux.Close()
			mux = nil
		}
	}()
	for {
		id := uint16(rand.Intn(32768))
		err = mux.writePacket(packet{
			pktid:  id,
			pktype: msyn,
		})
		var pkt packet
		pkt, err = mux.readPacket()
		if pkt.pktype != msyn {
			err = fmt.Errorf("wrong protocol")
			return
		}
		if id > pkt.pktid {
			mux.avalid = 0
		} else if id < pkt.pktid {
			mux.avalid = 1
		} else {
			continue
		}
		break
	}
	go mux.readLoop()
	return
}

func (mux *Mux) NumOfConns() int {
	mux.connsLock.Lock()
	defer mux.connsLock.Unlock()
	return len(mux.conns)
}

func (mux *Mux) Close() (err error) {
	mux.lock.Lock()
	if mux.destroy {
		mux.lock.Unlock()
		return
	}
	mux.destroy = true
	mux.lock.Unlock()
	select {
	default:
		close(mux.die)
	case <-mux.die:
		return
	}
	err = mux.Conn.Close()
	var conns []*MuxConn
	mux.connsLock.Lock()
	for _, v := range mux.conns {
		conns = append(conns, v)
	}
	mux.connsLock.Unlock()
	for _, v := range conns {
		v.Close()
	}
	return
}

func (mux *Mux) IsClosed() bool {
	mux.lock.Lock()
	defer mux.lock.Unlock()
	return mux.destroy
}

func (mux *Mux) Addr() net.Addr {
	return mux.LocalAddr()
}

func (mux *Mux) getID() (id uint16, err error) {
	mux.connsLock.Lock()
	defer mux.connsLock.Unlock()
	if len(mux.conns) >= 32767 {
		err = fmt.Errorf("Open Too much MuxConns")
		return
	}
	id = mux.avalid
	for {
		mux.avalid += 2
		_, ok := mux.conns[mux.avalid]
		if !ok {
			break
		}
	}
	return
}

var (
	zerobuf = make([]byte, 128)
)

func (mux *Mux) Dial() (conn *MuxConn, err error) {
	select {
	default:
	case <-mux.die:
		err = fmt.Errorf("closed mux")
		return
	}
	id, err := mux.getID()
	if err != nil {
		return
	}
	mux.connsLock.Lock()
	ver, ok := mux.connVers[id]
	if !ok {
		ver = 0
	} else {
		ver++
		mux.connVers[id] = ver
	}
	conn = NewMuxConn(mux, id, ver)
	mux.conns[id] = conn
	mux.connsLock.Unlock()
	mux.writePacket(packet{
		pktid:  id,
		pktver: ver,
		pktype: msyn,
	})
	conn.Pause()
	_, err = conn.Write(nil)
	return
}

func (mux *Mux) Accept() (conn net.Conn, err error) {
	return mux.AcceptMux()
}

func (mux *Mux) AcceptMux() (conn *MuxConn, err error) {
	select {
	case conn = <-mux.acceptch:
	case <-mux.die:
		err = fmt.Errorf("closed mux")
	}
	return
}

func (m *Mux) writePacket(pkt packet) (err error) {
	select {
	case m.writech <- pkt:
	case <-m.die:
		err = fmt.Errorf("closed mux")
	}
	return
}

func (mux *Mux) readPacket() (pkt packet, err error) {
	pktbuf := make([]byte, pktHdrlen)
	_, err = io.ReadFull(mux, pktbuf)
	if err != nil {
		return
	}
	pkt = packetUnmarshal(pktbuf)
	// log.Println(err, pkt.pktid, pkt.pktlen, pkt.pktver, pkt.pktype)
	pktlen := int(pkt.pktlen)
	switch pkt.pktype {
	case mpsh:
		for pktlen > 0 {
			buf := mux.pool.Get().([]byte)
			if len(buf) == 0 {
				continue
			} else if len(buf) > pktlen {
				buf = buf[:pktlen]
				mux.pool.Put(buf[pktlen:])
				pktlen = 0
			} else {
				pktlen -= len(buf)
			}
			_, err = io.ReadFull(mux, buf)
			if err != nil {
				return
			}
			pkt.payloads = append(pkt.payloads, buf)
		}
	default:
		if pktlen > 0 {
			buf := make([]byte, pktlen)
			_, err = io.ReadFull(mux, buf)
		}
	}
	return
}

func (mux *Mux) readLoop() {
	defer mux.Close()
	for {
		pkt, err := mux.readPacket()
		if err != nil {
			return
		}
		mux.connsLock.Lock()
		c, ok := mux.conns[pkt.pktid]
		if (ok && (c.ver != pkt.pktver || pkt.pktype == msyn)) || (!ok && pkt.pktype != msyn) {
			mux.connsLock.Unlock()
			continue
		}
		mux.connsLock.Unlock()
		switch pkt.pktype {
		default:
			return
		case msyn:
			conn := NewMuxConn(mux, pkt.pktid, pkt.pktver)
			mux.connsLock.Lock()
			mux.conns[pkt.pktid] = conn
			mux.connVers[pkt.pktid] = pkt.pktver
			mux.connsLock.Unlock()
			mux.async.Run(func() {
				select {
				case <-mux.die:
					conn.Close()
				case mux.acceptch <- conn:
					mux.writePacket(packet{
						pktid:  conn.id,
						pktver: conn.ver,
						pktype: mrep,
					})
				}
			})
		case mpsh:
			mux.doPshPacket(pkt)
		case mnop:
		case mrst:
			mux.connsLock.Lock()
			delete(mux.conns, pkt.pktid)
			mux.connsLock.Unlock()
			c1 := c
			mux.async.Run(func() {
				c1.Close()
			})
		case mpse:
			c.Pause()
		case mrep:
			c.Reply()
		}
	}
}

func (mux *Mux) writeLoop() {
	defer mux.Close()
	for {
		var pkt packet
		select {
		case pkt = <-mux.writech:
		case <-mux.die:
			return
		}
		if len(pkt.payloads) == 0 && pkt.pktype != mpsh {
			pkt.payloads = [][]byte{zerobuf[:rand.Intn(16)]}
		}
		bufs := make([][]byte, 0, len(pkt.payloads)+1)
	f1:
		for {
			var bs [][]byte
			var nbytes int
		f2:
			for len(pkt.payloads) != 0 {
				b := pkt.payloads[0]
				if len(b)+nbytes >= maxSeglen {
					bs = append(bs, b[:maxSeglen-nbytes])
					pkt.payloads[0] = b[maxSeglen-nbytes:]
					nbytes = maxSeglen
					break f2
				}
				bs = append(bs, b)
				nbytes += len(b)
				pkt.payloads = pkt.payloads[1:]
			}
			pkt.pktlen = uint16(nbytes)
			pktbuf := make([]byte, pktHdrlen)
			pkt.marshal(pktbuf)
			bufs = append(bufs, pktbuf)
			bufs = append(bufs, bs...)
			if len(pkt.payloads) == 0 {
				break f1
			}
		}
		var err error
		if conn, ok := mux.Conn.(utils.Conn); ok {
			_, err = conn.WriteBuffers(bufs)
		} else {
			nbufs := net.Buffers(bufs)
			_, err = nbufs.WriteTo(mux)
		}
		if err != nil {
			return
		}
		if pkt.die != nil && pkt.sig != nil {
			select {
			case <-mux.die:
				return
			case <-pkt.die:
			case pkt.sig <- true:
			}
		}
	}
}

func (mux *Mux) doPshPacket(pkt packet) {
	if pkt.pktlen == 0 || len(pkt.payloads) == 0 {
		return
	}
	mux.connsLock.Lock()
	conn, ok := mux.conns[pkt.pktid]
	mux.connsLock.Unlock()
	if !ok {
		return
	}
	select {
	default:
	case <-conn.die:
		return
	}
	conn.rlock.Lock()
	conn.rbufs = append(conn.rbufs, pkt.payloads...)
	var rbufsbytes int64
	for _, v := range conn.rbufs {
		rbufsbytes += int64(len(v))
	}
	var rpse bool
	if rbufsbytes > int64(16*maxSeglen) && !conn.rpse {
		conn.rpse = true
		rpse = true
	}
	conn.rlock.Unlock()
	if rbufsbytes > int64(maxSeglen)*128 {
		conn.Close()
		return
	}
	conn.NotifyRead()
	if rpse {
		mux.async.Run(func() {
			mux.writePacket(packet{
				pktid:  conn.id,
				pktver: conn.ver,
				pktype: mpse,
			})
		})
	}
}

type MuxConn struct {
	mux    *Mux
	id     uint16
	ver    uint8
	lock   sync.Mutex
	rlock  sync.Mutex
	pause  bool
	rpse   bool
	die    chan bool
	psech  chan bool
	rsigch chan bool
	wsigch chan bool
	rtime  time.Time
	wtime  time.Time
	rbufs  [][]byte
}

func NewMuxConn(mux *Mux, id uint16, ver uint8) *MuxConn {
	return &MuxConn{
		mux:    mux,
		id:     id,
		ver:    ver,
		pause:  false,
		die:    make(chan bool),
		psech:  make(chan bool),
		rsigch: make(chan bool),
		wsigch: make(chan bool),
	}
}

func (conn *MuxConn) Close() (err error) {
	select {
	default:
	case <-conn.die:
		return
	}
	close(conn.die)
	select {
	default:
	case <-conn.mux.die:
		return
	}
	conn.mux.connsLock.Lock()
	delete(conn.mux.conns, conn.id)
	conn.mux.connsLock.Unlock()
	err = conn.mux.writePacket(packet{
		pktid:  conn.id,
		pktype: mrst,
		pktver: conn.ver,
	})
	return
}

func (conn *MuxConn) Pause() {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	if !conn.pause {
		conn.pause = true
	}
}

func (conn *MuxConn) Reply() {
	select {
	case conn.psech <- true:
	default:
	}
}

func (conn *MuxConn) NotifyRead() {
	select {
	case conn.rsigch <- true:
	default:
	}
}

func (conn *MuxConn) Read(b []byte) (n int, err error) {
	conn.rlock.Lock()
	for len(conn.rbufs) == 0 {
		conn.rlock.Unlock()
		if conn.rtime.After(time.Now()) {
			rtimer := time.NewTimer(conn.rtime.Sub(time.Now()))
			defer rtimer.Stop()
			select {
			case <-conn.die:
				err = fmt.Errorf("read from closed MuxConn")
				return
			case <-conn.rsigch:
				conn.rlock.Lock()
			case <-rtimer.C:
				err = &timeoutErr{op: fmt.Sprintf("read from %s", conn.RemoteAddr())}
				return
			}
		} else {
			select {
			case <-conn.die:
				err = fmt.Errorf("read from closed MuxConn")
				return
			case <-conn.rsigch:
				conn.rlock.Lock()
			}
		}
	}
	for len(b) > 0 && len(conn.rbufs) > 0 {
		nbytes := copy(b, conn.rbufs[0])
		n += nbytes
		b = b[nbytes:]
		conn.mux.pool.Put(conn.rbufs[0][:nbytes])
		conn.rbufs[0] = conn.rbufs[0][nbytes:]
		if len(conn.rbufs[0]) == 0 {
			conn.rbufs = conn.rbufs[1:]
		}
	}
	var flag bool
	if conn.rpse {
		var rbufsbytes int64
		for _, v := range conn.rbufs {
			rbufsbytes += int64(len(v))
		}
		if rbufsbytes < 4*int64(maxSeglen) {
			flag = true
			conn.rpse = false
		}
	}
	conn.rlock.Unlock()
	if flag {
		conn.mux.writePacket(packet{
			pktid:  conn.id,
			pktver: conn.ver,
			pktype: mrep,
		})
	}
	return
}

func (conn *MuxConn) Write(b []byte) (n int, err error) {
	return conn.WriteBuffers([][]byte{b})
}

func (conn *MuxConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	conn.lock.Lock()
	if conn.pause {
		conn.lock.Unlock()
		select {
		case <-conn.psech:
			conn.pause = false
			conn.lock.Lock()
		case <-conn.die:
			err = fmt.Errorf("cannot wirte to closed MuxConn")
			return
		}
	}
	conn.lock.Unlock()
	if len(bufs) == 0 || len(bufs[0]) == 0 {
		return
	}
	pkt := packet{
		pktid:    conn.id,
		pktver:   conn.ver,
		pktype:   mpsh,
		sig:      conn.wsigch,
		die:      conn.die,
		payloads: bufs}
	if conn.wtime.After(time.Now()) {
		wtimer := time.NewTimer(conn.wtime.Sub(time.Now()))
		defer wtimer.Stop()
		select {
		case <-conn.die:
			err = fmt.Errorf("closed connection")
		case <-wtimer.C:
			err = &timeoutErr{op: fmt.Sprintf("write to %s", conn.RemoteAddr())}
		case conn.mux.writech <- pkt:
		}
	} else {
		err = conn.mux.writePacket(pkt)
	}
	if err == nil {
		select {
		case <-conn.die:
		case <-conn.wsigch:
		}
		for _, v := range bufs {
			n += len(v)
		}
	}
	return
}

type timeoutErr struct {
	op string
}

func (t *timeoutErr) Error() string {
	return t.op + " timeout"
}

func (t *timeoutErr) Temporary() bool {
	return true
}

func (t *timeoutErr) Timeout() bool {
	return true
}

type Addr struct {
	net.Addr
	id uint16
}

func (addr *Addr) String() string {
	return fmt.Sprintf("%s:%v", addr.Addr.String(), addr.id)
}

func (conn *MuxConn) LocalAddr() (addr net.Addr) {
	return &Addr{
		Addr: conn.mux.LocalAddr(),
		id:   conn.id,
	}
}

func (conn *MuxConn) RemoteAddr() (addr net.Addr) {
	return &Addr{
		Addr: conn.mux.RemoteAddr(),
		id:   conn.id,
	}
}

func (conn *MuxConn) SetDeadline(t time.Time) (err error) {
	err = conn.SetReadDeadline(t)
	if err == nil {
		err = conn.SetWriteDeadline(t)
	}
	return
}

func (conn *MuxConn) SetReadDeadline(t time.Time) (err error) {
	select {
	default:
	case <-conn.die:
		err = fmt.Errorf("closed connection")
	}
	conn.rtime = t
	return
}

func (conn *MuxConn) SetWriteDeadline(t time.Time) (err error) {
	select {
	default:
	case <-conn.die:
		err = fmt.Errorf("closed connection")
	}
	conn.wtime = t
	return
}
