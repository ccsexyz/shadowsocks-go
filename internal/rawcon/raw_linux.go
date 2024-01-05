package rawcon

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"

	"os/exec"
	"strconv"

	ran "math/rand"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

type RAWConn struct {
	conn    *net.IPConn
	udp     net.Conn
	layer   *pktLayers
	buf     []byte
	cleaner *utils.ExitCleaner
	r       *Raw
	dstport int
	hseqn   uint32
	mss     int
}

func (raw *RAWConn) Close() (err error) {
	if raw.cleaner != nil {
		raw.cleaner.Exit()
	}
	if raw.udp != nil {
		raw.sendFin()
	}
	if raw.udp != nil {
		err = raw.udp.Close()
	}
	if raw.conn != nil {
		err1 := raw.conn.Close()
		if err1 != nil {
			err = err1
		}
	}
	return
}

func (raw *RAWConn) GetMSS() int {
	return raw.mss
}

func getMssFromTcpLayer(tcp *tcpLayer) int {
	for _, v := range tcp.options {
		if v.kind != tcpOptionKindMSS || len(v.data) == 0 {
			continue
		}
		return (int)(binary.BigEndian.Uint16(v.data))
	}
	return 0
}

func (layer *pktLayers) updateTCP() {
	tcp := layer.tcp
	tcp.flags = 0
	tcp.ecn = 0
	tcp.reserved = 0
	tcp.chksum = 0
	tcp.payload = nil
}

func (raw *RAWConn) updateTCP() {
	raw.layer.updateTCP()
}

func (raw *RAWConn) sendPacketWithLayer(layer *pktLayers) (err error) {
	data := layer.tcp.marshal(layer.ip4.srcip, layer.ip4.dstip)
	if raw.udp != nil {
		_, err = raw.conn.Write(data)
	} else {
		_, err = raw.conn.WriteTo(data, &net.IPAddr{IP: layer.ip4.dstip})
	}
	return
}

func (raw *RAWConn) sendPacket() (err error) {
	return raw.sendPacketWithLayer(raw.layer)
}

func (raw *RAWConn) sendSynWithLayer(layer *pktLayers) (err error) {
	layer.updateTCP()
	tcp := layer.tcp
	tcp.setFlag(SYN)
	options := tcp.options
	defer func() { tcp.options = options }()
	tcp.options = append(tcp.options, tcpOption{
		kind:   tcpOptionKindMSS,
		length: 4,
		data:   []byte{0x5, 0xb4},
	})
	tcp.options = append(tcp.options, tcpOption{
		kind:   tcpOptionKindWindowScale,
		length: 3,
		data:   []byte{0x5},
	})
	tcp.options = append(tcp.options, tcpOption{
		kind:   tcpOptionKindSACKPermitted,
		length: 2,
	})
	return raw.sendPacketWithLayer(layer)
}

func (raw *RAWConn) sendSyn() (err error) {
	return raw.sendSynWithLayer(raw.layer)
}

func (raw *RAWConn) sendSynAckWithLayer(layer *pktLayers) (err error) {
	layer.updateTCP()
	tcp := layer.tcp
	tcp.setFlag(SYN | ACK)
	options := tcp.options
	defer func() { tcp.options = options }()
	tcp.options = append(tcp.options, tcpOption{
		kind:   tcpOptionKindMSS,
		length: 4,
		data:   []byte{0x5, 0xb4},
	})
	tcp.options = append(tcp.options, tcpOption{
		kind:   tcpOptionKindWindowScale,
		length: 3,
		data:   []byte{0x5},
	})
	tcp.options = append(tcp.options, tcpOption{
		kind:   tcpOptionKindSACKPermitted,
		length: 2,
	})
	return raw.sendPacketWithLayer(layer)
}

func (conn *RAWConn) sendSynAck() (err error) {
	return conn.sendSynAckWithLayer(conn.layer)
}

func (conn *RAWConn) sendAckWithLayer(layer *pktLayers) (err error) {
	layer.updateTCP()
	layer.tcp.setFlag(ACK)
	return conn.sendPacketWithLayer(layer)
}

func (conn *RAWConn) sendAck() (err error) {
	return conn.sendAckWithLayer(conn.layer)
}

func (conn *RAWConn) sendFinWithLayer(layer *pktLayers) (err error) {
	layer.updateTCP()
	layer.tcp.setFlag(FIN)
	return conn.sendPacketWithLayer(layer)
}

func (conn *RAWConn) sendFin() (err error) {
	return conn.sendFinWithLayer(conn.layer)
}

func (conn *RAWConn) sendRstWithLayer(layer *pktLayers) (err error) {
	layer.updateTCP()
	layer.tcp.setFlag(RST)
	return conn.sendPacketWithLayer(layer)
}

func (conn *RAWConn) sendRst() (err error) {
	return conn.sendRstWithLayer(conn.layer)
}

// the function write will not increase seqn
func (raw *RAWConn) write(b []byte) (n int, err error) {
	n = len(b)
	raw.updateTCP()
	tcp := raw.layer.tcp
	tcp.setFlag(PSH | ACK)
	tcp.payload = b
	err = raw.sendPacket()
	return
}

func (raw *RAWConn) writeWithLayer(b []byte, layer *pktLayers) (n int, err error) {
	n = len(b)
	layer.updateTCP()
	tcp := layer.tcp
	tcp.setFlag(PSH | ACK)
	tcp.payload = b
	err = raw.sendPacketWithLayer(layer)
	return
}

func (raw *RAWConn) Write(b []byte) (n int, err error) {
	if raw.r.TLS {
		buf := utils.GetBuf(len(b) + 5)
		defer utils.PutBuf(buf)
		copy(buf, []byte{0x17, 0x3, 0x3})
		binary.BigEndian.PutUint16(buf[3:5], uint16(len(b)))
		copy(buf[5:], b)
		b = buf[:5+len(b)]
	}
	n, err = raw.write(b)
	raw.layer.tcp.seqn += uint32(n)
	return
}

func (raw *RAWConn) ReadTCPLayer() (tcp *tcpLayer, addr *net.UDPAddr, err error) {
	for {
		var n int
		var ipaddr *net.IPAddr
		n, ipaddr, err = raw.conn.ReadFromIP(raw.buf)
		if err != nil {
			e, ok := err.(net.Error)
			if ok && e.Temporary() {
				raw.SetReadDeadline(time.Time{})
			}
			return
		}
		tcp, err = decodeTCPlayer(raw.buf[:n])
		if err != nil {
			return
		}
		if tcp.dstPort != raw.dstport {
			continue
		}
		if tcp.chkFlag(RST) {
			if raw.r.IgnRST {
				continue
			} else {
				err = fmt.Errorf("connect reset by peer %s", addr.String())
			}
		}
		addr = &net.UDPAddr{
			IP:   ipaddr.IP,
			Port: tcp.srcPort,
		}
		return
	}
}

func (raw *RAWConn) Read(b []byte) (n int, err error) {
	n, _, err = raw.ReadFrom(b)
	return
}

func (conn *RAWConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.layer.ip4.srcip,
		Port: conn.layer.tcp.srcPort,
	}
}

func (conn *RAWConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.layer.ip4.dstip,
		Port: conn.layer.tcp.dstPort,
	}
}

func (raw *RAWConn) SetDeadline(t time.Time) error {
	return raw.conn.SetDeadline(t)
}

func (raw *RAWConn) SetReadDeadline(t time.Time) error {
	return raw.conn.SetReadDeadline(t)
}

func (raw *RAWConn) SetWriteDeadline(t time.Time) error {
	return raw.conn.SetWriteDeadline(t)
}

func (raw *RAWConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		var tcp *tcpLayer
		tcp, addr, err = raw.ReadTCPLayer()
		if err != nil {
			return
		}
		if tcp == nil || addr == nil {
			continue
		}
		if tcp.chkFlag(FIN) {
			err = fmt.Errorf("receive fin from %s", addr.String())
			return
		}
		if tcp.chkFlag(SYN | ACK) {
			err = raw.sendAck()
			if err != nil {
				return
			} else {
				continue
			}
		}
		if !tcp.chkFlag(PSH|ACK) || tcp.seqn == raw.hseqn {
			continue
		}
		n = len(tcp.payload)
		if n > 0 {
			if uint64(tcp.seqn)+uint64(n) > uint64(raw.layer.tcp.ackn) {
				raw.layer.tcp.ackn = tcp.seqn + uint32(n)
			}
			if raw.r.TLS {
				if n < 5 {
					continue
				}
				n = copy(b, tcp.payload[5:])
			} else {
				n = copy(b, tcp.payload)
			}
			raw.trySendAck(raw.layer)
		}
		return n, addr, err
	}
}

func (raw *RAWConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return raw.Write(b)
}

func (raw *RAWConn) trySendAck(layer *pktLayers) {
	now := time.Now()
	if layer.tcp.ackn < layer.lastack+16384 {
		if now.Sub(layer.lastacktime) < time.Millisecond*time.Duration(10) {
			return
		}
	}
	layer.lastack = layer.tcp.ackn
	layer.lastacktime = now
	raw.sendAckWithLayer(layer)
}

func (r *Raw) DialRAW(address string) (raw *RAWConn, err error) {
	udp, err := net.Dial("udp4", address)
	if err != nil {
		return
	}
	ulocaladdr := udp.LocalAddr().(*net.UDPAddr)
	uremoteaddr := udp.RemoteAddr().(*net.UDPAddr)
	conn, err := net.DialIP("ip4:tcp", &net.IPAddr{IP: ulocaladdr.IP}, &net.IPAddr{IP: uremoteaddr.IP})
	fatalErr(err)
	if r.DSCP != 0 {
		ipv4.NewConn(conn).SetTOS(r.DSCP)
	}
	// https://www.kernel.org/doc/Documentation/networking/filter.txt
	ipv4.NewPacketConn(conn).SetBPF([]bpf.RawInstruction{
		{0x30, 0, 0, 0x00000009},
		{0x15, 0, 12, 0x00000006},
		{0x28, 0, 0, 0x00000006},
		{0x45, 4, 0, 0x00001fff},
		{0xb1, 0, 0, 0x00000000},
		{0x48, 0, 0, 0x00000000},
		{0x15, 4, 0, uint32(ulocaladdr.Port)},
		{0x48, 0, 0, 0x00000000},
		{0x15, 0, 5, uint32(uremoteaddr.Port)},
		{0x48, 0, 0, 0x00000002},
		{0x15, 2, 3, uint32(ulocaladdr.Port)},
		{0x48, 0, 0, 0x00000002},
		{0x15, 0, 1, uint32(uremoteaddr.Port)},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	})
	raw = &RAWConn{
		conn:    conn,
		udp:     udp,
		buf:     make([]byte, 2048),
		dstport: ulocaladdr.Port,
		layer: &pktLayers{
			ip4: &iPv4Layer{
				srcip: ulocaladdr.IP,
				dstip: uremoteaddr.IP,
			},
			tcp: &tcpLayer{
				srcPort: ulocaladdr.Port,
				dstPort: uremoteaddr.Port,
				window:  12580,
				ackn:    0,
				data:    make([]byte, 2048),
			},
		},
		r: r,
	}
	binary.Read(rand.Reader, binary.LittleEndian, &(raw.layer.tcp.seqn))
	defer func() {
		if err != nil {
			raw.Close()
		} else {
			raw.SetReadDeadline(time.Time{})
		}
	}()
	cmd := exec.Command("iptables", "-I", "OUTPUT", "-p", "tcp", "-s", conn.LocalAddr().String(),
		"--sport", strconv.Itoa(ulocaladdr.Port), "-d", conn.RemoteAddr().String(),
		"--dport", strconv.Itoa(uremoteaddr.Port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return
	}
	cleaner := &utils.ExitCleaner{}
	clean := exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "-s", conn.LocalAddr().String(),
		"--sport", strconv.Itoa(ulocaladdr.Port), "-d", conn.RemoteAddr().String(),
		"--dport", strconv.Itoa(uremoteaddr.Port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	cleaner.Push(func() {
		clean.Run()
	})
	defer func() {
		if err != nil {
			cleaner.Exit()
			return
		}
		raw.cleaner = cleaner
	}()
	retry := 0
	layer := raw.layer
	var ackn uint32
	var seqn uint32
	for {
		if retry > 5 {
			err = errors.New("retry too many times")
			return
		}
		retry++
		err = raw.sendSyn()
		if err != nil {
			return
		}
		err = raw.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(500+int(ran.Int63()%500))))
		if err != nil {
			return
		}
		var tcp *tcpLayer
		tcp, _, err = raw.ReadTCPLayer()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			} else {
				continue
			}
		}
		if tcp.chkFlag(SYN | ACK) {
			layer.tcp.ackn = tcp.seqn + 1
			layer.tcp.seqn++
			ackn = layer.tcp.ackn
			seqn = layer.tcp.seqn
			raw.mss = getMssFromTcpLayer(tcp)
			err = raw.sendAck()
			if err != nil {
				return
			}
			break
		}
	}
	if r.NoHTTP && !r.TLS {
		return
	}
	var req []byte
	var host string
	if len(r.Hosts) == 0 {
		if len(r.Host) != 0 {
			r.Hosts = strings.Split(r.Host, ",")
		}
	}
	if len(r.Hosts) > 0 {
		host = r.Hosts[ran.Int()%len(r.Hosts)]
	}
	if r.TLS {
		b := utils.GetBuf(2048)
		defer utils.PutBuf(b)
		utils.PutRandomBytes(b[1816:])
		tlsLen := utils.GenTLSClientHello(b, host, b[2016:], b[1816:1816+ran.Intn(200)])
		req = b[:tlsLen]
	} else {
		if uremoteaddr.Port != 80 {
			host += strconv.Itoa(uremoteaddr.Port)
		}
		headers := "Host: " + host + "\r\n"
		headers += "X-Online-Host: " + host + "\r\n"
		req = utils.StringToSlice(buildHTTPRequest(headers))
	}
	retry = 0
	needretry := true
	var starttime time.Time
	for {
		if retry > 25 {
			err = errors.New("retry too many times")
			return
		}
		if needretry {
			needretry = false
			starttime = time.Now()
			retry++
			_, err = raw.write(req)
			if err != nil {
				return
			}
		}
		err = raw.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(200+int(ran.Int63()%100))))
		if err != nil {
			return
		}
		var tcp *tcpLayer
		tcp, _, err = raw.ReadTCPLayer()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			} else {
				needretry = true
				continue
			}
		}
		if tcp.chkFlag(SYN | ACK) {
			layer.tcp.ackn = ackn
			layer.tcp.seqn = seqn
			err = raw.sendAck()
			if err != nil {
				return
			}
			continue
		}
		n := len(tcp.payload)
		if tcp.chkFlag(PSH|ACK) && n >= tcpLen {
			if r.TLS {
				ok, _, _ := utils.ParseTLSServerHelloMsg(tcp.payload)
				if ok {
					layer.tcp.seqn += uint32(len(req))
					layer.tcp.ackn = tcp.seqn + uint32(n)
					raw.hseqn = tcp.seqn
					break
				}
			} else {
				head := string(tcp.payload[:4])
				tail := string(tcp.payload[n-4:])
				if head == "HTTP" && tail == "\r\n\r\n" {
					layer.tcp.seqn += uint32(len(req))
					layer.tcp.ackn = tcp.seqn + uint32(n)
					raw.hseqn = tcp.seqn
					break
				}
			}
		}
		if time.Now().After(starttime.Add(time.Millisecond * 200)) {
			needretry = true
		}
	}
	return
}

type RAWListener struct {
	RAWConn
	newcons map[string]*connInfo
	conns   map[string]*connInfo
	mutex   myMutex
	laddr   *net.UDPAddr
}

func (listener *RAWListener) GetMSSByAddr(addr net.Addr) int {
	listener.mutex.Lock()
	defer listener.mutex.Unlock()
	conn, ok := listener.conns[addr.String()]
	if ok && conn.mss > 0 {
		return conn.mss
	}
	return 0
}

func (r *Raw) ListenRAW(address string) (listener *RAWListener, err error) {
	udpaddr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return
	}
	if udpaddr.IP == nil {
		udpaddr.IP = ipv4AddrAny
	}
	conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: udpaddr.IP})
	if err != nil {
		return
	}
	isAddrAny := udpaddr.IP.Equal(ipv4AddrAny)
	ipv4.NewPacketConn(conn).SetBPF([]bpf.RawInstruction{
		{0x30, 0, 0, 0x00000009},
		{0x15, 0, 8, 0x00000006},
		{0x28, 0, 0, 0x00000006},
		{0x45, 4, 0, 0x00001fff},
		{0xb1, 0, 0, 0x00000000},
		{0x48, 0, 0, 0x00000002},
		{0x15, 2, 3, uint32(udpaddr.Port)},
		{0x48, 0, 0, 0x00000000},
		{0x15, 0, 1, uint32(udpaddr.Port)},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	})
	listener = &RAWListener{
		RAWConn: RAWConn{
			conn:    conn,
			udp:     nil,
			buf:     make([]byte, 2048),
			layer:   nil,
			dstport: udpaddr.Port,
			r:       r,
		},
		newcons: make(map[string]*connInfo),
		conns:   make(map[string]*connInfo),
		laddr:   udpaddr,
	}
	var cmd *exec.Cmd
	if isAddrAny {
		cmd = exec.Command("iptables", "-I", "OUTPUT", "-p", "tcp",
			"--sport", strconv.Itoa(udpaddr.Port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	} else {
		cmd = exec.Command("iptables", "-I", "OUTPUT", "-p", "tcp", "-s", conn.LocalAddr().String(),
			"--sport", strconv.Itoa(udpaddr.Port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	}
	_, err = cmd.CombinedOutput()
	if err != nil {
		return
	}
	cleaner := &utils.ExitCleaner{}
	var clean1 *exec.Cmd
	if isAddrAny {
		clean1 = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp",
			"--sport", strconv.Itoa(udpaddr.Port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	} else {
		clean1 = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "-s", conn.LocalAddr().String(),
			"--sport", strconv.Itoa(udpaddr.Port), "--tcp-flags", "RST", "RST", "-j", "DROP")
	}
	cleaner.Push(func() {
		clean1.Run()
	})
	defer func() {
		if err != nil {
			cleaner.Exit()
		} else {
			listener.cleaner = cleaner
		}
	}()
	var cmd2 *exec.Cmd
	if isAddrAny {
		cmd2 = exec.Command("iptables", "-I", "INPUT", "-p", "tcp",
			"--dport", strconv.Itoa(udpaddr.Port), "-j", "ACCEPT")
	} else {
		cmd2 = exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "-d", conn.LocalAddr().String(),
			"--dport", strconv.Itoa(udpaddr.Port), "-j", "ACCEPT")
	}

	_, err = cmd2.CombinedOutput()
	if err != nil {
		return
	}
	var clean2 *exec.Cmd
	if isAddrAny {
		clean2 = exec.Command("iptables", "-D", "INPUT", "-p", "tcp",
			"--dport", strconv.Itoa(udpaddr.Port), "-j", "ACCEPT")
	} else {
		clean2 = exec.Command("iptables", "-D", "INPUT", "-p", "tcp", "-d", conn.LocalAddr().String(),
			"--dport", strconv.Itoa(udpaddr.Port), "-j", "ACCEPT")
	}
	cleaner.Push(func() {
		clean2.Run()
	})
	return
}

func (listener *RAWListener) doRead(b []byte) (n int, addr *net.UDPAddr, err error) {
	for {
		var tcp *tcpLayer
		var addrstr string
		tcp, addr, err = listener.ReadTCPLayer()
		if addr != nil {
			addrstr = addr.String()
		}
		if tcp != nil && (tcp.chkFlag(RST) || tcp.chkFlag(FIN)) {
			listener.mutex.run(func() {
				delete(listener.newcons, addrstr)
				delete(listener.conns, addrstr)
			})
			continue
		}
		if err != nil {
			return
		}
		var info *connInfo
		var ok bool
		listener.mutex.run(func() {
			info, ok = listener.conns[addrstr]
		})
		n = len(tcp.payload)
		if ok && n != 0 {
			t := info.layer.tcp
			if uint64(tcp.seqn)+uint64(n) > uint64(t.ackn) {
				t.ackn = tcp.seqn + uint32(n)
			}
			if info.state == httprepsent {
				if tcp.chkFlag(PSH | ACK) {
					if tcp.seqn == info.hseqn && n > 20 {
						ok := false
						if listener.r.TLS || listener.r.Mixed {
							ok, _, _ = utils.ParseTLSClientHelloMsg(tcp.payload)
						}
						head := string(tcp.payload[:4])
						tail := string(tcp.payload[n-4:])
						if !ok && head == "POST" && tail == "\r\n\r\n" {
							ok = true
						}
						if ok {
							t.ackn = tcp.seqn + uint32(n)
							_, err = listener.writeWithLayer(info.rep, info.layer)
							if err != nil {
								return
							}
						}
					} else {
						t.seqn += uint32(len(info.rep))
						info.rep = nil
						info.state = established
					}
				} else {
					// listener.layer = info.layer
					// listener.sendFin()
				}
			}
			if info.state == established {
				if info.tls {
					if len(tcp.payload) < 5 {
						continue
					}
					n = copy(b, tcp.payload[5:])
				} else {
					n = copy(b, tcp.payload)
				}
				listener.trySendAck(info.layer)
				return
			}
			continue
		}
		if ok && n == 0 {
			if tcp.chkFlag(PSH | ACK) {
				return
			}
			continue
		}
		listener.mutex.run(func() {
			info, ok = listener.newcons[addrstr]
		})
		if ok {
			t := info.layer.tcp
			if info.state == synreceived {
				if tcp.chkFlag(ACK) && !tcp.chkFlag(PSH|FIN|SYN) {
					t.seqn++
					if listener.r.NoHTTP {
						info.state = established
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
					} else {
						info.state = waithttpreq
					}
				} else if tcp.chkFlag(SYN) && !tcp.chkFlag(ACK|PSH) {
					err = listener.sendSynAckWithLayer(info.layer)
					if err != nil {
						return
					}
				}
			} else if info.state == waithttpreq {
				if tcp.chkFlag(ACK|PSH) && n > 20 {
					if listener.r.TLS || listener.r.Mixed {
						ok, _, msg := utils.ParseTLSClientHelloMsg(tcp.payload)
						if ok {
							t.ackn = tcp.seqn + uint32(n)
							if info.rep == nil {
								rep := make([]byte, 2048)
								l := ran.Intn(128)
								n = utils.GenTLSServerHello(rep, l, msg.SessionId)
								info.rep = rep[:l+n]
							}
							info.hseqn = tcp.seqn
							info.tls = true
						}
					}
					head := string(tcp.payload[:4])
					tail := string(tcp.payload[n-4:])
					if info.rep == nil && head == "POST" && tail == "\r\n\r\n" {
						t.ackn = tcp.seqn + uint32(n)
						rep := buildHTTPResponse("")
						info.rep = []byte(rep)
						info.hseqn = tcp.seqn
					}
					if info.rep != nil {
						_, err = listener.writeWithLayer(info.rep, info.layer)
						if err != nil {
							return
						}
						info.state = httprepsent
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
					} else if listener.r.Mixed {
						t.ackn = tcp.seqn + uint32(n)
						info.state = established
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
						n = copy(b, tcp.payload)
						listener.trySendAck(info.layer)
						return
					}
				} else if tcp.chkFlag(SYN) && !tcp.chkFlag(ACK|PSH) {
					err = listener.sendSynAckWithLayer(info.layer)
					if err != nil {
						return
					}
				}
			}
			continue
		}
		srcip := listener.laddr.IP
		if srcip.Equal(ipv4AddrAny) {
			srcip, _ = getSrcIPForDstIP(addr.IP)
			if srcip == nil {
				continue
			}
		}
		layer := &pktLayers{
			ip4: &iPv4Layer{
				srcip: srcip,
				dstip: addr.IP,
			},
			tcp: &tcpLayer{
				srcPort: listener.laddr.Port,
				dstPort: addr.Port,
				window:  65535,
				ackn:    tcp.seqn + 1,
				data:    make([]byte, 2048),
			},
		}
		if tcp.chkFlag(SYN) && !tcp.chkFlag(ACK|PSH|FIN) {
			info = &connInfo{
				state: synreceived,
				layer: layer,
				mss:   getMssFromTcpLayer(tcp),
			}
			binary.Read(rand.Reader, binary.LittleEndian, &(info.layer.tcp.seqn))
			err = listener.sendSynAckWithLayer(info.layer)
			if err != nil {
				return
			}
			listener.mutex.run(func() {
				listener.newcons[addrstr] = info
			})
		} else {
			listener.sendFinWithLayer(layer)
		}
	}
}

func (listener *RAWListener) LocalAddr() net.Addr {
	return listener.laddr
}

func (listener *RAWListener) RemoteAddr() net.Addr {
	return nil
}

func (listener *RAWListener) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = listener.doRead(b)
	return
}

func (listener *RAWListener) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	listener.mutex.Lock()
	info, ok := listener.conns[addr.String()]
	listener.mutex.Unlock()
	if !ok {
		return 0, errors.New("cannot write to " + addr.String())
	}
	if info.tls {
		buf := utils.GetBuf(len(b) + 5)
		defer utils.PutBuf(buf)
		copy(buf, []byte{0x17, 0x3, 0x3})
		binary.BigEndian.PutUint16(buf[3:5], uint16(len(b)))
		copy(buf[5:], b)
		b = buf[:5+len(b)]
	}
	n, err = listener.writeWithLayer(b, info.layer)
	info.layer.tcp.seqn += uint32(n)
	return
}

type pktLayers struct {
	ip4         *iPv4Layer
	tcp         *tcpLayer
	lastack     uint32
	lastacktime time.Time
}

type connInfo struct {
	state uint32
	layer *pktLayers
	rep   []byte
	hseqn uint32
	mss   int
	tls   bool
}

// copy from github.com/google/gopacket/layers/tcp.go

const (
	tcpOptionKindEndList                         = 0
	tcpOptionKindNop                             = 1
	tcpOptionKindMSS                             = 2  // len = 4
	tcpOptionKindWindowScale                     = 3  // len = 3
	tcpOptionKindSACKPermitted                   = 4  // len = 2
	tcpOptionKindSACK                            = 5  // len = n
	tcpOptionKindEcho                            = 6  // len = 6, obsolete
	tcpOptionKindEchoReply                       = 7  // len = 6, obsolete
	tcpOptionKindTimestamps                      = 8  // len = 10
	tcpOptionKindPartialOrderConnectionPermitted = 9  // len = 2, obsolete
	tcpOptionKindPartialOrderServiceProfile      = 10 // len = 3, obsolete
	tcpOptionKindCC                              = 11 // obsolete
	tcpOptionKindCCNew                           = 12 // obsolete
	tcpOptionKindCCEcho                          = 13 // obsolete
	tcpOptionKindAltChecksum                     = 14 // len = 3, obsolete
	tcpOptionKindAltChecksumData                 = 15 // len = n, obsolete
)

const (
	FIN = 1
	SYN = 2
	RST = 4
	PSH = 8
	ACK = 16
	URG = 32

	ECE = 1
	CWR = 2
	NS  = 4
)

const (
	tcpLen = 20 // FIXME
)

type iPv4Layer struct {
	srcip net.IP
	dstip net.IP
}

type tcpOption struct {
	kind   uint8
	length uint8
	data   []byte
}

type tcpLayer struct {
	srcPort    int
	dstPort    int
	seqn       uint32
	ackn       uint32
	dataOffset uint8 // 4 bits, headerLen = dataOffset << 2
	reserved   uint8 // 3 bits, must be zero
	ecn        uint8 // 3 bits, NS, CWR and ECE
	flags      uint8 // 6 bits, URG, ACK, PSH, RST, SYN and FIN
	window     uint16
	chksum     uint16
	urgent     uint16 // if URG is set
	options    []tcpOption
	opts       [4]tcpOption // pre allocate
	padding    []byte
	pads       [4]byte // pre allocate
	payload    []byte
	data       []byte // if data is not nil, marshal method will use this slice
}

func decodeTCPlayer(data []byte) (tcp *tcpLayer, err error) {
	tcp = &tcpLayer{}
	defer func() {
		if err != nil {
			tcp = nil
		}
	}()

	length := len(data)
	if length < tcpLen {
		err = fmt.Errorf("Invalid TCP packet length %d < %d", length, tcpLen)
		return
	}

	tcp.srcPort = int(binary.BigEndian.Uint16(data[:2]))
	tcp.dstPort = int(binary.BigEndian.Uint16(data[2:4]))
	tcp.seqn = binary.BigEndian.Uint32(data[4:8])
	tcp.ackn = binary.BigEndian.Uint32(data[8:12])

	u16 := binary.BigEndian.Uint16(data[12:14])
	tcp.dataOffset = uint8(u16 >> 12)
	tcp.reserved = uint8(u16 >> 9 & (1<<3 - 1))
	tcp.ecn = uint8(u16 >> 6 & (1<<3 - 1))
	tcp.flags = uint8(u16 & (1<<6 - 1))
	if (length >> 2) < int(tcp.dataOffset) {
		err = errors.New("TCP data offset greater than packet length")
		return
	}
	headerLen := int(tcp.dataOffset) << 2

	tcp.window = binary.BigEndian.Uint16(data[14:16])
	tcp.chksum = binary.BigEndian.Uint16(data[16:18])
	tcp.urgent = binary.BigEndian.Uint16(data[18:20])

	if length > headerLen {
		tcp.payload = data[headerLen:]
	}

	if headerLen == tcpLen {
		return
	}

	data = data[tcpLen:headerLen]
	for len(data) > 0 {
		if tcp.options == nil {
			tcp.options = tcp.opts[:0]
		}
		tcp.options = append(tcp.options, tcpOption{kind: data[0]})
		opt := &tcp.options[len(tcp.options)-1]
		switch opt.kind {
		case tcpOptionKindEndList:
			opt.length = 1
			tcp.padding = data[1:]
			break
		case tcpOptionKindNop:
			opt.length = 1
		default:
			opt.length = data[1]
			if opt.length < 2 {
				err = fmt.Errorf("Invalid TCP option length %d < 2", opt.length)
				return
			} else if int(opt.length) > len(data) {
				err = fmt.Errorf("Invalid TCP option length %d exceeds remaining %d bytes", opt.length, len(data))
				return
			}
			opt.data = data[2:opt.length]
		}
		data = data[opt.length:]
	}

	return
}

func (tcp *tcpLayer) marshal(srcip, dstip net.IP) (data []byte) {
	tcp.padding = nil

	headerLen := tcpLen
	for _, v := range tcp.options {
		switch v.kind {
		case tcpOptionKindEndList, tcpOptionKindNop:
			headerLen++
		default:
			v.length = uint8(len(v.data) + 2)
			headerLen += int(v.length)
		}
	}
	if rem := headerLen % 4; rem != 0 {
		tcp.padding = tcp.pads[:4-rem]
		headerLen += len(tcp.padding)
	}

	if len(tcp.data) >= len(tcp.payload)+headerLen {
		data = tcp.data
	} else {
		data = make([]byte, len(tcp.payload)+headerLen)
	}

	binary.BigEndian.PutUint16(data, uint16(tcp.srcPort))
	binary.BigEndian.PutUint16(data[2:], uint16(tcp.dstPort))
	binary.BigEndian.PutUint32(data[4:], tcp.seqn)
	binary.BigEndian.PutUint32(data[8:], tcp.ackn)

	var u16 uint16
	tcp.dataOffset = uint8(headerLen / 4)
	u16 = uint16(tcp.dataOffset) << 12
	u16 |= uint16(tcp.reserved) << 9
	u16 |= uint16(tcp.ecn) << 6
	u16 |= uint16(tcp.flags)
	binary.BigEndian.PutUint16(data[12:], u16)

	binary.BigEndian.PutUint16(data[14:], tcp.window)
	binary.BigEndian.PutUint16(data[18:], tcp.urgent)

	start := 20
	for _, v := range tcp.options {
		data[start] = byte(v.kind)
		switch v.kind {
		case tcpOptionKindEndList, tcpOptionKindNop:
			start++
		default:
			data[start+1] = v.length
			copy(data[start+2:start+len(v.data)+2], v.data)
			start += int(v.length)
		}
	}
	copy(data[start:], tcp.padding)
	start += len(tcp.padding)
	copy(data[start:], tcp.payload)
	binary.BigEndian.PutUint16(data[16:], 0)
	data = data[:start+len(tcp.payload)]
	binary.BigEndian.PutUint16(data[16:], csum(data, srcip, dstip))
	return
}

func (tcp *tcpLayer) setFlag(flag uint8) {
	tcp.flags |= flag
}

func (tcp *tcpLayer) chkFlag(flag uint8) bool {
	return tcp.flags&flag == flag
}

func csum(data []byte, srcip, dstip net.IP) uint16 {
	srcip = srcip.To4()
	dstip = dstip.To4()
	pseudoHeader := []byte{
		srcip[0], srcip[1], srcip[2], srcip[3],
		dstip[0], dstip[1], dstip[2], dstip[3],
		0, // reserved
		6, // tcp protocol number
		0, 0,
	}
	binary.BigEndian.PutUint16(pseudoHeader[10:], uint16(len(data)))

	var sum uint32

	f := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 != 0 {
			sum += uint32(binary.BigEndian.Uint16([]byte{b[len(b)-1], 0}))
		}
	}

	f(pseudoHeader)
	f(data)

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(^sum)
}
