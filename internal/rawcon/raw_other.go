//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd
// +build !linux,!darwin,!dragonfly,!freebsd,!netbsd,!openbsd

package rawcon

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	ran "math/rand"

	"github.com/ccsexyz/gopacket/layers"
	"github.com/ccsexyz/gopacket/pcap"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	"github.com/google/gopacket"
	"golang.org/x/net/ipv4"
)

type RAWConn struct {
	udp        net.Conn
	tcp        net.Conn
	handle     *pcap.Handle
	pktsrc     *gopacket.PacketSource
	opts       gopacket.SerializeOptions
	buffer     gopacket.SerializeBuffer
	cleaner    *utils.ExitCleaner
	packets    chan gopacket.Packet
	rtimer     *time.Timer
	wtimer     *time.Timer
	layer      *pktLayers
	r          *Raw
	hseqn      uint32
	lock       sync.Mutex
	mss        int
	async      utils.AsyncRunner
	linktype   layers.LinkType
	rcond      *sync.Cond
	rver       uint64
	errch      chan error
	nocopy     bool
	isLoopBack bool
	die        chan struct{}
}

func (raw *RAWConn) GetMSS() int {
	return raw.mss
}

func getMssFromTcpLayer(tcp *layers.TCP) int {
	for _, v := range tcp.Options {
		if v.OptionType != layers.TCPOptionKindMSS || len(v.OptionData) == 0 {
			continue
		}
		return (int)(binary.BigEndian.Uint16(v.OptionData))
	}
	return 0
}

func (conn *RAWConn) reader() {
	rver := uint64(0)
	for {
		conn.rcond.L.Lock()
		for {
			select {
			default:
			case <-conn.die:
				conn.rcond.L.Unlock()
				return
			}
			if conn.rver > rver {
				rver = conn.rver
				break
			}
			conn.rcond.Wait()
		}
		conn.rcond.L.Unlock()
		data, _, err := conn.handle.ZeroCopyReadPacketData()
		if err != nil {
			select {
			case <-conn.die:
			case conn.errch <- err:
			}
			return
		}
		packet := gopacket.NewPacket(data, conn.linktype, gopacket.DecodeOptions{NoCopy: conn.nocopy, Lazy: true})
		// log.Println(packet)
		select {
		case <-conn.die:
			return
		case conn.packets <- packet:
		}
	}
}

func (conn *RAWConn) notifyReader() {
	conn.rcond.L.Lock()
	defer conn.rcond.L.Unlock()
	conn.rver++
	conn.rcond.Signal()
}

func (conn *RAWConn) readPacket() (packet gopacket.Packet, err error) {
	select {
	default:
	case packet = <-conn.packets:
		return
	}

	conn.notifyReader()

	var timeoutch <-chan time.Time
	if conn.rtimer != nil {
		timeoutch = conn.rtimer.C
	}

	var ok bool
	select {
	case <-timeoutch:
		err = &timeoutErr{
			op: "read from " + conn.RemoteAddr().String(),
		}
	case err = <-conn.errch:
	case packet, ok = <-conn.packets:
		if packet == nil || ok == false {
			err = fmt.Errorf("read from closed connection")
		}
	}
	return
}

func (conn *RAWConn) readLayers() (layer *pktLayers, err error) {
	for {
		var packet gopacket.Packet
		packet, err = conn.readPacket()
		if err != nil {
			return
		}
		var eth *layers.Ethernet
		var ethLayer, loopLayer gopacket.Layer
		if conn.isLoopBack {
			loopLayer = packet.Layer(layers.LayerTypeLoopback)
		} else {
			ethLayer = packet.Layer(layers.LayerTypeEthernet)
			eth, _ = ethLayer.(*layers.Ethernet)
		}
		if ethLayer == nil && loopLayer == nil {
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip4, _ := ipLayer.(*layers.IPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if conn.r.IgnRST && tcp.RST {
			continue
		}
		layer = &pktLayers{
			eth: eth, ip4: ip4, tcp: tcp,
		}
		return
	}
}

func (conn *RAWConn) Close() (err error) {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	if conn.die != nil {
		select {
		default:
		case <-conn.die:
			return
		}
	}
	if conn.cleaner != nil {
		conn.cleaner.Exit()
		conn.cleaner = nil
	}
	if conn.udp != nil && conn.handle != nil {
		// conn.sendFin()
	}
	if conn.udp != nil {
		err = conn.udp.Close()
	}
	if conn.tcp != nil {
		err = conn.tcp.Close()
	}
	if conn.handle != nil {
		conn.handle.Close()
	}
	if conn.die != nil {
		close(conn.die)
	}
	go func() {
		conn.rcond.L.Lock()
		defer conn.rcond.L.Unlock()
		conn.rcond.Broadcast()
	}()
	return
}

func (conn *RAWConn) sendPacketWithLayer(layer *pktLayers) (err error) {
	buffer := gopacket.NewSerializeBuffer()
	opts := conn.opts
	layer.ip4.Id++
	layer.tcp.SetNetworkLayerForChecksum(layer.ip4)
	if layer.eth != nil {
		err = gopacket.SerializeLayers(buffer, opts,
			layer.eth, layer.ip4,
			layer.tcp, gopacket.Payload(layer.tcp.Payload))
	} else {
		err = gopacket.SerializeLayers(buffer, opts,
			&layers.Loopback{Family: layers.ProtocolFamilyIPv4}, layer.ip4,
			layer.tcp, gopacket.Payload(layer.tcp.Payload))
	}
	if err == nil {
		err = conn.handle.WritePacketData(buffer.Bytes())
	}
	return
}

func (conn *RAWConn) sendPacket() (err error) {
	return conn.sendPacketWithLayer(conn.layer)
}

func (layer *pktLayers) updateTCP() {
	tcp := layer.tcp
	tcp.Padding = nil
	tcp.FIN = false
	tcp.PSH = false
	tcp.ACK = false
	tcp.RST = false
	tcp.SYN = false
}

func (conn *RAWConn) updateTCP() {
	conn.layer.updateTCP()
}

func (conn *RAWConn) sendSynWithLayer(layer *pktLayers) (err error) {
	layer.updateTCP()
	tcp := layer.tcp
	tcp.SYN = true
	options := tcp.Options
	defer func() { tcp.Options = options }()
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x5, 0xb4},
	})
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindWindowScale,
		OptionLength: 3,
		OptionData:   []byte{0x6},
	})
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindSACKPermitted,
		OptionLength: 2,
	})
	return conn.sendPacketWithLayer(layer)
}

func (conn *RAWConn) sendSyn() (err error) {
	return conn.sendSynWithLayer(conn.layer)
}

func (conn *RAWConn) sendSynAckWithLayer(layer *pktLayers) (err error) {
	layer.updateTCP()
	tcp := layer.tcp
	tcp.SYN = true
	tcp.ACK = true
	options := tcp.Options
	defer func() { tcp.Options = options }()
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x5, 0xb4},
	})
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindWindowScale,
		OptionLength: 3,
		OptionData:   []byte{0x6},
	})
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType:   layers.TCPOptionKindSACKPermitted,
		OptionLength: 2,
	})
	return conn.sendPacketWithLayer(layer)
}

func (conn *RAWConn) sendSynAck() (err error) {
	return conn.sendSynAckWithLayer(conn.layer)
}

func (conn *RAWConn) sendAckWithLayer(layer *pktLayers) (err error) {
	layer.updateTCP()
	layer.tcp.ACK = true
	return conn.sendPacketWithLayer(layer)
}

func (conn *RAWConn) sendAck() (err error) {
	return conn.sendAckWithLayer(conn.layer)
}

func (conn *RAWConn) sendFinWithLayer(layer *pktLayers) (err error) {
	layer.updateTCP()
	layer.tcp.FIN = true
	return conn.sendPacketWithLayer(layer)
}

func (conn *RAWConn) sendFin() (err error) {
	return conn.sendPacketWithLayer(conn.layer)
}

func (conn *RAWConn) sendRstWithLayer(layer *pktLayers) (err error) {
	layer.updateTCP()
	layer.tcp.RST = true
	return conn.sendPacketWithLayer(layer)
}

func (conn *RAWConn) sendRst() (err error) {
	return conn.sendPacketWithLayer(conn.layer)
}

func (conn *RAWConn) writeWithLayer(b []byte, layer *pktLayers) (n int, err error) {
	n = len(b)
	layer.updateTCP()
	tcp := layer.tcp
	tcp.PSH = true
	tcp.ACK = true
	tcp.Payload = b
	defer func() { tcp.Payload = nil }()
	return n, conn.sendPacketWithLayer(layer)
}

// the write method don't increace the seq number
func (conn *RAWConn) write(b []byte) (n int, err error) {
	return conn.writeWithLayer(b, conn.layer)
}

func (conn *RAWConn) Write(b []byte) (n int, err error) {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	if conn.r.TLS {
		buf := utils.GetBuf(len(b) + 5)
		defer utils.PutBuf(buf)
		copy(buf, []byte{0x17, 0x3, 0x3})
		binary.BigEndian.PutUint16(buf[3:5], uint16(len(b)))
		copy(buf[5:], b)
		b = buf[:5+len(b)]
	}
	n, err = conn.write(b)
	conn.layer.tcp.Seq += uint32(n)
	return
}

func (conn *RAWConn) trySendAck(layer *pktLayers) {
	now := time.Now()
	if layer.tcp.Ack < layer.lastack+16384 {
		if now.Sub(layer.lastacktime) < time.Millisecond*time.Duration(10) {
			return
		}
	}
	layer.lastack = layer.tcp.Ack
	layer.lastacktime = now
	conn.sendAckWithLayer(layer)
}

func (conn *RAWConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	defer func() {
		if conn.rtimer != nil {
			conn.rtimer.Stop()
			conn.rtimer = nil
		}
	}()
	for {
		var layer *pktLayers
		layer, err = conn.readLayers()
		if err != nil {
			return
		}
		ip4 := layer.ip4
		tcp := layer.tcp
		if tcp.SYN && tcp.ACK {
			err = conn.sendAck()
			if err != nil {
				return
			}
			continue
		}
		if !tcp.PSH || !tcp.ACK || tcp.Seq == conn.hseqn {
			continue
		}
		if conn.udp != nil {
			addr = conn.RemoteAddr()
		} else {
			addr = &net.UDPAddr{
				IP:   ip4.SrcIP,
				Port: int(tcp.SrcPort),
			}
		}
		n = len(tcp.Payload)
		if n > 0 {
			if uint64(tcp.Seq)+uint64(n) > uint64(conn.layer.tcp.Ack) {
				conn.layer.tcp.Ack = tcp.Seq + uint32(n)
			}
			if conn.r.TLS {
				if n < 5 {
					continue
				}
				n = copy(b, tcp.Payload[5:])
			} else {
				n = copy(b, tcp.Payload)
			}
			conn.trySendAck(conn.layer)
		}
		return
	}
}

func (conn *RAWConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	uaddr := addr.(*net.UDPAddr)
	conn.layer.ip4.DstIP = uaddr.IP
	conn.layer.tcp.DstPort = layers.TCPPort(uaddr.Port)
	return conn.Write(b)
}

func (conn *RAWConn) Read(b []byte) (n int, err error) {
	n, _, err = conn.ReadFrom(b)
	return
}

func (conn *RAWConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.layer.ip4.SrcIP,
		Port: int(conn.layer.tcp.SrcPort),
	}
}

func (conn *RAWConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   conn.layer.ip4.DstIP,
		Port: int(conn.layer.tcp.DstPort),
	}
}

func (conn *RAWConn) SetReadDeadline(t time.Time) (err error) {
	if conn.rtimer != nil {
		conn.rtimer.Stop()
	}
	conn.rtimer = time.NewTimer(t.Sub(time.Now()))
	return
}

func (conn *RAWConn) SetWriteDeadline(t time.Time) (err error) {
	if conn.wtimer != nil {
		conn.wtimer.Stop()
	}
	conn.wtimer = time.NewTimer(t.Sub(time.Now()))
	return
}

func (conn *RAWConn) SetDeadline(t time.Time) (err error) {
	err = conn.SetReadDeadline(t)
	if err == nil {
		err = conn.SetWriteDeadline(t)
	}
	return
}

func (r *Raw) dialRAWDummy(address string) (conn *RAWConn, err error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return
	}
	udp, err := net.Dial("udp4", address)
	if err != nil {
		return
	}
	defer udp.Close()
	var ifaceName string
	for _, iface := range ifaces {
		for _, addr := range iface.Addresses {
			if addr.IP.Equal(udp.LocalAddr().(*net.UDPAddr).IP) {
				ifaceName = iface.Name
			}
		}
	}
	if len(ifaceName) == 0 {
		err = errors.New("cannot find correct interface")
		return
	}
	handle, err := pcap.OpenLive(ifaceName, 65536, true, time.Millisecond)
	if err != nil {
		return
	}
	filter := "tcp and src host " + udp.RemoteAddr().(*net.UDPAddr).IP.String() +
		" and src port " + strconv.Itoa(udp.RemoteAddr().(*net.UDPAddr).Port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return
	}
	conn = &RAWConn{
		buffer:     gopacket.NewSerializeBuffer(),
		handle:     handle,
		isLoopBack: udp.LocalAddr().(*net.UDPAddr).IP.IsLoopback(),
		packets:    make(chan gopacket.Packet),
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		r: r,
		layer: &pktLayers{
			ip4: &layers.IPv4{
				DstIP: udp.LocalAddr().(*net.UDPAddr).IP,
			},
			tcp: &layers.TCP{
				DstPort: layers.TCPPort(udp.LocalAddr().(*net.UDPAddr).Port),
			},
		},
		linktype: handle.LinkType(),
		die:      make(chan struct{}),
		rcond:    &sync.Cond{L: &sync.Mutex{}},
	}
	go conn.reader()
	defer func() {
		if err != nil {
			conn.Close()
		} else {
			conn.nocopy = true
		}
	}()
	var layersArray []*pktLayers
	var tcpConn net.Conn
	var tcpConnErr error
	var synAckLayer *pktLayers
	var tcpLocalAddr *net.TCPAddr
	var tcpRemoteAddr *net.TCPAddr
	sigch := make(chan bool)
	go func() {
		<-sigch
		tcpConn, tcpConnErr = net.Dial("tcp4", address)
		if tcpConn != nil && tcpConnErr == nil {
			tcpLocalAddr = tcpConn.LocalAddr().(*net.TCPAddr)
			tcpRemoteAddr = tcpConn.RemoteAddr().(*net.TCPAddr)
		}
	}()
	retry := 0
	sigch <- true
	for {
		if tcpConnErr != nil {
			err = tcpConnErr
			return
		}
		if tcpConn != nil && tcpLocalAddr != nil && tcpRemoteAddr != nil {
			for _, layer := range layersArray {
				if int(layer.tcp.SrcPort) == tcpRemoteAddr.Port &&
					int(layer.tcp.DstPort) == tcpLocalAddr.Port &&
					layer.ip4.SrcIP.Equal(tcpRemoteAddr.IP) &&
					layer.ip4.DstIP.Equal(tcpLocalAddr.IP) {
					synAckLayer = layer
					break
				}
			}
			if synAckLayer != nil {
				break
			}
			if retry > 5 {
				var layersArrayString string
				for _, layer := range layersArray {
					layersArrayString += fmt.Sprintf("{%d %d %v %v} ", int(layer.tcp.SrcPort), int(layer.tcp.DstPort),
						layer.ip4.SrcIP.Equal(tcpRemoteAddr.IP), layer.ip4.DstIP.Equal(tcpLocalAddr.IP))
				}
				err = fmt.Errorf("retry too many times and con't capture anything\n"+
					"len(layersArray)=%d\n"+"tcpRemoteAddr.Port=%d\ntcpLocalAddr.Port=%d\n"+
					"layersArray:\n%s\n", len(layersArray), tcpRemoteAddr.Port, tcpLocalAddr.Port, layersArrayString)
				return
			}
		}
		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
		var layer *pktLayers
		layer, err = conn.readLayers()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				retry++
				continue
			}
			return
		}
		if layer == nil || layer.ip4 == nil || layer.tcp == nil ||
			!(layer.tcp.SYN && layer.tcp.ACK) {
			continue
		}
		layersArray = append(layersArray, layer)
	}
	conn.SetReadDeadline(time.Time{})
	ipv4.NewConn(tcpConn).SetTTL(0)
	conn.layer = &pktLayers{
		ip4: &layers.IPv4{
			SrcIP:    tcpLocalAddr.IP,
			DstIP:    tcpRemoteAddr.IP,
			Protocol: layers.IPProtocolTCP,
			Version:  0x4,
			Id:       uint16(ran.Int() % 65536),
			Flags:    layers.IPv4DontFragment,
			TTL:      0x40,
			TOS:      uint8(r.DSCP),
		},
		tcp: &layers.TCP{
			SrcPort: layers.TCPPort(tcpLocalAddr.Port),
			DstPort: layers.TCPPort(tcpRemoteAddr.Port),
			Window:  12580,
			Ack:     synAckLayer.tcp.Seq + 1,
			Seq:     synAckLayer.tcp.Ack,
		},
	}
	if synAckLayer.eth != nil {
		conn.layer.eth = &layers.Ethernet{
			EthernetType: synAckLayer.eth.EthernetType,
			SrcMAC:       synAckLayer.eth.DstMAC,
			DstMAC:       synAckLayer.eth.SrcMAC,
		}
	}
	conn.tcp = tcpConn
	filter = "tcp and src host " + conn.layer.ip4.DstIP.String() +
		" and src port " + strconv.Itoa(int(conn.layer.tcp.DstPort)) +
		" and dst host " + conn.layer.ip4.SrcIP.String() +
		" and dst port " + strconv.Itoa(int(conn.layer.tcp.SrcPort))
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return
	}
	var cl *pktLayers
	tcp := conn.layer.tcp
	defer func() { conn.rtimer = nil }()
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
		if tcpRemoteAddr.Port != 80 {
			host += strconv.Itoa(tcpRemoteAddr.Port)
		}
		headers := "Host: " + host + "\r\n"
		headers += "X-Online-Host: " + host + "\r\n"
		req = utils.StringToSlice(buildHTTPRequest(headers))
	}
	retry = 0
	needretry := true
	var starttime time.Time
out:
	for {
		if retry > 25 {
			err = errors.New("retry too many times")
			return
		}
		if needretry {
			starttime = time.Now()
			needretry = false
			retry++
			_, err = conn.write(req)
			if err != nil {
				return
			}
		}
		err = conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(200+int(ran.Int63()%100))))
		if err != nil {
			return
		}
		cl, err = conn.readLayers()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			}
			needretry = true
			continue out
		}
		n := len(cl.tcp.Payload)
		if cl.tcp.PSH && cl.tcp.ACK && n >= 20 {
			var ok bool
			if r.TLS {
				ok, _, _ = utils.ParseTLSServerHelloMsg(cl.tcp.Payload)
			} else {
				head := string(cl.tcp.Payload[:4])
				tail := string(cl.tcp.Payload[n-4:])
				if head == "HTTP" && tail == "\r\n\r\n" {
					ok = true
				}
			}
			if ok {
				conn.hseqn = cl.tcp.Seq
				tcp.Seq += uint32(len(req))
				tcp.Ack = cl.tcp.Seq + uint32(n)
				break out
			}
		}
		if time.Now().After(starttime.Add(time.Millisecond * 200)) {
			needretry = true
		}
	}
	return
}

func (r *Raw) DialRAW(address string) (conn *RAWConn, err error) {
	if r.Dummy {
		return r.dialRAWDummy(address)
	}
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return
	}
	udp, err := net.Dial("udp4", address)
	if err != nil {
		return
	}
	defer func() {
		if udp != nil {
			udp.Close()
		}
	}()
	ulocaladdr := udp.LocalAddr().(*net.UDPAddr)
	localaddr := &net.IPAddr{IP: ulocaladdr.IP}
	uremoteaddr := udp.RemoteAddr().(*net.UDPAddr)
	remoteaddr := &net.IPAddr{IP: uremoteaddr.IP}
	var ifaceName string
	for _, iface := range ifaces {
		for _, addr := range iface.Addresses {
			if addr.IP.Equal(ulocaladdr.IP) {
				ifaceName = iface.Name
			}
		}
	}
	if len(ifaceName) == 0 {
		err = errors.New("cannot find correct interface")
		return
	}
	handle, err := pcap.OpenLive(ifaceName, 65536, true, time.Millisecond)
	if err != nil {
		return
	}
	conn = &RAWConn{
		udp:        udp,
		buffer:     gopacket.NewSerializeBuffer(),
		handle:     handle,
		isLoopBack: udp.LocalAddr().(*net.UDPAddr).IP.IsLoopback(),
		packets:    make(chan gopacket.Packet),
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		layer: &pktLayers{
			ip4: &layers.IPv4{
				SrcIP:    localaddr.IP,
				DstIP:    remoteaddr.IP,
				Protocol: layers.IPProtocolTCP,
				Version:  0x4,
				Id:       uint16(ran.Int63() % 65536),
				Flags:    layers.IPv4DontFragment,
				TTL:      0x40,
				TOS:      uint8(r.DSCP),
			},
			tcp: &layers.TCP{
				SrcPort: layers.TCPPort(ulocaladdr.Port),
				DstPort: layers.TCPPort(uremoteaddr.Port),
				Window:  12580,
				Ack:     0,
			},
		},
		r:        r,
		linktype: handle.LinkType(),
		die:      make(chan struct{}),
		rcond:    &sync.Cond{L: &sync.Mutex{}},
	}
	udp = nil
	go conn.reader()
	defer func() {
		if err != nil {
			conn.Close()
		} else {
			conn.nocopy = true
		}
	}()
	var eth *layers.Ethernet
	if ulocaladdr.IP.String() != "127.0.0.1" {
		buf := make([]byte, 32)
		binary.Read(rand.Reader, binary.LittleEndian, buf)
		var uconn *net.UDPConn
		uconn, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(8, 8, buf[0], buf[1]), Port: int(binary.LittleEndian.Uint16(buf[2:4]))})
		if err != nil {
			return
		}
		defer uconn.Close()
		filter := "udp and src port " + strconv.Itoa(uconn.LocalAddr().(*net.UDPAddr).Port) +
			" and dst host " + uconn.RemoteAddr().(*net.UDPAddr).IP.String() +
			" and dst port " + strconv.Itoa(uconn.RemoteAddr().(*net.UDPAddr).Port)
		err = handle.SetBPFFilter(filter)
		if err != nil {
			return
		}

		sigch := make(chan bool)

		go func() {
			<-sigch
			_, err = uconn.Write(buf)
			if err != nil {
				return
			}
		}()

		conn.SetReadDeadline(time.Now().Add(time.Second * 2))

		var packet gopacket.Packet
		packet, err = conn.readPacket()
		if err != nil {
			return
		}

		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		loopLayer := packet.Layer(layers.LayerTypeLoopback)
		if ethLayer != nil {
			eth, _ = ethLayer.(*layers.Ethernet)
		} else if loopLayer == nil {
			return
		}
	}
	conn.layer.eth = eth
	filter := "tcp and src host " + remoteaddr.String() +
		" and src port " + strconv.Itoa(uremoteaddr.Port) +
		" and dst host " + localaddr.String() +
		" and dst port " + strconv.Itoa(ulocaladdr.Port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return
	}
	tcp := conn.layer.tcp
	var cl *pktLayers
	binary.Read(rand.Reader, binary.LittleEndian, &(conn.layer.tcp.Seq))
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("echo block drop out proto tcp from %s port %d to %s port %d flags R/R >> /etc/pf.conf && pfctl -f /etc/pf.conf",
			localaddr.String(), ulocaladdr.Port, remoteaddr.String(), uremoteaddr.Port))
		_, err = cmd.CombinedOutput()
		if err == nil {
			exec.Command("pfctl", "-e").Run()
			cleaner := &utils.ExitCleaner{}
			filename := randStringBytesMaskImprSrc(20)
			clean := exec.Command("sh", "-c", fmt.Sprintf("cat /etc/pf.conf | grep -v "+
				"'block drop out proto tcp from %s port %d to %s port %d flags R/R' > /tmp/%s.conf && mv /tmp/%s.conf /etc/pf.conf"+
				" && pfctl -f /etc/pf.conf",
				localaddr.String(), ulocaladdr.Port, remoteaddr.String(), uremoteaddr.Port, filename, filename))
			cleaner.Push(func() {
				clean.Run()
				exec.Command("pfctl", "-e").Run()
			})
			conn.cleaner = cleaner
		}
	} else if runtime.GOOS == "windows" {

	}
	retry := 0
	var ackn uint32
	var seqn uint32
	defer func() { conn.rtimer = nil }()
	for {
		if retry > 5 {
			err = errors.New("retry too many times")
			return
		}
		retry++
		err = conn.sendSyn()
		if err != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(500+int(ran.Int63()%500))))
		cl, err = conn.readLayers()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			}
			continue
		}
		if cl.tcp.SYN && cl.tcp.ACK {
			tcp.Ack = cl.tcp.Seq + 1
			tcp.Seq++
			ackn = tcp.Ack
			seqn = tcp.Seq
			conn.mss = getMssFromTcpLayer(cl.tcp)
			err = conn.sendAck()
			if err != nil {
				return
			}
		}
		break
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
			_, err = conn.write(req)
			if err != nil {
				return
			}
		}
		err = conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(200+int(ran.Int63()%100))))
		if err != nil {
			return
		}
		cl, err = conn.readLayers()
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				return
			}
			needretry = true
			continue
		}
		if cl.tcp.SYN && cl.tcp.ACK {
			tcp.Ack = ackn
			tcp.Seq = seqn
			err = conn.sendAck()
			if err != nil {
				return
			}
			continue
		}
		n := len(cl.tcp.Payload)
		if cl.tcp.PSH && cl.tcp.ACK && n >= 20 {
			var ok bool
			if r.TLS {
				ok, _, _ = utils.ParseTLSServerHelloMsg(cl.tcp.Payload)
			} else {
				head := string(cl.tcp.Payload[:4])
				tail := string(cl.tcp.Payload[n-4:])
				if head == "HTTP" && tail == "\r\n\r\n" {
					ok = true
				}
			}
			if ok {
				conn.hseqn = cl.tcp.Seq
				tcp.Seq += uint32(len(req))
				tcp.Ack = cl.tcp.Seq + uint32(n)
				break
			}
		}
		if time.Now().After(starttime.Add(time.Millisecond * 200)) {
			needretry = true
		}
	}
	return
}

func chooseInterfaceByAddr(addr string) (in pcap.Interface, err error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		for _, address := range iface.Addresses {
			if address.IP.String() == addr {
				in = iface
				return
			}
		}
	}
	err = errors.New("incorrect bind address")
	return
}

type RAWListener struct {
	*RAWConn
	newcons map[string]*connInfo
	conns   map[string]*connInfo
	mutex   myMutex
	laddr   *net.IPAddr
	lport   int
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

func (listener *RAWListener) Close() (err error) {
	conn := listener
	// if conn != nil {
	// 	listener.mutex.run(func() {
	// 		for _, v := range listener.newcons {
	// 			listener.closeConn(v)
	// 		}
	// 		for _, v := range listener.conns {
	// 			listener.closeConn(v)
	// 		}
	// 	})
	// }
	return conn.RAWConn.Close()
}

func (listener *RAWListener) closeConn(info *connInfo) (err error) {
	return listener.sendFinWithLayer(info.layer)
}

func (r *Raw) ListenRAW(address string) (listener *RAWListener, err error) {
	udpaddr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return
	}
	if udpaddr.IP == nil || udpaddr.IP.Equal(net.IPv4(0, 0, 0, 0)) {
		udpaddr.IP = net.IPv4(127, 0, 0, 1)
	}
	in, err := chooseInterfaceByAddr(udpaddr.IP.String())
	if err != nil {
		return
	}
	handle, err := pcap.OpenLive(in.Name, 65536, true, time.Millisecond*1)
	if err != nil {
		return
	}
	filter := "tcp and dst host " + udpaddr.IP.String() +
		" and dst port " + strconv.Itoa(udpaddr.Port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return
	}
	pktsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	listener = &RAWListener{
		laddr: &net.IPAddr{IP: udpaddr.IP},
		lport: udpaddr.Port,
		RAWConn: &RAWConn{
			buffer:  gopacket.NewSerializeBuffer(),
			handle:  handle,
			pktsrc:  pktsrc,
			packets: pktsrc.Packets(),
			opts: gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			},
			r: r,
		},
		newcons: make(map[string]*connInfo),
		conns:   make(map[string]*connInfo),
	}
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("echo block drop out proto tcp from %s port %d to any flags R/R >> /etc/pf.conf && pfctl -f /etc/pf.conf",
			listener.laddr.String(), listener.lport))
		_, err = cmd.CombinedOutput()
		if err == nil {
			exec.Command("pfctl", "-e").Run()
			cleaner := &utils.ExitCleaner{}
			filename := randStringBytesMaskImprSrc(20)
			clean := exec.Command("sh", "-c", fmt.Sprintf("cat /etc/pf.conf | grep -v "+
				"'block drop out proto tcp from %s port %d to any flags R/R' > /tmp/%s.conf && mv /tmp/%s.conf /etc/pf.conf"+
				" && pfctl -f /etc/pf.conf",
				listener.laddr.String(), listener.lport, filename, filename))
			cleaner.Push(func() {
				clean.Run()
				exec.Command("pfctl", "-e").Run()
			})
			listener.cleaner = cleaner
		}
	}
	return
}

func (listener *RAWListener) closeConnByAddr(addrstr string) (err error) {
	info, ok := listener.newcons[addrstr]
	if ok {
		delete(listener.newcons, addrstr)
	} else {
		info, ok = listener.conns[addrstr]
		if ok {
			delete(listener.conns, addrstr)
		}
	}
	if info != nil {
		err = listener.closeConn(info)
	}
	return
}

func (listener *RAWListener) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		var cl *pktLayers
		cl, err = listener.readLayers()
		if err != nil {
			return
		}
		tcp := cl.tcp
		listener.layer = nil
		uaddr := &net.UDPAddr{
			IP:   cl.ip4.SrcIP,
			Port: int(tcp.SrcPort),
		}
		addr = uaddr
		addrstr := uaddr.String()
		if (tcp.RST) || tcp.FIN {
			listener.mutex.run(func() {
				err = listener.closeConnByAddr(addrstr)
			})
			if err != nil {
				return
			}
			continue
		}
		var info *connInfo
		var ok bool
		listener.mutex.run(func() {
			info, ok = listener.conns[addrstr]
		})
		n = len(tcp.Payload)
		if ok && n != 0 {
			if uint64(tcp.Seq)+uint64(n) > uint64(info.layer.tcp.Ack) {
				info.layer.tcp.Ack = tcp.Seq + uint32(n)
			}
			if info.state == httprepsent {
				if tcp.PSH && tcp.ACK {
					if tcp.Seq == info.hseqn && n > 20 {
						ok := false
						if listener.r.TLS || listener.r.Mixed {
							ok, _, _ = utils.ParseTLSClientHelloMsg(tcp.Payload)
						} else {
							head := string(tcp.Payload[:4])
							tail := string(tcp.Payload[n-4:])
							if head == "POST" && tail == "\r\n\r\n" {
								ok = true
							}
						}
						if ok {
							info.layer.tcp.Ack = tcp.Seq + uint32(n)
							info.layer.tcp.Seq += uint32(len(info.rep))
							_, err = listener.writeWithLayer(info.rep, info.layer)
							if err != nil {
								return
							}
						}
					} else {
						info.layer.tcp.Seq += uint32(len(info.rep))
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
					if len(tcp.Payload) < 5 {
						continue
					}
					n = copy(b, tcp.Payload[5:])
				} else {
					n = copy(b, tcp.Payload)
				}
				return
			}
			continue
		}
		if ok && n == 0 {
			if tcp.ACK && tcp.PSH {
				return
			}
			continue
		}
		listener.mutex.run(func() {
			info, ok = listener.newcons[addrstr]
		})
		if ok {
			if info.state == synreceived {
				if tcp.ACK && !tcp.PSH && !tcp.FIN && !tcp.SYN {
					info.layer.tcp.Seq++
					if listener.r.NoHTTP {
						info.state = established
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
					} else {
						info.state = waithttpreq
					}
				} else if tcp.SYN && !tcp.ACK && !tcp.PSH {
					listener.layer = info.layer
					err = listener.sendSynAckWithLayer(info.layer)
					if err != nil {
						return
					}
				}
			} else if info.state == waithttpreq {
				if tcp.PSH && tcp.ACK && n > 20 {
					if listener.r.TLS || listener.r.Mixed {
						ok, _, msg := utils.ParseTLSClientHelloMsg(tcp.Payload)
						if ok {
							info.layer.tcp.Ack += uint32(n)
							if info.rep == nil {
								rep := make([]byte, 2048)
								l := ran.Intn(128)
								n = utils.GenTLSServerHello(rep, l, msg.SessionId)
								info.rep = rep[:l+n]
							}
							info.hseqn = tcp.Seq
						}
					}
					head := string(tcp.Payload[:4])
					tail := string(tcp.Payload[n-4:])
					if info.rep == nil && head == "POST" && tail == "\r\n\r\n" {
						info.layer.tcp.Ack += uint32(n)
						if info.rep == nil {
							rep := buildHTTPResponse("")
							info.rep = []byte(rep)
						}
						info.hseqn = tcp.Seq
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
						info.layer.tcp.Ack = tcp.Seq + uint32(n)
						info.state = established
						listener.mutex.run(func() {
							listener.conns[addrstr] = info
							delete(listener.newcons, addrstr)
						})
						n = copy(b, tcp.Payload)
						return
					}
				} else if tcp.SYN && !tcp.ACK && !tcp.PSH {
					err = listener.sendSynAckWithLayer(info.layer)
					if err != nil {
						return
					}
				}
			}
			continue
		}
		layer := &pktLayers{
			eth: nil,
			ip4: &layers.IPv4{
				SrcIP:    cl.ip4.DstIP,
				DstIP:    cl.ip4.SrcIP,
				Protocol: layers.IPProtocolTCP,
				Version:  0x4,
				Id:       uint16(ran.Int63() % 65536),
				Flags:    layers.IPv4DontFragment,
				TTL:      0x40,
				TOS:      uint8(listener.r.DSCP),
			},
			tcp: &layers.TCP{
				SrcPort: cl.tcp.DstPort,
				DstPort: cl.tcp.SrcPort,
				Window:  32760,
				Ack:     cl.tcp.Seq + 1,
			},
		}
		if cl.eth != nil {
			layer.eth = &layers.Ethernet{
				DstMAC:       cl.eth.SrcMAC,
				SrcMAC:       cl.eth.DstMAC,
				EthernetType: cl.eth.EthernetType,
			}
		}
		if tcp.SYN && !tcp.ACK && !tcp.PSH && !tcp.FIN {
			info := &connInfo{
				state: synreceived,
				layer: layer,
				mss:   getMssFromTcpLayer(tcp),
			}
			binary.Read(rand.Reader, binary.LittleEndian, &(info.layer.tcp.Seq))
			err = listener.sendSynAckWithLayer(info.layer)
			if err != nil {
				return
			}
			listener.mutex.run(func() {
				listener.newcons[addrstr] = info
			})
		} else {
			listener.layer = layer
			listener.sendFinWithLayer(layer)
		}
	}
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
	info.layer.tcp.Seq += uint32(n)
	return
}

func (listener *RAWListener) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   listener.laddr.IP,
		Port: listener.lport,
	}
}

// FIXME
type pktLayers struct {
	eth         *layers.Ethernet
	ip4         *layers.IPv4
	tcp         *layers.TCP
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
