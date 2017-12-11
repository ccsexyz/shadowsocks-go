package ss

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/ccsexyz/utils"
)

type DialOptions struct {
	RawHeader []byte
	Data      []byte
	C         *Config
	PartEnc   bool
	UseSnappy bool
	Target    string
	Timeout   int
}

var (
	errTargetTooLong = fmt.Errorf("target length is too long")
	errNoBackends    = fmt.Errorf("no available backends")
)

func dialSSWithOptions(opt *DialOptions) (conn Conn, err error) {
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
			conn = nil
		}
	}()
	c := opt.C
	if c.Mux {
		return DialMux(opt.Target, c)
	}
	if len(c.Backends) != 0 {
		die := make(chan bool)
		num := len(c.Backends)
		errch := make(chan error, num)
		conch := make(chan Conn)
		for _, v := range c.Backends {
			if v.disable {
				num--
				continue
			}
			newOpts := *opt
			newOpts.C = v
			if len(opt.Data) > 0 {
				newOpts.Data = utils.CopyBuffer(opt.Data)
			}
			go func(newOpts *DialOptions) {
				if len(newOpts.Data) > 0 {
					defer utils.PutBuf(newOpts.Data)
				}
				rconn, err := dialSSWithOptions(newOpts)
				if err != nil {
					select {
					case <-die:
					case errch <- fmt.Errorf("cannot connect to %s : %s", newOpts.C.Remoteaddr, err.Error()):
					}
					return
				}
				select {
				case <-die:
					rconn.Close()
				case conch <- rconn:
				}
			}(&newOpts)
		}
		for i := 0; i < num; i++ {
			select {
			case conn = <-conch:
				close(die)
				i = num
			case <-errch:
			}
		}
		if conn == nil {
			err = errNoBackends
		}
		return
	}
	if len(opt.RawHeader) == 0 {
		host, port, sperr := utils.SplitHostAndPort(opt.Target)
		if sperr != nil {
			return nil, sperr
		}
		opt.RawHeader, err = GetHeader(host, port)
		if err != nil {
			return
		}
	}
	if c.Snappy {
		opt.UseSnappy = true
	}
	if c.PartEnc {
		opt.PartEnc = true
	}
	if c.PartEncHTTPS && !opt.PartEnc && len(opt.Data) > 0 {
		ok, _, _ := utils.ParseTLSClientHelloMsg(opt.Data)
		if ok {
			opt.PartEnc = true
			opt.UseSnappy = false
		}
	}
	if c.Obfs {
		conn, err = DialObfs(c.Remoteaddr, c)
	} else {
		var tconn *TCPConn
		tconn, err = DialTCP(c.Remoteaddr, c)
		if tconn != nil {
			conn = tconn
		}
	}
	if err != nil {
		return
	}
	if len(c.limiters) != 0 || c.LimitPerConn != 0 {
		limiters := make([]*Limiter, len(c.limiters))
		copy(limiters, c.limiters)
		if c.LimitPerConn != 0 {
			limiters = append(limiters, NewLimiter(c.LimitPerConn))
		}
		conn = &LimitConn{
			Conn:      conn,
			Rlimiters: limiters,
		}
	}
	C := NewSsConn(conn, c)
	conn = C
	if c.Nonop {
		conn = &RemainConn{
			Conn:    conn,
			wremain: opt.RawHeader,
		}
	} else {
		header := make([]byte, 512)
		headerLen := 0
		if opt.PartEnc {
			C.partenc = true
			C.partencnum = 16384
			headerLen += copy(header[headerLen:], []byte{typePartEnc, 0x10})
		}
		if opt.UseSnappy {
			headerLen += copy(header[headerLen:], []byte{typeSnappy})
		}
		noplen := rand.Intn(4)
		noplen += int(crc32.Checksum(header, c.crctbl) % (128 - (lenTs + 5)))
		headerLen += copy(header[headerLen:], []byte{typeNop, byte(noplen)})
		headerLen += noplen
		header[headerLen] = typeTs
		headerLen++
		binary.BigEndian.PutUint64(header[headerLen:], uint64(time.Now().Unix()))
		headerLen += lenTs
		conn = &RemainConn{
			Conn:    conn,
			wremain: append(header[:headerLen], opt.RawHeader...),
		}
		if opt.UseSnappy {
			conn = NewSnappyConn(conn)
		}
	}
	return
}

func DialSSWithOptions(opt *DialOptions) (conn Conn, err error) {
	defer func() {
		if conn != nil {
			if err == nil && len(opt.Data) > 0 {
				_, err = conn.Write(opt.Data)
			}
			if err != nil {
				conn.Close()
				conn = nil
			}
		}
	}()

	c := opt.C

	if len(opt.Target) == 0 && c.MITM && len(opt.Data) > 0 {
		ok, _, msg := utils.ParseTLSClientHelloMsg(opt.Data)
		if ok {
			if len(msg.ServerName) != 0 {
				if c.PartEncHTTPS {
					opt.PartEnc = true
				}
				opt.UseSnappy = false
				if strings.ContainsRune(msg.ServerName, ':') {
					opt.Target = msg.ServerName
				} else {
					opt.Target = msg.ServerName + ":443"
				}
			}
		} else {
			parser := utils.NewHTTPHeaderParser(utils.GetBuf(httpbuffersize))
			defer utils.PutBuf(parser.GetBuf())
			ok, _ = parser.Read(opt.Data)
			if ok {
				hosts, ok := parser.Load([]byte("Host"))
				if ok && len(hosts) > 0 && len(hosts[0]) > 0 {
					target := utils.SliceToString(hosts[0])
					if strings.ContainsRune(target, ':') {
						opt.Target = target
					} else {
						opt.Target = target + ":80"
					}
				}
			}
		}
	}

	var direct, proxy bool
	var ip net.IP

	host, _, err := net.SplitHostPort(opt.Target)
	if err != nil {
		return
	}

	ip = net.ParseIP(host)

	if ip != nil && c.chnListCtx != nil {
		if c.chnListCtx.testIP(ip) {
			c.LogD("host", host, "hit chn route")
			direct = true
		} else {
			c.LogD("host", host, "miss chn route")
			proxy = true
		}
	} else {
		if c.autoProxyCtx == nil {
			proxy = true
		} else if c.autoProxyCtx.checkIfByPass(host) {
			c.LogD("host", host, "hit bypass list")
			direct = true
		} else if c.autoProxyCtx.checkIfProxy(host) {
			c.LogD("host", host, "hit proxy list")
			proxy = true
		} else if host == "localhost" {
			direct = true
		} else if !strings.ContainsRune(host, '.') {
			proxy = true
		}
	}

	if direct {
		return DialTCPConn(opt.Target, opt.C)
	}

	if proxy {
		return dialSSWithOptions(opt)
	}

	die := make(chan bool)
	num := 2
	errch := make(chan error, 2)
	conch := make(chan Conn)

	type dialer func(*DialOptions) (Conn, error)
	work := func(d dialer, direct bool) {
		rconn, err := d(opt)
		if err != nil {
			select {
			case <-die:
			case errch <- err:
			}
			return
		}
		select {
		case <-die:
			rconn.Close()
		case conch <- rconn:
			if ip == nil {
				if direct {
					c.autoProxyCtx.markHostByPass(host)
					c.LogD("add", host, "to bypass list")
				} else {
					c.autoProxyCtx.markHostNeedProxy(host)
					c.LogD("add", host, "to proxy list")
				}
			}
		}
	}

	go work(dialSSWithOptions, false)
	go work(func(opt *DialOptions) (Conn, error) { return DialTCPConn(opt.Target, opt.C) }, true)

	for i := 0; i < num; i++ {
		select {
		case conn = <-conch:
			close(die)
			i = num
			err = nil
		case err = <-errch:
		}
	}

	return
}
