package ss

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	"golang.org/x/net/proxy"
)

type DialOptions struct {
	RawHeader []byte
	Data      []byte
	C         *Config
	Target    string
	Timeout   int
}

var (
	errTargetTooLong = fmt.Errorf("target length is too long")
	errNoBackends    = fmt.Errorf("no available backends")
)

func dialSocks5WithOptions(opt *DialOptions) (conn Conn, err error) {
	var rawConn net.Conn
	var dialer proxy.Dialer

	c := opt.C

	dialer, err = proxy.SOCKS5("tcp", c.Remoteaddr, nil, proxy.Direct)
	if err != nil {
		return
	}

	rawConn, err = dialer.Dial("tcp", opt.Target)
	if err != nil {
		return
	}

	conn = newTCPConn(&utils.UtilsConn{Conn: rawConn}, c)
	return
}

func checkAndModifyTarget(opt *DialOptions) (newOpt *DialOptions, err error) {
	c := opt.C

	if !c.LocalResolve {
		return
	}

	isDomain, isV4, host, port := checkAddrType(opt.Target)
	if !isDomain {
		if isV4 && c.NoIPv4 {
			err = fmt.Errorf("IPv4 is disabled")
		} else if !isV4 && c.NoIPv6 {
			err = fmt.Errorf("IPv6 is disabled")
		}
		return
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return
	}

	noIPv6 := c.NoIPv6
	if c.PreferIPv4 && !noIPv6 {
		hasV4 := false
		hasV6 := false

		addrCount := len(ips)
		for i := 0; i < addrCount && !(hasV4 && hasV6); i++ {
			ip := ips[i]
			if ip.To4() != nil {
				hasV4 = true
			} else if ip.To16() != nil && ip.To4() == nil {
				hasV6 = true
			}
		}

		if hasV4 && hasV6 {
			noIPv6 = true
		}
	}

	for _, idx := range rand.Perm(len(ips)) {
		ip := ips[idx]

		if c.NoIPv4 && ip.To4() != nil {
			continue
		}
		if noIPv6 && ip.To16() != nil && ip.To4() == nil {
			continue
		}

		newOpt = new(DialOptions)
		*newOpt = *opt // copy the options to avoid modifying the original one
		newOpt.Target = net.JoinHostPort(ip.String(), strconv.Itoa(port))
		return
	}
	err = fmt.Errorf("resolve %s fail, no ip found", host)
	return
}

func dialSSWithOptions(opt *DialOptions) (conn Conn, err error) {
	newOpt, err := checkAndModifyTarget(opt)
	if err != nil {
		return
	}
	if newOpt != nil {
		opt = newOpt
	}

	c := opt.C
	if c.Method == "socks5" {
		return dialSocks5WithOptions(opt)
	}
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
			conn = nil
		}
	}()
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
	dec, err := utils.NewDecrypter(c.Method, c.Password)
	if err != nil {
		return
	}
	enc, err := utils.NewEncrypter(c.Method, c.Password)
	if err != nil {
		return
	}
	C := &SsConn{Conn: conn, enc: enc, dec: dec, c: c}
	conn = C
	if c.Nonop {
		conn = &RemainConn{
			Conn:    conn,
			wremain: opt.RawHeader,
		}
	} else {
		header := make([]byte, 512)
		headerLen := 0
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

	if c.Direct {
		direct = true
	} else if ip != nil && c.chnListCtx != nil {
		if c.chnListCtx.testIP(ip) {
			c.LogD("host", host, "hit chn route")
			direct = true
		} else {
			c.LogD("host", host, "miss chn route")
			proxy = true
		}
	} else {
		if c.AutoProxy == false || c.autoProxyCtx == nil {
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
