package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"sort"
	"strings"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/utils"
)

var (
	pprofaddr = flag.String("pprof", "", "listen address for pprof")
)

func init() {
	if *pprofaddr != "" {
		utils.RunProfileHTTPServer(*pprofaddr)
	}
}

func init() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)
}

type tunnelAcceptor struct {
	raddr string
}

func newTunnelAcceptor(raddr string) Acceptor {
	return &tunnelAcceptor{raddr: raddr}
}

func (t *tunnelAcceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	ctx.Store(ss.CtxTarget, ss.NewDstAddr(t.raddr))
	return conn, nil
}

type localAcceptor struct {
	dialer ss.Dialer
}

func newLocalAcceptor(dialers ...ss.Dialer) ss.Acceptor {
	if len(dialers) == 0 {
		return &localAcceptor{dialer: ss.NewNetDialer()}
	} else if len(dialers) == 1 {
		return &localAcceptor{dialer: dialers[0]}
	} else {
		return &localAcceptor{dialer: ss.NewPickFastDialer(dialers...)}
	}
}

func (acc *localAcceptor) Accept(conn ss.Conn, ctx *ss.ConnCtx) (ss.Conn, error) {
	v, ok := ctx.Get(ss.CtxTarget)
	if !ok {
		return nil, nil
	}
	dst := v.(ss.DstAddr)
	addr := dst.String()
	var uptls bool
	if strings.HasPrefix(addr, "tls://") {
		uptls = true
		addr = strings.TrimPrefix(addr, "tls://")
	}
	rconn, err := acc.dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer rconn.Close()
	if uptls {
		v, ok = ctx.Get("ServerName")
		if !ok {
			return nil, nil
		}
		serverName := v.(string)
		rTLSConn := tls.Client(ss.NewNetConnFromConn(rconn),
			&tls.Config{ServerName: serverName})
		rconn = ss.NewConnFromNetConn(rTLSConn)
	}
	log.Println("proxy", addr, "to", rconn.RemoteAddr())
	ss.Pipe(conn, rconn)
	return nil, nil
}

func main() {
	flag.Parse()
	var configs []*Config
	var err error
	if len(configPath) != 0 {
		configs, err = readConfig(configPath)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		checkConfig(&defaultConfig)
		configs = append(configs, &defaultConfig)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, config := range configs {
		go runServer(ctx, config)
	}
	<-ctx.Done()
}

func getOrder(c *Config) int {
	switch c.Type {
	default:
		return 5
	case "shadowsocks", "ss":
		if ss.IsAEAD(c.Method) {
			return 3
		}
		return 4
	case "http":
		return 2
	case "socks":
		return 1
	case "plain":
		return 0
	}
}

func runServer(ctx context.Context, config *Config) {
	config.print()
	bultin := newBultinServiceAcceptor()
	bultin.StoreServiceAcceptor(echoaddr, new(echoAcceptor))
	sort.SliceStable(config.Input, func(i, j int) bool {
		return getOrder(config.Input[i]) < getOrder(config.Input[j])
	})
	sort.SliceStable(config.Output, func(i, j int) bool {
		return getOrder(config.Output[i]) < getOrder(config.Output[j])
	})
	var pickOneAcceptors []Acceptor
	for _, in := range config.Input {
		var acc Acceptor
		switch in.Type {
		case "socks":
			acc = ss.NewSocks5Acceptor()
		case "http":
			acc = ss.NewHTTPProxyAcceptor()
		case "shadowsocks", "ss":
			if ss.IsAEAD(in.Method) {
				acc = ss.NewAEADShadowSocksAcceptor(in.Method, in.Password)
			} else {
				acc = ss.NewShadowSocksAcceptor(in.Method, in.Password)
			}
		case "plain":
			if len(in.RemoteAddr) > 0 {
				acc = newTunnelAcceptor(in.RemoteAddr)
			}
		}
		if acc != nil {
			pickOneAcceptors = append(pickOneAcceptors, acc)
		}
	}
	var dialers []Dialer
	for _, out := range config.Output {
		var dial Dialer
		switch out.Type {
		case "socks":
			dial = ss.NewSocks5Dialer(nil, out.RemoteAddr)
		case "http":
			dial = ss.NewHTTPProxyDialer(nil, out.RemoteAddr)
		case "shadowsocks", "ss":
			if ss.IsAEAD(out.Method) {
				dial = ss.NewAEADShadowSocksDialer(ss.NewNetDialer(),
					out.RemoteAddr, out.Method, out.Password)
			} else {
				dial = ss.NewShadowSocksDialer(
					ss.NewNetDialer(), out.RemoteAddr, out.Method, out.Password)
			}
		case "plain":
			dial = ss.NewNetDialer()
		}
		dialers = append(dialers, dial)
	}
	pickone := ss.NewPickOneAcceptor(pickOneAcceptors...)
	accs := ss.Acceptors([]ss.Acceptor{
		pickone, bultin,
	})
	if config.DecTLS {
		accs = append(accs, ss.NewTLSAcceptor(config.RootCA, config.RootKey))
	}
	accs = append(accs, newLocalAcceptor(dialers...))
	for _, addr := range strings.Split(config.LocalAddr, "|") {
		go runTCPServer(ctx, addr, func(conn net.Conn) {
			accs.Accept(conn)
		})
	}

}
