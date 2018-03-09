package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strings"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func init() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
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
	addr := v.(ss.DstAddr)
	log.Println(addr.String())
	rconn, err := acc.dialer.Dial("tcp", addr.String())
	if err != nil {
		return nil, err
	}
	defer rconn.Close()
	log.Println("proxy", addr.String(), "to", rconn.RemoteAddr())
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

func runServer(ctx context.Context, config *Config) {
	config.print()
	bultin := newBultinServiceAcceptor()
	bultin.StoreServiceAcceptor(echoaddr, new(echoAcceptor))
	var pickOneAcceptors []Acceptor
	for _, in := range config.Input {
		switch in.Type {
		case "socks":
			pickOneAcceptors = append(pickOneAcceptors,
				ss.NewSocks5Acceptor())
		case "http":
			pickOneAcceptors = append(pickOneAcceptors,
				ss.NewHTTPProxyAcceptor())
		case "shadowsocks", "ss":
			pickOneAcceptors = append(pickOneAcceptors,
				ss.NewShadowSocksAcceptor(in.Method, in.Password))
		case "plain":
			if len(in.RemoteAddr) > 0 {
				pickOneAcceptors = append(pickOneAcceptors,
					newTunnelAcceptor(in.RemoteAddr))
			}
		}
	}
	var dialers []Dialer
	for _, out := range config.Output {
		switch out.Type {
		case "socks":
			// dialers = append(dialers, )
		case "http":
			//
		case "shadowsocks", "ss":
			dialers = append(dialers, ss.NewShadowSocksDialer(
				ss.NewNetDialer(), out.RemoteAddr, out.Method, out.Password))
		case "plain":
			dialers = append(dialers, ss.NewNetDialer())
		}
	}
	pickone := ss.NewPickOneAcceptor(pickOneAcceptors...)
	accs := ss.Acceptors([]ss.Acceptor{
		pickone, bultin, newLocalAcceptor(dialers...),
	})
	for _, addr := range strings.Split(config.LocalAddr, "|") {
		go runTCPServer(ctx, addr, func(conn net.Conn) {
			accs.Accept(conn)
		})
	}

}
