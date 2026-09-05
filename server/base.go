package server

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPServer(address string, c *ss.Config,
	handlers []ss.AcceptHandler,
	handler func(*ss.AcceptedConn)) {
	var addresses []string
	func() {
		addrsMap := make(map[string]bool)
		for _, addr := range c.RegisterLocalAddr(c.Localaddr) {
			if len(addr) > 0 {
				addrsMap[addr] = true
			}
		}
		for addr := range addrsMap {
			addresses = append(addresses, addr)
		}
	}()
	var wg sync.WaitGroup
	for _, address := range addresses {
		wg.Add(1)
		go func(address string) {
			defer wg.Done()
			lis, err := ss.Listen(address, c, handlers)
			if err != nil {
				c.InitRuntime().Logger.Fatal(err)
			}
			defer lis.Close()
			go func() {
				die := c.DieChan()
				<-die
				lis.Close()
			}()
			if !strings.HasPrefix(address, "@") {
				vl := ss.RegisterVirtualForce("@"+address, c.Nickname)
				vlis := ss.NewListener(vl, c, handlers)
				go func() {
					<-c.DieChan()
					vlis.Close()
				}()
				go func() {
					for {
						conn, err := vlis.Accept()
						if err != nil {
							return
						}
						ac, ok := conn.(*ss.AcceptedConn)
						if !ok {
							// Defensive: a non-AcceptedConn must not take
							// down the accept loop for every later conn.
							c.Log("virtual listener: unexpected conn type", fmt.Sprintf("%T", conn))
							conn.Close()
							continue
						}
						go handler(ac)
					}
				}()
			}
			for {
				conn, err := lis.Accept()
				if err != nil {
					return
				}
				ac, ok := conn.(*ss.AcceptedConn)
				if !ok {
					// Defensive: a non-AcceptedConn must not take down the
					// accept loop for every later conn.
					c.Log("listener: unexpected conn type", fmt.Sprintf("%T", conn))
					conn.Close()
					continue
				}
				go handler(ac)
			}
		}(address)
	}
	wg.Wait()
}

func getDefaultUDPServerCtx() *utils.UDPServerCtx {
	return &utils.UDPServerCtx{Mtu: 65536, Expires: 60}
}

func RunUDPServer(listener net.PacketConn, config *ss.Config, creator func(*ss.Config) func(*utils.SubConn) (utils.Conn, utils.Conn, error)) {
	go func() {
		die := config.DieChan()
		defer listener.Close()
		<-die
	}()
	getDefaultUDPServerCtx().RunUDPServer(listener, creator(config))
}
