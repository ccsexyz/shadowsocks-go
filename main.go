package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: myss configfile")
		return
	}
	configs, err := ss.ReadConfig(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, c := range configs {
		wg.Add(1)
		go func(c *ss.Config) {
			defer wg.Done()
			switch c.Type {
			default:
				log.Println("unsupported server type")
			case "local":
				log.Println("run client at", c.Localaddr, "with method", c.Method)
				RunTCPLocalServer(c)
			case "server":
				log.Println("run server at", c.Localaddr, "with method", c.Method)
				RunTCPRemoteServer(c)
			case "ssproxy":
				log.Println("run ss proxy at", c.Localaddr, "with method", c.Method)
				RunSSProxyServer(c)
			case "socksproxy":
				log.Println("run socks proxy at", c.Localaddr, "with method", c.Method)
				RunSocksProxyServer(c)
			}
		}(c)
	}
	wg.Wait()
}
