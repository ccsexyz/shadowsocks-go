package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/fsnotify/fsnotify"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: myss configfile")
		return
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	for {
		configs, err := ss.ReadConfig(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		die := make(chan bool)
		var wg sync.WaitGroup
		for _, c := range configs {
			wg.Add(1)
			go func(c *ss.Config) {
				defer wg.Done()
				c.Die = die
				switch c.Type {
				default:
					log.Println("unsupported server type")
				case "local":
					log.Println("run client at", c.Localaddr, "with method", c.Method)
					if c.UDPRelay {
						log.Println("run udp local server at", c.Localaddr, "with method", c.Method)
						go RunUDPLocalServer(c)
					}
					RunTCPLocalServer(c)
				case "redir":
					log.Println("run redir at", c.Localaddr, "with method", c.Method)
					RunTCPRedirServer(c)
				case "server":
					log.Println("run server at", c.Localaddr, "with method", c.Method)
					if c.UDPRelay {
						log.Println("run udp remote server at", c.Localaddr, "with method", c.Method)
						go RunUDPRemoteServer(c)
					}
					RunTCPRemoteServer(c)
				case "multiserver":
					log.Println("run multi server at", c.Localaddr)
					if c.UDPRelay {
						log.Println("run multi udp remote server at", c.Localaddr)
						go RunMultiUDPRemoteServer(c)
					}
					RunMultiTCPRemoteServer(c)
				case "ssproxy":
					log.Println("run ss proxy at", c.Localaddr, "with method", c.Method)
					RunSSProxyServer(c)
				case "socksproxy":
					log.Println("run socks proxy at", c.Localaddr, "with method", c.Method)
					RunSocksProxyServer(c)
				case "tcptun":
					if len(c.Localaddr) == 0 || c.Backend == nil || len(c.Backend.Remoteaddr) == 0 {
						break
					}
					log.Println("run tcp tunnel at", c.Localaddr, "to", c.Remoteaddr)
					RunTCPTunServer(c)
				case "udptun":
					if len(c.Localaddr) == 0 || c.Backend == nil || len(c.Backend.Remoteaddr) == 0 {
						break
					}
					log.Println("run udp tunnel at", c.Localaddr, "to", c.Remoteaddr)
					RunUDPTunServer(c)
				}
			}(c)
		}
		go func() {
			err = watcher.Add(os.Args[1])
			if err != nil {
				return
			}
			defer watcher.Remove(os.Args[1])
			for {
				select {
				case event := <-watcher.Events:
					if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Rename == fsnotify.Rename {
						close(die)
						return
					} else if event.Op&fsnotify.Remove == fsnotify.Remove {
						return
					}
				case <-watcher.Errors:
					close(die)
					return
				case <-die:
					return
				}
			}
		}()
		wg.Wait()
		select {
		case <-die:
		default:
			return
		}
	}
}
