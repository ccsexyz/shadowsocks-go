package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

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

	configs, err := ss.ReadConfig(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	for {
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
					c.Log("run client at", c.Localaddr, "with method", c.Method)
					if c.UDPRelay {
						c.Log("run udp local server at", c.Localaddr, "with method", c.Method)
						go RunUDPLocalServer(c)
					}
					RunTCPLocalServer(c)
				case "redir":
					c.Log("run redir at", c.Localaddr, "with method", c.Method)
					RunTCPRedirServer(c)
				case "server":
					c.Log("run server at", c.Localaddr, "with method", c.Method)
					if c.UDPRelay {
						c.Log("run udp remote server at", c.Localaddr, "with method", c.Method)
						go RunUDPRemoteServer(c)
					}
					RunTCPRemoteServer(c)
				case "multiserver":
					c.Log("run multi server at", c.Localaddr)
					if c.UDPRelay {
						c.Log("run multi udp remote server at", c.Localaddr)
						go RunMultiUDPRemoteServer(c)
					}
					RunMultiTCPRemoteServer(c)
				case "ssproxy":
					c.Log("run ss proxy at", c.Localaddr, "with method", c.Method)
					RunSSProxyServer(c)
				case "socksproxy":
					c.Log("run socks proxy at", c.Localaddr, "with method", c.Method)
					RunSocksProxyServer(c)
				case "tcptun":
					if len(c.Localaddr) == 0 || c.Backend == nil || len(c.Backend.Remoteaddr) == 0 {
						break
					}
					c.Log("run tcp tunnel at", c.Localaddr, "to", c.Remoteaddr)
					RunTCPTunServer(c)
				case "udptun":
					if len(c.Localaddr) == 0 || c.Backend == nil || len(c.Backend.Remoteaddr) == 0 {
						break
					}
					c.Log("run udp tunnel at", c.Localaddr, "to", c.Remoteaddr)
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
						newConfigs, err := ss.ReadConfig(os.Args[1])
						if err != nil {
							continue
						}
						configs = newConfigs
						close(die)
						return
					} else if event.Op&fsnotify.Remove == fsnotify.Remove {
						return
					}
				case <-watcher.Errors:
					// close(die)
					// return
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
		time.Sleep(time.Second)
	}
}
