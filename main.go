package main

import (
	"flag"
	"log"
	"os"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/fsnotify/fsnotify"
)

func main() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)

	var c ss.Config
	var target string
	var configfile string
	var pprofaddr string

	flag.StringVar(&c.Type, "type", "", "server type(eg: server, local)")
	flag.StringVar(&c.Remoteaddr, "s", "", "remote server address")
	flag.StringVar(&c.Localaddr, "l", "", "local listen address")
	flag.StringVar(&target, "t", "", "target address(for tcptun and udptun)")
	flag.StringVar(&configfile, "c", "", "the configuration file path")
	flag.StringVar(&c.Method, "m", "aes-256-cfb", "crypt method")
	flag.StringVar(&c.Password, "p", "you need a password", "password")
	flag.BoolVar(&c.Nonop, "nonop", false, "enable this to be compatiable with official ss servers(client only)")
	flag.BoolVar(&c.UDPRelay, "udprelay", false, "relay udp packets")
	flag.BoolVar(&c.Mux, "mux", false, "use mux to reduce the number of connections")
	flag.StringVar(&c.Nickname, "name", "", "nickname for logging")
	flag.BoolVar(&c.Obfs, "obfs", false, "enable obfs mode")
	flag.StringVar(&c.LogFile, "log", "", "set the path of logfile")
	flag.BoolVar(&c.Verbose, "verbose", false, "show verbose log")
	flag.BoolVar(&c.Debug, "debug", false, "show debug log")
	flag.StringVar(&pprofaddr, "pprof", "", "the pprof listen address")
	flag.IntVar(&c.Timeout, "timeout", 0, "set the timeout of tcp connection")
	flag.BoolVar(&c.Safe, "safe", false, "runs under safe mode, server won't validate iv if safe is enabled")
	flag.BoolVar(&c.MITM, "mitm", false, "enable MITM-based http/https proxy")
	flag.IntVar(&c.DataShard, "ds", 0, "set datashard - fec")
	flag.IntVar(&c.ParityShard, "ps", 0, "set parityshard - fec")
	flag.StringVar(&c.ObfsMethod, "om", "", "set the method for obfs(http/websocket/tls)")
	flag.BoolVar(&c.SSProxy, "ssproxy", false, "enable ss proxy for local server")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		return
	}

	if len(os.Args) == 2 {
		configfile = os.Args[1]
	}

	if len(pprofaddr) != 0 {
		if utils.PprofEnabled() {
			log.Println("run pprof http server at", pprofaddr)
			go func() {
				utils.RunProfileHTTPServer(pprofaddr)
			}()
		} else {
			log.Println("set pprof but pprof isn't compiled")
		}
	}

	if len(configfile) == 0 {
		if len(target) != 0 {
			c.Backend = &ss.Config{Method: c.Method, Password: c.Password, Remoteaddr: c.Remoteaddr}
			c.Remoteaddr = target
		}
		ss.CheckConfig(&c)
		runServer(&c)
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	configs, err := ss.ReadConfig(configfile)
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
				runServer(c)
			}(c)
		}
		oldConfigs := configs
		go func() {
			<-die
			for _, c := range oldConfigs {
				c.Close()
			}
		}()
		go func() {
			err = watcher.Add(configfile)
			if err != nil {
				log.Println(err)
				return
			}
			defer watcher.Remove(configfile)
			for {
				select {
				case event := <-watcher.Events:
					if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Rename == fsnotify.Rename {
						newConfigs, err := ss.ReadConfig(configfile)
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
		for _, c := range configs {
			c.Close()
		}
	}
}

func runServer(c *ss.Config) {
	switch c.Type {
	default:
		log.Println("unsupported server type:", c.Type)
	case "local":
		c.Log("run client at", c.Localaddr, "with method", c.Method)
		if c.UDPRelay {
			c.Log("run udp local server at", c.Localaddr, "with method", c.Method)
			go RunUDPLocalServer(c)
		}
		RunTCPLocalServer(c)
	case "redir":
		c.Log("run redir at", c.Localaddr)
		if c.UDPRelay {
			c.Log("run udp redir server at", c.Localaddr)
			go RunUDPRedirServer(c)
		}
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
		if c.UDPRelay {
			c.Log("run udp remote proxy server at", c.Localaddr)
			go RunUDPRemoteServer(c)
		}
		c.Log("run ss proxy at", c.Localaddr, "with method", c.Method)
		RunSSProxyServer(c)
	case "socksproxy":
		if c.UDPRelay {
			c.Log("run udp local proxy server at", c.Localaddr, "with method", c.Method)
			go RunUDPLocalServer(c)
		}
		c.Log("run socks proxy at", c.Localaddr, "with method", c.Method)
		RunSocksProxyServer(c)
	case "tcptun":
		if len(c.Localaddr) == 0 || c.Backend == nil || len(c.Backend.Remoteaddr) == 0 {
			break
		}
		c.Log("run tcp tunnel at", c.Localaddr, "to", c.Remoteaddr)
		RunTCPTunServer(c)
	case "udptun":
		if len(c.Localaddr) == 0 || c.Backend == nil || (len(c.Backend.Remoteaddr) == 0 && len(c.Backend.FakeTCPAddr) == 0) {
			break
		}
		c.Log("run udp tunnel at", c.Localaddr, "to", c.Remoteaddr)
		RunUDPTunServer(c)
	}
}
