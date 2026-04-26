package main

import (
	"flag"
	"log"
	"os"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/domain"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	"github.com/ccsexyz/shadowsocks-go/server"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/fsnotify/fsnotify"
)

func main() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.Ltime | log.Lmicroseconds)

	var c ss.Config
	var target string
	var configfile string
	var pprofaddr string

	flag.StringVar(&c.NetworkConfig.Type, "type", "", "server type(eg: server, local)")
	flag.StringVar(&c.NetworkConfig.Remoteaddr, "s", "", "remote server address")
	flag.StringVar(&c.NetworkConfig.Localaddr, "l", "", "local listen address")
	flag.StringVar(&target, "t", "", "target address(for tcptun and udptun)")
	flag.StringVar(&configfile, "c", "", "the configuration file path")
	flag.StringVar(&c.AdminAddr, "admin", "", "admin webui listen address (e.g. 127.0.0.1:8090)")
	flag.StringVar(&c.CryptoConfig.Method, "m", "aes-128-gcm", "crypt method")
	flag.StringVar(&c.CryptoConfig.Password, "p", "you need a password", "password")
	flag.BoolVar(&c.CryptoConfig.Nonop, "nonop", false, "enable this to be compatiable with official ss servers(client only)")
	flag.BoolVar(&c.UDPRelay, "udprelay", false, "relay udp packets")
	flag.StringVar(&c.Nickname, "name", "", "nickname for logging")
	flag.BoolVar(&c.ObfsConfig.Obfs, "obfs", false, "enable obfs mode")
	flag.StringVar(&c.LogFile, "log", "", "set the path of logfile")
	flag.BoolVar(&c.Verbose, "verbose", false, "show verbose log")
	flag.BoolVar(&c.Debug, "debug", false, "show debug log")
	flag.StringVar(&pprofaddr, "pprof", "", "the pprof listen address")
	flag.IntVar(&c.NetworkConfig.Timeout, "timeout", 0, "set the timeout of tcp connection")
	flag.BoolVar(&c.CryptoConfig.Safe, "safe", false, "runs under safe mode, server won't validate iv if safe is enabled")
	flag.BoolVar(&c.ProxyConfig.MITM, "mitm", false, "enable MITM-based http/https proxy")
	flag.IntVar(&c.DataShard, "ds", 0, "set datashard - fec")
	flag.IntVar(&c.ParityShard, "ps", 0, "set parityshard - fec")
	flag.StringVar(&c.ObfsConfig.ObfsMethod, "om", "", "set the method for obfs(http/websocket/tls)")
	flag.BoolVar(&c.SSProxy, "ssproxy", false, "enable ss proxy for local server")
	flag.BoolVar(&c.HttpConfig.AllowHTTP, "allow_http", false, "allow http wstunel connection")
	flag.BoolVar(&c.HttpConfig.SecureOrigin, "secure_origin", false, "enable WebSocket origin validation")
	flag.Int64Var(&domain.IvExpireSecond, "iv_expire_second", 30, "specifies the expiration time for IVs in the checker, in seconds")
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
			c.Backend = &ss.Config{CryptoConfig: ss.CryptoConfig{Method: c.CryptoConfig.Method, Password: c.CryptoConfig.Password}, NetworkConfig: ss.NetworkConfig{Remoteaddr: c.NetworkConfig.Remoteaddr}}
			c.Remoteaddr = target
		}
		ss.CheckConfig(&c)
		if c.AdminAddr != "" {
			ss.StartAdminServer(c.AdminAddr)
		}
		ss.SetAdminConfigs([]*ss.Config{&c})
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
	if c.AdminAddr == "" {
		for _, cfg := range configs {
			if cfg.AdminAddr != "" {
				c.AdminAddr = cfg.AdminAddr
				break
			}
		}
	}
	if c.AdminAddr != "" {
		ss.StartAdminServer(c.AdminAddr)
	}
	ss.SetAdminConfigs(configs)
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
						ss.SetAdminConfigs(configs)
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

func runServer(c *ss.Config) {
	switch c.Type {
	default:
		log.Println("unsupported server type:", c.Type)
	case "local":
		c.Log("run client at", c.Localaddr, "with method", c.Method)
		if c.UDPRelay {
			c.Log("run udp local server at", c.Localaddr, "with method", c.Method)
			go server.RunUDPLocalServer(c)
		}
		server.RunTCPLocalServer(c)
	case "redir":
		c.Log("run redir at", c.Localaddr)
		if c.UDPRelay {
			c.Log("run udp redir server at", c.Localaddr)
			go server.RunUDPRedirServer(c)
		}
		server.RunTCPRedirServer(c)
	case "server":
		c.Log("run server at", c.Localaddr, "with method", c.Method)
		if c.UDPRelay {
			c.Log("run udp remote server at", c.Localaddr, "with method", c.Method)
			go server.RunUDPRemoteServer(c)
		}
		server.RunTCPRemoteServer(c)
	case "multiserver":
		c.Log("run multi server at", c.Localaddr)
		if c.UDPRelay {
			c.Log("run multi udp remote server at", c.Localaddr)
			go server.RunMultiUDPRemoteServer(c)
		}
		server.RunMultiTCPRemoteServer(c)
	case "ssproxy":
		if c.UDPRelay {
			c.Log("run udp remote proxy server at", c.Localaddr)
			go server.RunUDPRemoteServer(c)
		}
		c.Log("run ss proxy at", c.Localaddr, "with method", c.Method)
		server.RunSSProxyServer(c)
	case "socksproxy":
		if c.UDPRelay {
			c.Log("run udp local proxy server at", c.Localaddr, "with method", c.Method)
			go server.RunUDPLocalServer(c)
		}
		c.Log("run socks proxy at", c.Localaddr, "with method", c.Method)
		server.RunSocksProxyServer(c)
	case "tcptun":
		if len(c.Localaddr) == 0 || c.Backend == nil || len(c.Backend.Remoteaddr) == 0 {
			break
		}
		c.Log("run tcp tunnel at", c.Localaddr, "to", c.Remoteaddr)
		server.RunTCPTunServer(c)
	case "udptun":
		if len(c.Localaddr) == 0 || c.Backend == nil || (len(c.Backend.Remoteaddr) == 0 && len(c.Backend.FakeTCPAddr) == 0) {
			break
		}
		c.Log("run udp tunnel at", c.Localaddr, "to", c.Remoteaddr)
		server.RunUDPTunServer(c)
	case "wstunnel":
		c.Log("run wstunnel server at", c.Localaddr, "with method", c.Method)
		server.RunWstunnelRemoteServer(c)
	}
}
