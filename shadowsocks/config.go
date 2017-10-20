package ss

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ccsexyz/utils"
)

type Config struct {
	Nickname       string    `json:"nickname"`
	Type           string    `json:"type"`
	Localaddr      string    `json:"localaddr"`
	Localaddrs     []string  `json:"localaddrs"`
	Remoteaddr     string    `json:"remoteaddr"`
	Method         string    `json:"method"`
	Password       string    `json:"password"`
	Nonop          bool      `json:"nonop"`
	UDPRelay       bool      `json:"udprelay"`
	Backend        *Config   `json:"backend"`
	Backends       []*Config `json:"backends"`
	Verbose        bool      `json:"verbose"`
	Debug          bool      `json:"debug"`
	LogFile        string    `json:"logfile"`
	Obfs           bool      `json:"obfs"`
	ObfsHost       []string  `json:"obfshost"`
	ObfsAlive      bool      `json:"obfsalive"`
	Mux            bool      `json:"mux"`
	MuxLimit       int       `json:"muxlimit"`
	Limit          int       `json:"limit"`
	LimitPerConn   int       `json:"limitperconn"`
	LogHTTP        bool      `json:"loghttp"`
	PartEncHTTPS   bool      `json:"partenchttps"`
	PartEnc        bool      `json:"partenc"`
	Timeout        int       `json:"timeout"`
	Snappy         bool      `json:"snappy"`
	FilterCapacity int       `json:"filtcap"`
	AutoProxy      bool      `json:"autoproxy"`
	ProxyList      string    `json:"proxylist"`
	NotProxyList   string    `json:"notproxylist"`
	DumpList       bool      `json:"dumplist"`
	ChnList        string    `json:"chnlist"`
	RedisAddr      string    `json:"redisaddr"`
	RedisKey       string    `json:"rediskey"`
	UseMul         bool      `json:"usemul"`
	UseUDP         bool      `json:"useudp"`
	MulConn        int       `json:"mulconn"`
	FakeTCPAddr    string    `json:"faketcpaddr"`
	Safe           bool      `json:"safe"`
	MITM           bool      `json:"mitm"`
	limiters       []*Limiter
	Vlogger        *log.Logger
	Dlogger        *log.Logger
	Logger         *log.Logger
	logfile        *os.File
	Ivlen          int
	Any            interface{}
	Die            chan bool
	pool           *ConnPool
	muxDialer      *MuxDialer
	closers        []cb
	tcpFilterLock  sync.Mutex
	tcpFilterOnce  sync.Once
	tcpFilter      bytesFilter
	udpFilterOnce  sync.Once
	udpFilter      bytesFilter
	tcpIvChecker   ivChecker
	autoProxyCtx   *autoProxy
	chnListCtx     *chnRouteList
	redisFilter    bytesFilter
	crctbl         *crc32.Table
}

func ReadConfig(path string) (configs []*Config, err error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	err = json.Unmarshal(bytes, &configs)
	if err != nil {
		var c Config
		err = json.Unmarshal(bytes, &c)
		if err == nil {
			configs = append(configs, &c)
		}
	}
	for _, c := range configs {
		CheckConfig(c)
	}
	return
}

func (c *Config) Close() error {
	if len(c.LogFile) != 0 && c.logfile != os.Stderr && c.logfile != nil {
		c.logfile.Close()
	}
	for _, bkn := range c.Backends {
		if bkn.logfile != c.logfile && bkn.logfile != os.Stderr {
			bkn.logfile.Close()
		}
	}
	if c.pool != nil {
		c.pool.Close()
	}
	if c.redisFilter != nil {
		c.redisFilter.Close()
	}
	for _, f := range c.closers {
		f()
	}
	return nil
}

func initBloomFilter(c *Config, f *bytesFilter) {
	*f = newBloomFilter(c.FilterCapacity, defaultFilterFalseRate)
}

func (c *Config) redisFilterTestAndAdd(b []byte) bool {
	if c.Ivlen == 0 || c.redisFilter == nil {
		return false
	}
	return c.redisFilter.TestAndAdd(b)
}

func (c *Config) udpFilterTestAndAdd(b []byte) bool {
	if c.Ivlen == 0 {
		return false
	}
	c.udpFilterOnce.Do(func() {
		initBloomFilter(c, &c.udpFilter)
	})
	ok1 := c.udpFilter.TestAndAdd(b)
	ok2 := c.redisFilterTestAndAdd(b)
	return ok1 || ok2
}

func (c *Config) tcpFilterTestAndAdd(b []byte) bool {
	if c.Ivlen == 0 {
		return false
	}
	c.tcpFilterOnce.Do(func() {
		initBloomFilter(c, &c.tcpFilter)
	})
	c.tcpFilterLock.Lock()
	ok1 := c.tcpFilter.TestAndAdd(b)
	c.tcpFilterLock.Unlock()
	ok2 := c.redisFilterTestAndAdd(b)
	return ok1 || ok2
}

func CheckLogFile(c *Config) {
	if len(c.LogFile) == 0 {
		c.logfile = os.Stderr
		return
	}
	f, err := os.OpenFile(c.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		c.logfile = os.Stderr
		log.Println(err)
	} else {
		c.logfile = f
	}
}

func CheckBasicConfig(c *Config) {
	if len(c.Password) == 0 {
		c.Password = defaultPassword
	}
	if len(c.Method) == 0 {
		c.Method = defaultMethod
	}
	if c.Ivlen == 0 {
		c.Ivlen = utils.GetIvLen(c.Method)
	}
	if len(c.Nickname) == 0 {
		if len(c.Localaddr) == 0 {
			c.Nickname = fmt.Sprintf("%v-%v-%v", c.Type, c.Method, c.Password)
		} else {
			c.Nickname = fmt.Sprintf("%v-%v", c.Type, c.Localaddr)
		}
	}
	c.Logger = log.New(c.logfile, fmt.Sprintf("[info] [%s] ", c.Nickname), log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	if c.Verbose {
		c.Vlogger = log.New(c.logfile, fmt.Sprintf("[verbose] [%s] ", c.Nickname), log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	if c.Debug {
		c.Dlogger = log.New(c.logfile, fmt.Sprintf("[debug] [%s] ", c.Nickname), log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	if c.Limit != 0 {
		c.limiters = append(c.limiters, NewLimiter(c.Limit))
	}
	if c.Type == "local" {
		if c.Mux {
			c.muxDialer = &MuxDialer{}
		}
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	if c.FilterCapacity == 0 {
		c.FilterCapacity = defaultFilterCapacity
	}
	c.crctbl = crc32.MakeTable(crc32.ChecksumIEEE(utils.StringToSlice(c.Password)))
}

func CheckConfig(c *Config) {
	if len(c.Localaddr) == 0 && len(c.Localaddrs) > 0 {
		c.Localaddr = c.Localaddrs[0]
		c.Localaddrs = c.Localaddrs[1:]
	}
	if len(c.Type) == 0 {
		if len(c.Localaddr) != 0 && len(c.Remoteaddr) != 0 {
			c.Type = "local"
		} else if len(c.Localaddr) != 0 {
			c.Type = "server"
		}
	}
	if c.Type == "socks" {
		c.Type = "socksproxy"
		c.Backend = nil
		c.Backends = nil
	}
	CheckLogFile(c)
	CheckBasicConfig(c)
	if c.pool == nil && c.Obfs && c.ObfsAlive && (c.Type == "server" || c.Type == "multiserver" || c.Type == "local") {
		c.pool = NewConnPool()
	}
	if c.Backend != nil {
		c.Backends = append(c.Backends, c.Backend)
	}
	if c.AutoProxy {
		c.autoProxyCtx = newAutoProxy()
		c.autoProxyCtx.loadByPassList(c.NotProxyList)
		c.autoProxyCtx.loadPorxyList(c.ProxyList)
		if c.DumpList {
			go c.proxyListDump()
		}
	}
	if len(c.ChnList) != 0 {
		c.chnListCtx = new(chnRouteList)
		err := c.chnListCtx.load(c.ChnList)
		if err != nil {
			log.Println(err)
			c.chnListCtx = nil
		}
	}
	for _, v := range c.Backends {
		if len(v.Type) == 0 {
			if len(v.Remoteaddr) != 0 {
				v.Type = "local"
			} else {
				v.Type = "server"
			}
		}
		if c.Obfs {
			v.Obfs = true
			if c.ObfsAlive {
				v.ObfsAlive = true
			}
			v.ObfsHost = append(v.ObfsHost, c.ObfsHost...)
		}
		if c.Debug {
			v.Debug = true
		}
		if c.Safe {
			v.Safe = true
		}
		if c.Verbose {
			v.Verbose = true
		}
		if c.LogHTTP {
			v.LogHTTP = true
		}
		if c.PartEncHTTPS {
			v.PartEncHTTPS = true
		}
		if v.Timeout == 0 {
			v.Timeout = c.Timeout
		}
		if c.autoProxyCtx != nil {
			v.autoProxyCtx = c.autoProxyCtx
		}
		if c.LogFile == v.LogFile {
			v.logfile = c.logfile
		} else {
			CheckLogFile(v)
			if v.logfile == os.Stderr && c.logfile != os.Stderr {
				v.logfile = c.logfile
			}
		}
		if v.Obfs && v.ObfsAlive {
			if v.Type != "server" {
				v.pool = NewConnPool()
			} else {
				v.pool = c.pool
			}
		}
		CheckBasicConfig(v)
		if c.LimitPerConn != 0 && v.LimitPerConn == 0 {
			v.LimitPerConn = c.LimitPerConn
		}
		if len(c.limiters) != 0 {
			v.limiters = append(v.limiters, c.limiters...)
		}
	}
	if len(c.RedisAddr) != 0 {
		c.redisFilter = newRedisFilter(c.RedisAddr, c.RedisKey, 0)
	}
}

func (c *Config) LogV(v ...interface{}) {
	if c.Vlogger != nil {
		c.Vlogger.Output(2, fmt.Sprintln(v...))
	}
}

func (c *Config) LogD(v ...interface{}) {
	if c.Dlogger != nil {
		c.Dlogger.Output(2, fmt.Sprintln(v...))
	}
}

func (c *Config) Log(v ...interface{}) {
	if c.Logger != nil {
		c.Logger.Output(2, fmt.Sprintln(v...))
	}
}

func (c *Config) CallOnClosed(f cb) {
	c.closers = append(c.closers, f)
}

func (c *Config) proxyListDump() {
	if c.NotProxyList == "" && c.ProxyList == "" {
		return
	}
	autoProxyCtx := c.autoProxyCtx
	if autoProxyCtx == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
			case <-c.Die:
				return
			}
			if len(c.NotProxyList) != 0 {
				hosts := autoProxyCtx.getByPassHosts()
				if len(hosts) != 0 {
					hoststr := strings.Join(hosts, "\n")
					err := ioutil.WriteFile(c.NotProxyList, utils.StringToSlice(hoststr), 0644)
					if err != nil {
						c.Log(err)
					}
				}
			}
			if len(c.ProxyList) != 0 {
				hosts := autoProxyCtx.getProxyHosts()
				if len(hosts) != 0 {
					hoststr := strings.Join(hosts, "\n")
					err := ioutil.WriteFile(c.ProxyList, utils.StringToSlice(hoststr), 0644)
					if err != nil {
						c.Log(err)
					}
				}
			}
		}
	}()
}
