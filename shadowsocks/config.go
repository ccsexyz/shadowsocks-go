package shadowsocks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/ccsexyz/utils"
)

type Config struct {
	Nickname     string    `json:"nickname"`
	Type         string    `json:"type"`
	Localaddr    string    `json:"localaddr"`
	Remoteaddr   string    `json:"remoteaddr"`
	Method       string    `json:"method"`
	Password     string    `json:"password"`
	Nonop        bool      `json:"nonop"`
	UDPRelay     bool      `json:"udprelay"`
	UDPOverTCP   bool      `json:"udpovertcp"`
	Backend      *Config   `json:"backend"`
	Backends     []*Config `json:"backends"`
	Verbose      bool      `json:"verbose"`
	Debug        bool      `json:"debug"`
	LogFile      string    `json:"logfile"`
	Obfs         bool      `json:"obfs"`
	ObfsHost     []string  `json:"obfshost"`
	ObfsAlive    bool      `json:"obfsalive"`
	Delay        bool      `json:"delay"`
	Mux          bool      `json:"mux"`
	Smux         bool      `json:"smux"`
	SmuxConn     int       `json:"smuxconn"`
	Limit        int       `json:"limit"`
	LimitPerConn int       `json:"limitperconn"`
	LogHTTP 	 bool 	   `json:"loghttp"`
	limiters     []*Limiter
	Vlogger      *log.Logger
	Dlogger      *log.Logger
	Logger       *log.Logger
	logfile      *os.File
	Ivlen        int
	Any          interface{}
	Die          chan bool
	pool         *ConnPool
	muxDialer    *MuxDialer
	smuxDialer   *SmuxDialer
	closers      []cb
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
	for _, f := range c.closers {
		f()
	}
	return nil
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
		} else if c.Smux {
			c.smuxDialer = &SmuxDialer{}
			if c.SmuxConn <= 0 {
				c.SmuxConn = 16
			}
			c.CallOnClosed(func(){
				if c != nil && c.smuxDialer != nil && c.smuxDialer.client != nil {
					c.smuxDialer.client.MarkExpired()
				}
			})
		}
	}
}

func CheckConfig(c *Config) {
	if len(c.Type) == 0 {
		if len(c.Localaddr) != 0 && len(c.Remoteaddr) != 0 {
			c.Type = "local"
		} else if len(c.Localaddr) != 0 {
			c.Type = "server"
		}
	}
	CheckLogFile(c)
	CheckBasicConfig(c)
	if c.pool == nil && c.Obfs && c.ObfsAlive && (c.Type == "server" || c.Type == "multiserver" || c.Type == "local") {
		c.pool = NewConnPool()
	}
	if c.Backend != nil {
		c.Backends = append(c.Backends, c.Backend)
	}
	if c.UDPRelay && c.Type != "server" && c.Type != "local" && c.Type != "udptun" && c.Type != "multiserver" {
		c.UDPRelay = false
	}
	if c.UDPOverTCP && c.Type != "server" && c.Type != "local" && c.Type != "udptun" && c.Type != "multiserver" {
		c.UDPOverTCP = false
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
		if c.Verbose {
			v.Verbose = true
		}
		if c.Delay {
			v.Delay = true
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
