package shadowsocks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

type Config struct {
	Type       string    `json:"type"`
	Localaddr  string    `json:"localaddr"`
	Remoteaddr string    `json:"remoteaddr"`
	Method     string    `json:"method"`
	Password   string    `json:"password"`
	Nonop      bool      `json:"nonop"`
	UDPRelay   bool      `json:"udprelay"`
	UDPOverTCP bool      `json:"udpovertcp"`
	Backend    *Config   `json:"backend"`
	Backends   []*Config `json:"backends"`
	Verbose    bool      `json:"verbose"`
	Debug      bool      `json:"debug"`
	LogFile    string    `json:"logfile"`
	Obfs       bool      `json:"obfs"`
	ObfsHost   []string  `json:"obfshost"`
	Delay      bool      `json:"delay"`
	Vlogger    *log.Logger
	Dlogger    *log.Logger
	Logger     *log.Logger
	logfile    *os.File
	Ivlen      int
	Any        interface{}
	Die        chan bool
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
		CheckLogFile(c)
		CheckConfig(c)
	}
	return
}

func (c *Config) Close() error {
	if len(c.LogFile) != 0 && c.logfile != os.Stderr && c.logfile != nil {
		c.logfile.Close()
	}
	for _, bkn := range c.Backends {
		bkn.Close()
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

func CheckConfig(c *Config) {
	if len(c.Password) == 0 {
		c.Password = defaultPassword
	}
	if len(c.Method) == 0 {
		c.Method = defaultMethod
	}
	if c.Ivlen == 0 {
		c.Ivlen = GetIvLen(c.Method)
	}
	if c.Backend != nil {
		c.Backends = append(c.Backends, c.Backend)
	}
	if len(c.Type) == 0 {
		if len(c.Localaddr) != 0 && len(c.Remoteaddr) != 0 {
			c.Type = "local"
		} else if len(c.Localaddr) != 0 {
			c.Type = "server"
		}
	}
	if c.UDPRelay && c.Type != "server" && c.Type != "local" && c.Type != "udptun" && c.Type != "multiserver" {
		c.UDPRelay = false
	}
	if c.UDPOverTCP && c.Type != "server" && c.Type != "local" && c.Type != "udptun" && c.Type != "multiserver" {
		c.UDPOverTCP = false
	}
	c.Logger = log.New(c.logfile, "[info] ", log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	if c.Verbose {
		c.Vlogger = log.New(c.logfile, "[verbose] ", log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	if c.Debug {
		c.Dlogger = log.New(c.logfile, "[debug] ", log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	for _, v := range c.Backends {
		v.Type = c.Type
		if c.Obfs {
			v.Obfs = true
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
		CheckConfig(v)
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
