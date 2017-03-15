package shadowsocks

import (
	"encoding/json"
	"fmt"
	"io"
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
	Vlogger    *log.Logger
	Dlogger    *log.Logger
	Logger     *log.Logger
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
		CheckConfig(c)
	}
	return
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
	for _, v := range c.Backends {
		v.Type = c.Type
		CheckConfig(v)
	}
	var writer io.Writer
	if len(c.LogFile) == 0 {
		writer = os.Stderr
	} else {
		var err error
		writer, err = os.OpenFile(c.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Println(err)
			writer = os.Stderr
		}
	}
	c.Logger = log.New(writer, "[info] ", log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	if c.Verbose {
		c.Vlogger = log.New(writer, "[verbose] ", log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	if c.Debug {
		c.Dlogger = log.New(writer, "[debug] ", log.Lshortfile|log.Ldate|log.Ltime|log.Lmicroseconds)
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
