package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"reflect"
)

// Config config
type Config struct {
	Type       string    `json:"type"`
	LocalAddr  string    `json:"localaddr"`
	RemoteAddr string    `json:"remoteaddr"`
	Method     string    `json:"method"`
	Password   string    `json:"password"`
	SSProxy    bool      `json:"ssproxy"`
	Input      []*Config `json:"input"`
	Output     []*Config `json:"output"`
}

var (
	defaultConfig Config
	configPath    string
)

func init() {
	flag.StringVar(&configPath, "c", "", "json config file")
	flag.StringVar(&defaultConfig.Type, "t", "", "work mode")
	flag.StringVar(&defaultConfig.LocalAddr, "l", ":12345", "local listen address")
	flag.StringVar(&defaultConfig.RemoteAddr, "r", ":12346", "remote server address")
	flag.StringVar(&defaultConfig.Method, "m", "chacha20", "encrypt method")
	flag.StringVar(&defaultConfig.Password, "p", "secret", "pre-shared password")
	flag.BoolVar(&defaultConfig.SSProxy, "ssproxy", false, "enable shadowsocks proxy")
}

func readConfig(path string) (configs []*Config, err error) {
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
		checkConfig(c)
	}
	return
}

func checkConfig(c *Config) {
	if len(c.Type) == 0 {
		if len(c.LocalAddr) != 0 && len(c.RemoteAddr) != 0 {
			c.Type = "local"
		} else if len(c.LocalAddr) != 0 {
			c.Type = "server"
		}
	}
}

func (c *Config) print() {
	val := reflect.ValueOf(c)
	typ := reflect.Indirect(val).Type()
	nfield := typ.NumField()
	for i := 0; i < nfield; i++ {
		jv := typ.Field(i).Tag.Get("json")
		if len(jv) != 0 {
			log.Println(jv+":", val.Elem().Field(i))
		}
	}
	log.Println("")
}
