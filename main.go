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
		if len(c.Client) == 0 {
			log.Println("run server at ", c.Server, " method ", c.Method)
			go func() {
				defer wg.Done()
				RunTCPRemoteServer(c)
			}()
		} else {
			log.Println("run client at ", c.Client, " method ", c.Method)
			go func() {
				defer wg.Done()
				RunTCPLocalServer(c)
			}()
		}
	}
	wg.Wait()
}
