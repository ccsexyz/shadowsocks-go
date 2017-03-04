package main

import (
	"fmt"
	"log"
	"os"
	"sync"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: myss configfile")
		return
	}
	configs, err := readConfig(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, c := range configs {
		wg.Add(1)
		log.Println("run server at ", c.Server, " method ", c.Method)
		go func() {
			defer wg.Done()
			RunTCPRemoteServer(c.Server, &ssinfo{method: c.Method, password: c.Password})
		}()
	}
	wg.Wait()
}
