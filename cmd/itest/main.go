// Command itest is an integration test toolkit for shadowsocks-go.
package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "itest",
		Usage: "integration test toolkit for shadowsocks-go",
		Commands: []*cli.Command{
			echoCommand,
			pktCommand,
			udpCommand,
			udpfwdCommand,
			h3Command,
			virtCommand,
			scenarioCommand,
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
