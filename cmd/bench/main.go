// Command bench runs matrix benchmarks, compares results, and generates load.
//
// Subcommands:
//
//	bench run     <binary> <config.json> [-o results.json]
//	bench quick   <binary> <method> <password> [-latency]
//	bench compare <file.json> ... [--html] [-o report.html]
//	bench load    [flags]  (payload generator)
package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "bench",
		Usage: "matrix benchmark and comparison tool for shadowsocks-go",
		Commands: []*cli.Command{
			runCommand,
			quickCommand,
			compareCommand,
			loadCommand,
			udpLoadCommand,
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
