package main

import (
	"fmt"
	"os"

	"gamebond.local/benchmarking/cmd"
)

func main() {
	if err := cmd.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "benchmark:", err)
		os.Exit(2)
	}
}
