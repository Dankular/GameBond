//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"gamebond.local/nativeedge/edge"
)

func run() error {
	configPath := flag.String("config", "/run/config/server.json", "validated server config")
	keyPath := flag.String("key", "/run/secrets/gamebond.key", "read-only key file")
	flag.Parse()
	if os.Getenv("GAMEBOND_NATIVE_EDGE") != "1" {
		return fmt.Errorf("native edge requires explicit GAMEBOND_NATIVE_EDGE=1 in its container")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	if info.Size() > 1024*1024 {
		file.Close()
		return fmt.Errorf("server config exceeds size limit")
	}
	file.Close()
	data, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	c, options, address, session, err := edge.DecodeConfig(data)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	if len(key) != 32 {
		return fmt.Errorf("key file must contain exactly 32 bytes")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return edge.Run(ctx, c, options, address, session, key, os.Stdout)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
