// Command ttyrelay is gamebond.tty_server's CLI: serve, ensure, attach, stop,
// restart and status against the loopback log relay.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"time"

	"gamebond.local/nativeedge/ttyrelay"
)

func defaultMetadata() string {
	if v := os.Getenv("GAMEBOND_TTY_METADATA"); v != "" {
		return v
	}
	return filepath.Join(".runtime", "tty-relay.json")
}

func probe(path string) (ttyrelay.Record, error) {
	rec, err := ttyrelay.ReadMetadata(path)
	if err != nil {
		return rec, err
	}
	c, err := ttyrelay.Connect(rec, "attach", map[string]any{"tail": 0})
	if err != nil {
		return rec, err
	}
	c.Close()
	return rec, nil
}

func ensure(path string) (ttyrelay.Record, error) {
	if rec, err := probe(path); err == nil {
		return rec, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return ttyrelay.Record{}, err
	}
	abs, _ := filepath.Abs(path)
	cmd := exec.Command(exe, "serve", "--metadata", abs)
	if err := cmd.Start(); err != nil {
		return ttyrelay.Record{}, err
	}
	go cmd.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rec, err := probe(path); err == nil {
			return rec, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ttyrelay.Record{}, fmt.Errorf("read-only log relay did not become ready")
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: ttyrelay serve|ensure|attach|stop|restart|status [--metadata PATH]")
	}
	command := os.Args[1]
	if len(command) > 1 && command[0] == '-' {
		command = command[1:]
	}
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	metadata := fs.String("metadata", defaultMetadata(), "relay metadata file")
	tail := fs.Int("tail", 100, "lines of history (attach)")
	duration := fs.Float64("duration", 30, "seconds to follow (attach)")
	timeout := fs.Float64("timeout", 60, "seconds to wait (stop/restart/status)")
	fs.Parse(os.Args[2:])
	switch command {
	case "ensure":
		rec, err := ensure(*metadata)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"pid": rec.PID, "port": rec.Port, "metadata": *metadata})
	case "attach":
		return ttyrelay.Attach(*metadata, *tail, time.Duration(*duration*float64(time.Second)), os.Stdout)
	case "stop", "restart", "status":
		msg, err := ttyrelay.Control(*metadata, command, time.Duration(*timeout*float64(time.Second)), os.Stdout)
		if err != nil {
			return err
		}
		if msg["ok"] != true {
			os.Exit(1)
		}
		return nil
	case "serve":
		relay, err := ttyrelay.Start(ttyrelay.Options{Metadata: *metadata})
		if err != nil {
			return err
		}
		defer relay.Close()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		return nil
	}
	return fmt.Errorf("unknown command %q", command)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
