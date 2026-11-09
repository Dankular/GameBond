// desktopctl checks and controls the persistent desktop launch profile.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gamebond.local/nativeedge/desktopruntime"
)

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: desktopctl check|status|ensure|connect|stop [-root PATH]")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	root := fs.String("root", ".", "workspace root")
	profile := fs.String("profile", desktopruntime.ProfilePath, "desktop launch profile")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	plan, err := desktopruntime.Load(abs, *profile, "", ".runtime/go-relay.json", ".runtime/userspace-status.json")
	if err != nil {
		return err
	}
	m := &desktopruntime.Manager{Plan: plan}
	var result map[string]any
	switch os.Args[1] {
	case "check":
		err = plan.Validate()
		result = map[string]any{"ready": err == nil, "config": plan.Config, "proxifyre": plan.Proxifyre}
	case "status":
		result, err = m.Status()
	case "ensure":
		result, err = m.Ensure()
	case "connect":
		result, err = m.Control("restart")
	case "stop":
		result, err = m.Control("stop")
	default:
		return fmt.Errorf("unknown desktop command")
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
