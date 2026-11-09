package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// proxifyreFiles is the set userspace.stage_proxy copies from the install.
var proxifyreFiles = []string{"ProxiFyre.exe", "ProxiFyre.exe.config", "ProxiFyre.Configuration.dll",
	"Newtonsoft.Json.dll", "NLog.dll", "NLog.config", "socksify.dll", "Topshelf.dll"}

// AttributionUser is the SOCKS username the owner-attribution extension
// recognises; the password is the per-run capture token.
const AttributionUser = "gamebond-attribution-v1"

// StageOptions describes one staging of ProxiFyre.
type StageOptions struct {
	Source       string // installed ProxiFyre directory (C:\Program Files\ProxiFyre)
	Directory    string // .runtime/userspace-proxy
	Root         string // project root (for build\gamebond-internet-probe.exe)
	Stack        string // the netstack executable
	Extension    string // verified socksify.dll, or ""
	Token        string // capture token, used only with Extension
	Address      string // SOCKS endpoint of the netstack
	Mode         string
	Apps         []any
	Carriers     []string
	ReadyTimeout time.Duration // default 8s
	AssignToJob  func(*os.Process) error
	HideWindow   func(*exec.Cmd)
	ProxyArgs    []string // default --allow-not-admin
	ReadyMarker  string   // default "ProxiFyre Service is running"
}

// Process is a started ProxiFyre child.
type Process struct {
	Cmd    *exec.Cmd
	output *os.File
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// WriteConfiguration stages the files and writes app-config.json, without
// starting anything.
func WriteConfiguration(o StageOptions) (*Configuration, error) {
	if err := os.MkdirAll(o.Directory, 0o755); err != nil {
		return nil, err
	}
	for _, name := range proxifyreFiles {
		if err := copyFile(filepath.Join(o.Source, name), filepath.Join(o.Directory, name)); err != nil {
			return nil, err
		}
	}
	if o.Extension != "" {
		if err := copyFile(o.Extension, filepath.Join(o.Directory, "socksify.dll")); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Join(o.Root, "build"), 0o755); err != nil {
		return nil, err
	}
	if err := copyFile(o.Stack, filepath.Join(o.Root, "build", "gamebond-internet-probe.exe")); err != nil {
		return nil, err
	}
	cfg, err := ProxyConfiguration(o.Mode, o.Apps, o.Address, o.Root, o.Carriers, o.Stack)
	if err != nil {
		return nil, err
	}
	if o.Extension != "" {
		for i := range cfg.Proxies {
			cfg.Proxies[i].Username, cfg.Proxies[i].Password = AttributionUser, o.Token
		}
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	target := filepath.Join(o.Directory, "app-config.json")
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return nil, err
	}
	return cfg, os.Rename(tmp, target)
}

// Start is userspace.stage_proxy: stage, launch ProxiFyre and wait for its
// log to say it is running. It starts a process that diverts application
// traffic (WinDivert); callers must only invoke it on explicit operator
// request.
func Start(ctx context.Context, o StageOptions) (*Process, error) {
	if _, err := WriteConfiguration(o); err != nil {
		return nil, err
	}
	logPath := filepath.Join(o.Directory, "logs", "logfile.txt")
	if _, err := os.Stat(logPath); err == nil {
		_ = os.WriteFile(logPath, nil, 0o600)
	}
	console, err := os.Create(filepath.Join(o.Directory, "console.txt"))
	if err != nil {
		return nil, err
	}
	args := o.ProxyArgs
	if args == nil {
		args = []string{"--allow-not-admin"}
	}
	cmd := exec.Command(filepath.Join(o.Directory, "ProxiFyre.exe"), args...)
	cmd.Dir = o.Directory
	cmd.Stdout, cmd.Stderr = console, console
	if o.HideWindow != nil {
		o.HideWindow(cmd)
	}
	if err := cmd.Start(); err != nil {
		console.Close()
		return nil, err
	}
	p := &Process{Cmd: cmd, output: console}
	if o.AssignToJob != nil {
		if err := o.AssignToJob(cmd.Process); err != nil {
			p.Stop()
			return nil, err
		}
	}
	timeout, marker := o.ReadyTimeout, o.ReadyMarker
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	if marker == "" {
		marker = "ProxiFyre Service is running"
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			p.Stop()
			return nil, ctx.Err()
		case <-exited:
			p.output.Close()
			return nil, errors.New("ProxiFyre could not start; check .runtime/userspace-proxy/console.txt")
		case <-deadline.C:
			p.Stop()
			return nil, errors.New("Application capture did not become ready")
		case <-tick.C:
			if raw, err := os.ReadFile(logPath); err == nil && strings.Contains(string(raw), marker) {
				return p, nil
			}
		}
	}
}

// Stop kills the child and closes its console file.
func (p *Process) Stop() {
	if p == nil {
		return
	}
	if p.Cmd != nil && p.Cmd.Process != nil {
		_ = p.Cmd.Process.Kill()
		_, _ = p.Cmd.Process.Wait()
	}
	if p.output != nil {
		p.output.Close()
	}
}

// String reports the child for diagnostics.
func (p *Process) String() string { return fmt.Sprintf("ProxiFyre pid %d", p.Cmd.Process.Pid) }
