package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/capture"
	"gamebond.local/nativeedge/procjob"
)

// proxifyre is the opt-in application-capture half of userspace.Runtime: it
// verifies the owner-attribution extension, gives the netstack the capture
// token, and once the netstack reports its SOCKS endpoint stages and starts
// ProxiFyre pointed at it. Off unless -proxifyre is given; starting it
// diverts application traffic with WinDivert, so it is never implicit.
type proxifyre struct {
	enabled   bool
	extension string // verified socksify.dll, "" when absent
	token     string
	options   capture.StageOptions
	log       io.Writer

	mu      sync.Mutex
	started bool
	closed  bool
	settled chan struct{} // closed once ProxiFyre has opened the packet driver (or will not run)
	once    sync.Once
	proc    *capture.Process
	job     *procjob.Job
}

type proxifyreFlags struct {
	enabled      bool
	root         string
	runtimeDir   string
	extensionDir string
	source       string
}

func newProxifyre(f proxifyreFlags, stack string, rawConfig []byte, log io.Writer) (*proxifyre, error) {
	p := &proxifyre{enabled: f.enabled, log: log, settled: make(chan struct{})}
	if !f.enabled {
		p.settle()
		return p, nil
	}
	// ProxiFyre is started with its own working directory, so every path must be absolute.
	for _, v := range []*string{&f.root, &f.runtimeDir, &f.extensionDir, &f.source, &stack} {
		if abs, err := filepath.Abs(*v); err == nil {
			*v = abs
		}
	}
	ext, err := capture.VerifyExtension(f.extensionDir)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		CaptureMode string   `json:"capture_mode"`
		Exclude     []string `json:"capture_exclude"`
		Executables []any    `json:"cod_executables"`
	}
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, err
	}
	self, _ := os.Executable()
	if ext != "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		p.extension, p.token = ext, hex.EncodeToString(buf)
	}
	p.options = capture.StageOptions{Source: f.source, Directory: f.runtimeDir, Root: f.root, Stack: stack,
		Extension: p.extension, Token: p.token, Mode: cfg.CaptureMode, Apps: cfg.Executables,
		Carriers: []string{self}, HideWindow: hideWindow, Exclude: cfg.Exclude}
	return p, nil
}

func (p *proxifyre) settle() { p.once.Do(func() { close(p.settled) }) }

// waitSettled blocks until ProxiFyre has had time to attach to the Windows
// Packet Filter driver. With several handles on one adapter the newest
// receives the frames, so a LAN-device gateway must open its adapter after
// ProxiFyre or it never sees a frame. It returns early when ctx ends.
func (p *proxifyre) waitSettled(ctx context.Context) {
	select {
	case <-p.settled:
	case <-ctx.Done():
	}
}

// attribution reports whether owner attribution is available.
func (p *proxifyre) attribution() bool { return p.extension != "" }

// environment is the netstack environment: the capture token and
// authorization switch only when the extension is verified, and stale values
// are always removed first.
func (p *proxifyre) environment(base []string) []string {
	var out []string
	for _, kv := range base {
		k := strings.ToUpper(strings.SplitN(kv, "=", 2)[0])
		if k == "GAMEBOND_CAPTURE_TOKEN" || k == "GAMEBOND_APP_AUTHORIZATION" {
			continue
		}
		out = append(out, kv)
	}
	if p.attribution() {
		out = append(out, "GAMEBOND_CAPTURE_TOKEN="+p.token, "GAMEBOND_APP_AUTHORIZATION=1")
	}
	return out
}

// onStackReady starts ProxiFyre once, when the netstack reports its endpoint.
func (p *proxifyre) onStackReady(ctx context.Context, socks string, fail func(error)) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.mu.Unlock()
	go p.supervise(ctx, socks, fail)
}

// supervise keeps exactly one ProxiFyre alive. A copy left over from an
// earlier run is ended first (two would both divert traffic), and if our own
// copy exits it is restarted: otherwise apps captured into the tunnel keep
// their tunnel-side connections while new ones leave directly from another
// source address and get reset.
func (p *proxifyre) supervise(ctx context.Context, socks string, fail func(error)) {
	o := p.options
	o.Address = socks
	if job, err := procjob.New(); err == nil {
		p.mu.Lock()
		p.job = job
		p.mu.Unlock()
		o.AssignToJob = func(proc *os.Process) error { return job.Add(proc.Pid) }
	}
	first, failures, backoff := true, 0, 2*time.Second
	for ctx.Err() == nil && !p.isClosed() {
		if n := capture.KillStale(o.Directory); n > 0 {
			fmt.Fprintf(p.log, "ended %d stale ProxiFyre process(es)\n", n)
		}
		proc, err := capture.Start(ctx, o)
		if err == nil {
			select { // ProxiFyre opens the driver shortly after its process starts
			case <-time.After(4 * time.Second):
			case <-ctx.Done():
			}
		}
		if first {
			p.settle()
			first = false
			if err != nil {
				fail(fmt.Errorf("application capture: %w", err))
				return
			}
		}
		if err != nil {
			failures++
			fmt.Fprintln(p.log, "application capture restart failed:", err)
			reportHealth("cap:proxifyre", false, "start_failed")
			if failures >= 5 {
				fail(fmt.Errorf("application capture: %w", err))
				return
			}
		} else {
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				proc.Stop()
				return
			}
			p.proc = proc
			p.mu.Unlock()
			fmt.Fprintln(p.log, "application capture running:", proc)
			reportHealth("cap:proxifyre", true, "")
			started := time.Now()
			select {
			case <-proc.Done():
			case <-ctx.Done():
				return
			}
			if p.isClosed() {
				return
			}
			reportHealth("cap:proxifyre", false, "exited")
			fmt.Fprintf(p.log, "application capture: ProxiFyre exited after %s (%v); restarting\n", time.Since(started).Round(time.Second), proc.ExitError())
			proc.Stop()
			if time.Since(started) > time.Minute {
				failures, backoff = 0, 2*time.Second
			}
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (p *proxifyre) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func (p *proxifyre) close() {
	p.mu.Lock()
	p.closed = true
	proc, job := p.proc, p.job
	p.mu.Unlock()
	proc.Stop()
	if job != nil {
		job.Close()
	}
}

func defaultProxifyreDirs(root string) (runtime, extension string) {
	return filepath.Join(root, ".runtime", "userspace-proxy"), filepath.Join(root, "build", "native-capture")
}
