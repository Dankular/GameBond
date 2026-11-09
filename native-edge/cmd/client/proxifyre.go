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
	p := &proxifyre{enabled: f.enabled, log: log}
	if !f.enabled {
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
		CaptureMode string `json:"capture_mode"`
		Executables []any  `json:"cod_executables"`
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
		Carriers: []string{self}, HideWindow: hideWindow}
	return p, nil
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
	go func() {
		o := p.options
		o.Address = socks
		if job, err := procjob.New(); err == nil {
			p.mu.Lock()
			p.job = job
			p.mu.Unlock()
			o.AssignToJob = func(proc *os.Process) error { return job.Add(proc.Pid) }
		}
		proc, err := capture.Start(ctx, o)
		if err != nil {
			fail(fmt.Errorf("application capture: %w", err))
			return
		}
		p.mu.Lock()
		p.proc = proc
		p.mu.Unlock()
		fmt.Fprintln(p.log, "application capture running:", proc)
	}()
}

func (p *proxifyre) close() {
	p.mu.Lock()
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
