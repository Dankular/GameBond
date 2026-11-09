package capture

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The test binary doubles as a fake ProxiFyre: staged as ProxiFyre.exe and
// started with FAKE_PROXIFYRE set. Nothing here touches the real ProxiFyre.
func TestMain(m *testing.M) {
	switch os.Getenv("FAKE_PROXIFYRE") {
	case "":
		os.Exit(m.Run())
	case "ready":
		os.MkdirAll("logs", 0o755)
		os.WriteFile(filepath.Join("logs", "logfile.txt"), []byte("ProxiFyre Service is running\n"), 0o600)
		time.Sleep(30 * time.Second)
	case "exit":
		os.Exit(3)
	case "hang":
		time.Sleep(30 * time.Second)
	}
}

func fixture(t *testing.T, mode string) StageOptions {
	self, _ := os.Executable()
	root := t.TempDir()
	source := filepath.Join(root, "install")
	os.MkdirAll(source, 0o755)
	for _, n := range proxifyreFiles {
		data, _ := os.ReadFile(self)
		if n != "ProxiFyre.exe" {
			data = []byte("stub " + n)
		}
		os.WriteFile(filepath.Join(source, n), data, 0o755)
	}
	os.WriteFile(filepath.Join(root, "stack.exe"), []byte("stack"), 0o755)
	t.Setenv("FAKE_PROXIFYRE", mode)
	return StageOptions{Source: source, Directory: filepath.Join(root, ".runtime", "userspace-proxy"), Root: root,
		Stack: filepath.Join(root, "stack.exe"), Address: "127.0.0.1:1080", Mode: "selected",
		Apps: []any{`C:\Games\cod.exe`}, Carriers: []string{`C:\me.exe`}, ReadyTimeout: 3 * time.Second}
}

func TestStartWaitsForReadyAndWritesConfig(t *testing.T) {
	o := fixture(t, "ready")
	ext := filepath.Join(o.Root, "ext.dll")
	os.WriteFile(ext, []byte("ext"), 0o600)
	o.Extension, o.Token = ext, "tok"
	var assigned bool
	o.AssignToJob = func(p *os.Process) error { assigned = p != nil; return nil }
	p, err := Start(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if !assigned {
		t.Error("child not assigned to the job")
	}
	var cfg Configuration
	raw, _ := os.ReadFile(filepath.Join(o.Directory, "app-config.json"))
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	px := cfg.Proxies[0]
	if px.Username != AttributionUser || px.Password != "tok" || px.AppNames[0] != `C:\Games\cod.exe` {
		t.Fatalf("%+v", px)
	}
	if b, _ := os.ReadFile(filepath.Join(o.Directory, "socksify.dll")); string(b) != "ext" {
		t.Error("extension not staged over the stock socksify.dll")
	}
	if b, _ := os.ReadFile(filepath.Join(o.Root, "build", "gamebond-internet-probe.exe")); string(b) != "stack" {
		t.Error("probe copy missing")
	}
}

func TestStartWithoutExtensionHasNoCredentials(t *testing.T) {
	o := fixture(t, "ready")
	cfg, err := WriteConfiguration(o)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxies[0].Username != "" || cfg.Proxies[0].Password != "" {
		t.Fatalf("%+v", cfg.Proxies[0])
	}
}

func TestStartFailures(t *testing.T) {
	o := fixture(t, "exit")
	if _, err := Start(context.Background(), o); err == nil || err.Error() != "ProxiFyre could not start; check .runtime/userspace-proxy/console.txt" {
		t.Fatalf("early exit: %v", err)
	}
	o = fixture(t, "hang")
	o.ReadyTimeout = 400 * time.Millisecond
	if _, err := Start(context.Background(), o); err == nil || err.Error() != "Application capture did not become ready" {
		t.Fatalf("timeout: %v", err)
	}
	o = fixture(t, "ready")
	o.Apps = []any{"bad"}
	if _, err := Start(context.Background(), o); err == nil {
		t.Fatal("bad app list started ProxiFyre")
	}
	if _, err := os.Stat(filepath.Join(o.Directory, "console.txt")); err == nil {
		t.Fatal("process was launched despite invalid configuration")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o = fixture(t, "hang")
	if _, err := Start(ctx, o); err == nil {
		t.Fatal("cancelled context started")
	}
}
