package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxifyreOffByDefaultChangesNothing(t *testing.T) {
	p, err := newProxifyre(proxifyreFlags{}, "stack.exe", []byte(`{}`), io.Discard)
	if err != nil || p.enabled || p.attribution() {
		t.Fatalf("%v %+v", err, p)
	}
	in := []string{"A=1", "gamebond_capture_token=stale", "GAMEBOND_APP_AUTHORIZATION=1"}
	out := p.environment(in)
	if len(out) != 1 || out[0] != "A=1" {
		t.Fatalf("stale capture variables survived: %v", out)
	}
	p.onStackReady(nil, "127.0.0.1:1", func(error) { t.Fatal("started while disabled") }) // must not touch ctx
	p.close()
}

func TestProxifyreVerifiesExtensionAndSetsEnvironment(t *testing.T) {
	dir := t.TempDir()
	body := []byte("dll")
	os.WriteFile(filepath.Join(dir, "socksify.dll"), body, 0o600)
	sum := sha256.Sum256(body)
	raw, _ := json.Marshal(map[string]any{"schema": 1, "feature": "gamebond-owner-v1", "dll_sha256": hex.EncodeToString(sum[:])})
	os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600)
	cfg := []byte(`{"capture_mode":"selected","cod_executables":["C:\\g\\cod.exe"]}`)
	p, err := newProxifyre(proxifyreFlags{enabled: true, root: dir, runtimeDir: filepath.Join(dir, "rt"), extensionDir: dir, source: dir}, "stack.exe", cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !p.attribution() || len(p.token) != 64 || p.options.Mode != "selected" || len(p.options.Apps) != 1 {
		t.Fatalf("%+v", p)
	}
	env := strings.Join(p.environment([]string{"GAMEBOND_CAPTURE_TOKEN=old"}), "\n")
	if strings.Contains(env, "old") || !strings.Contains(env, "GAMEBOND_CAPTURE_TOKEN="+p.token) || !strings.Contains(env, "GAMEBOND_APP_AUTHORIZATION=1") {
		t.Fatal(env)
	}
	// tampered DLL: refuse to start at all
	os.WriteFile(filepath.Join(dir, "socksify.dll"), []byte("evil"), 0o600)
	if _, err := newProxifyre(proxifyreFlags{enabled: true, extensionDir: dir}, "s", cfg, io.Discard); err == nil {
		t.Fatal("tampered extension accepted")
	}
	// no extension installed: runs without attribution and without a token
	empty, err := newProxifyre(proxifyreFlags{enabled: true, extensionDir: t.TempDir()}, "s", cfg, io.Discard)
	if err != nil || empty.attribution() || len(empty.environment(nil)) != 0 {
		t.Fatalf("%v %+v", err, empty)
	}
}
