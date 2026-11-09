package desktopruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gamebond.local/nativeedge/launcher"
	"gamebond.local/nativeedge/ttyrelay"
)

func testPlan(t *testing.T) Plan {
	t.Helper()
	root := t.TempDir()
	p := Plan{Root: root, Client: filepath.Join(root, "client.exe"), Config: filepath.Join(root, "client.json"), Key: filepath.Join(root, "key"), Netstack: filepath.Join(root, "stack.exe"), Metadata: filepath.Join(root, "relay.json"), Status: filepath.Join(root, "status.json"), Usage: filepath.Join(root, "usage.json")}
	for _, path := range []string{p.Client, p.Netstack} {
		if err := os.WriteFile(path, []byte("test fixture; not executable"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p.Key, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := `{"role":"client","bind":[["192.168.1.93",0]],"interface_indices":[22],"peer":["203.0.113.7",4433],"session":"00112233445566778899aabbccddeeff","client_tunnel_ip":"10.77.0.2","redundant_mode":false,"bonding_mode":true}`
	if err := os.WriteFile(p.Config, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fakeSupervisor(t *testing.T, p Plan, runs *atomic.Int32) int {
	t.Helper()
	r, err := ttyrelay.Start(ttyrelay.Options{Metadata: p.Metadata, ConfigPath: p.Config})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	owner := launcher.NewOwner()
	registered := make(chan struct{})
	go ttyrelay.ServeSupervisor(ctx, p.Metadata, owner, func() { close(registered) })
	go launcher.Supervise(ctx, owner, func(ctx context.Context, ready func()) error { runs.Add(1); ready(); <-ctx.Done(); return nil }, launcher.Options{InitiallyStopped: true, Poll: time.Millisecond})
	t.Cleanup(func() { cancel(); owner.Close(); r.Close() })
	select {
	case <-registered:
	case <-time.After(time.Second):
		t.Fatal("supervisor never registered")
	}
	return os.Getpid()
}

func TestPassiveStatusAndStopNeverSpawn(t *testing.T) {
	p := testPlan(t)
	spawned := false
	m := Manager{Plan: p, Spawn: func(Plan) (int, error) { spawned = true; return 0, errors.New("unexpected spawn") }}
	if v, err := m.Status(); err != nil || v["state"] != "stopped" {
		t.Fatal(v, err)
	}
	if v, err := m.Control("stop"); err != nil || v["state"] != "stopped" {
		t.Fatal(v, err)
	}
	if spawned {
		t.Fatal("passive operation spawned a process")
	}
}

func TestEnsureIsStoppedAndConnectReusesSupervisor(t *testing.T) {
	p := testPlan(t)
	var runs, spawns atomic.Int32
	m := Manager{Plan: p, Spawn: func(plan Plan) (int, error) {
		spawns.Add(1)
		if !strings.Contains(strings.Join(plan.Args(), " "), "-stopped") {
			t.Fatal("bootstrap can start traffic")
		}
		return fakeSupervisor(t, plan, &runs), nil
	}}
	if v, err := m.Ensure(); err != nil || v["state"] != "stopped" {
		t.Fatal(v, err)
	}
	if runs.Load() != 0 {
		t.Fatal("ensure started a VPN session")
	}
	for i := 0; i < 2; i++ {
		if v, err := m.Control("restart"); err != nil || v["state"] != "running" {
			t.Fatal(v, err)
		}
	}
	if spawns.Load() != 1 || runs.Load() != 2 {
		t.Fatal(spawns.Load(), runs.Load())
	}
	if v, err := m.Control("stop"); err != nil || v["state"] != "stopped" {
		t.Fatal(v, err)
	}
}

func TestRefuseMismatchedConfigOrLiveOwnerlessRelay(t *testing.T) {
	p := testPlan(t)
	var runs atomic.Int32
	fakeSupervisor(t, p, &runs)
	p.Config = filepath.Join(p.Root, "other.json")
	m := Manager{Plan: p}
	if _, err := m.Control("restart"); err == nil || !strings.Contains(err.Error(), "different client config") {
		t.Fatal(err)
	}
	p2 := testPlan(t)
	relay, err := ttyrelay.Start(ttyrelay.Options{Metadata: p2.Metadata})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	m = Manager{Plan: p2, Spawn: func(Plan) (int, error) { t.Fatal("replaced live relay"); return 0, nil }}
	if _, err := m.Control("restart"); err == nil {
		t.Fatal("ownerless relay was replaced")
	}
}

func TestProfilePersistsOnlyPathsAndValidatesBeforeSpawn(t *testing.T) {
	p := testPlan(t)
	profile := Profile{Version: 1, Config: p.Config, Key: p.Key, Netstack: p.Netstack, Proxifyre: true}
	if err := profile.Write(p.Root); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p.Root, ProfilePath, "", "relay.json", "status.json")
	if err != nil {
		t.Fatal(err)
	}
	if got.Config != p.Config || !got.Proxifyre {
		t.Fatal(got)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Key, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	m := Manager{Plan: p, Spawn: func(Plan) (int, error) { t.Fatal("invalid key was launched"); return 0, nil }}
	if _, err := m.Control("restart"); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestUnreachableKnownProcessIsNotReportedStopped(t *testing.T) {
	p := testPlan(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p.Client = exe
	relay, err := ttyrelay.Start(ttyrelay.Options{Metadata: p.Metadata, ConfigPath: p.Config})
	if err != nil {
		t.Fatal(err)
	}
	record, err := ttyrelay.ReadMetadata(p.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	relay.Close()
	raw, _ := json.Marshal(record)
	if err := os.WriteFile(p.Metadata, raw, 0600); err != nil {
		t.Fatal(err)
	}
	m := Manager{Plan: p, Spawn: func(Plan) (int, error) { t.Fatal("duplicate process was started"); return 0, nil }}
	if _, err := m.Status(); err == nil {
		t.Fatal("unreachable live process reported stopped")
	}
	for _, command := range []string{"stop", "restart"} {
		if _, err := m.Control(command); err == nil {
			t.Fatal("unconfirmed control reported success", command)
		}
	}
	// Losing metadata must not hide a fresh running metrics document either.
	if err := os.Remove(p.Metadata); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(map[string]any{"pid": os.Getpid(), "state": "running", "updated_at": float64(time.Now().UnixNano()) / 1e9})
	if err := os.WriteFile(p.Status, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Status(); err == nil {
		t.Fatal("fresh live process hidden by absent metadata")
	}
}

func TestStaleMetadataPIDBelongingToAnotherExecutableDoesNotBlockStartup(t *testing.T) {
	p := testPlan(t)
	r, err := ttyrelay.Start(ttyrelay.Options{Metadata: p.Metadata})
	if err != nil {
		t.Fatal(err)
	}
	record, err := ttyrelay.ReadMetadata(p.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	raw, _ := json.Marshal(record)
	if err := os.WriteFile(p.Metadata, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// record.PID is this test process, not the configured client executable.
	m := Manager{Plan: p}
	if got, err := m.Status(); err != nil || got["state"] != "stopped" {
		t.Fatal(got, err)
	}
}

func TestFailedStartupIsReturnedAsAnError(t *testing.T) {
	p := testPlan(t)
	m := Manager{Plan: p, Spawn: func(plan Plan) (int, error) {
		r, err := ttyrelay.Start(ttyrelay.Options{Metadata: plan.Metadata, ConfigPath: plan.Config})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		owner := launcher.NewOwner()
		registered := make(chan struct{})
		go ttyrelay.ServeSupervisor(ctx, plan.Metadata, owner, func() { close(registered) })
		go launcher.Supervise(ctx, owner, func(context.Context, func()) error { return errors.New("fixture startup failed") }, launcher.Options{InitiallyStopped: true, Poll: time.Millisecond})
		t.Cleanup(func() { cancel(); owner.Close(); r.Close() })
		select {
		case <-registered:
		case <-time.After(time.Second):
			t.Fatal("owner not registered")
		}
		return os.Getpid(), nil
	}}
	result, err := m.Control("restart")
	if err == nil || !strings.Contains(err.Error(), "fixture startup failed") || result["state"] != "failed" {
		t.Fatal(result, err)
	}
}
