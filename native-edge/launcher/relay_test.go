package launcher

import (
	"bytes"
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"gamebond.local/nativeedge/ttyrelay"
)

func TestSupervisorOverRealRelay(t *testing.T) {
	meta := filepath.Join(t.TempDir(), "relay.json")
	relay, err := ttyrelay.Start(ttyrelay.Options{Metadata: meta})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	owner := NewOwner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registered := make(chan struct{})
	go ttyrelay.ServeSupervisor(ctx, meta, owner, func() { close(registered) })
	select {
	case <-registered:
	case <-time.After(3 * time.Second):
		t.Fatal("owner never registered")
	}
	var runs atomic.Int32
	done := make(chan int, 1)
	go func() {
		done <- Supervise(ctx, owner, func(c context.Context, ready func()) error {
			runs.Add(1)
			ready()
			<-c.Done()
			return nil
		}, Options{Poll: 5 * time.Millisecond})
	}()
	deadline := time.Now().Add(3 * time.Second)
	for relay.OwnerState() != "running" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if relay.OwnerState() != "running" {
		t.Fatalf("relay sees owner state %q", relay.OwnerState())
	}
	var out bytes.Buffer
	msg, err := ttyrelay.Control(meta, "restart", 5*time.Second, &out)
	if err != nil || msg["ok"] != true || msg["complete"] != true || msg["state"] != "running" {
		t.Fatalf("restart through the relay: %v %v %q", msg, err, out.String())
	}
	if runs.Load() != 2 {
		t.Fatalf("restart ran the tunnel %d times in total", runs.Load())
	}
	msg, err = ttyrelay.Control(meta, "stop", 5*time.Second, &out)
	if err != nil || msg["ok"] != true || msg["state"] != "stopped" {
		t.Fatalf("stop through the relay: %v %v %q", msg, err, out.String())
	}
	cancel()
	<-done
}
