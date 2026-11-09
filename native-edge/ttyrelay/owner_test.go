package ttyrelay

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func waitState(t *testing.T, r *Relay, want string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if r.OwnerState() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("owner state %q, want %q", r.OwnerState(), want)
}

func TestServeOwnerStopAndRestart(t *testing.T) {
	r, path := startWithMeta(t)
	var mu sync.Mutex
	var commands []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeOwner(ctx, path, func(c string) (string, error) {
			mu.Lock()
			commands = append(commands, c)
			mu.Unlock()
			if c == "restart" {
				return "running", errors.New("restart is not supported by the Go daemon")
			}
			return "stopped", nil
		})
	}()
	waitState(t, r, "running")

	var out bytes.Buffer
	msg, err := Control(path, "restart", 5*time.Second, &out)
	if err != nil || msg["ok"] != false || msg["complete"] != true || msg["state"] != "running" ||
		!strings.Contains(out.String(), "restart is not supported") {
		t.Fatalf("restart: %v %v %q", msg, err, out.String())
	}
	msg, err = Control(path, "status", 5*time.Second, &out)
	if err != nil || msg["state"] != "running" || msg["owner_pid"] == nil {
		t.Fatalf("status: %v %v", msg, err)
	}
	msg, err = Control(path, "stop", 5*time.Second, &out)
	if err != nil || msg["ok"] != true || msg["complete"] != true || msg["state"] != "stopping" {
		t.Fatalf("stop: %v %v", msg, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(commands)
		mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	if strings.Join(commands, ",") != "restart,stop" {
		t.Fatalf("handler saw %v", commands)
	}
	mu.Unlock()

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitState(t, r, "unavailable")
	// With the owner gone the relay says so.
	msg, err = Control(path, "stop", 5*time.Second, &out)
	if err != nil || msg["ok"] != false || msg["state"] != "unavailable" {
		t.Fatalf("after owner exit: %v %v", msg, err)
	}
}

func TestServeOwnerOnlyOneOwner(t *testing.T) {
	r, path := startWithMeta(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ServeOwner(ctx, path, func(string) (string, error) { return "stopped", nil })
	waitState(t, r, "running")
	err := ServeOwner(ctx, path, func(string) (string, error) { return "stopped", nil })
	if err == nil {
		t.Fatal("second owner accepted")
	}
}
