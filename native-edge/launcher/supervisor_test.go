package launcher

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type collector struct {
	mu   sync.Mutex
	msgs []map[string]any
}

func collect(o *Owner) *collector {
	c := &collector{}
	go func() {
		for m := range o.Outgoing() {
			c.mu.Lock()
			c.msgs = append(c.msgs, m)
			c.mu.Unlock()
		}
	}()
	return c
}

func (c *collector) wait(t *testing.T, match func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, m := range c.msgs {
			if match(m) {
				c.mu.Unlock()
				return m
			}
		}
		c.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("message never arrived; saw %v", c.msgs)
	return nil
}

func (c *collector) states() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, m := range c.msgs {
		if s, ok := m["event"].(string); ok && s == "status" {
			out = append(out, m["state"].(string))
		}
	}
	return out
}

func answer(id string) func(map[string]any) bool {
	return func(m map[string]any) bool { return m["request_id"] == id && m["complete"] == true }
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// blockingRun becomes ready, then waits for ctx.
func blockingRun(runs *int32, mu *sync.Mutex) RunFunc {
	return func(ctx context.Context, ready func()) error {
		mu.Lock()
		*runs++
		mu.Unlock()
		ready()
		<-ctx.Done()
		return nil
	}
}

func start(o *Owner, run RunFunc, opt Options) (done chan int) {
	done = make(chan int, 1)
	opt.Poll = 5 * time.Millisecond
	go func() { done <- Supervise(context.Background(), o, run, opt) }()
	return
}

func TestOnceSuccessAndFailure(t *testing.T) {
	o := NewOwner()
	c := collect(o)
	if st := <-start(o, func(ctx context.Context, ready func()) error { ready(); return nil }, Options{Once: true}); st != 0 {
		t.Fatalf("status %d", st)
	}
	time.Sleep(20 * time.Millisecond)
	if got := c.states(); !eq(got, []string{"starting", "running", "stopped"}) {
		t.Fatalf("states %v", got)
	}
	o = NewOwner()
	c = collect(o)
	if st := <-start(o, func(context.Context, func()) error { return errors.New("boom") }, Options{Once: true}); st != 1 {
		t.Fatalf("failed run status %d", st)
	}
	time.Sleep(20 * time.Millisecond)
	if got := c.states(); !eq(got, []string{"starting", "failed"}) {
		t.Fatalf("states %v", got)
	}
}

func TestStopRequestWhileRunning(t *testing.T) {
	var runs int32
	var mu sync.Mutex
	o := NewOwner()
	c := collect(o)
	done := start(o, blockingRun(&runs, &mu), Options{})
	c.wait(t, func(m map[string]any) bool { return m["state"] == "running" })
	if err := o.Request("s1", "stop"); err != nil {
		t.Fatal(err)
	}
	ack := c.wait(t, func(m map[string]any) bool { return m["request_id"] == "s1" && m["complete"] == false })
	if ack["state"] != "stopping" || ack["ok"] != true {
		t.Fatalf("ack %v", ack)
	}
	fin := c.wait(t, answer("s1"))
	if fin["ok"] != true || fin["state"] != "stopped" {
		t.Fatalf("final %v", fin)
	}
	o.Close()
	<-done
	if runs != 1 {
		t.Fatalf("ran %d times", runs)
	}
}

func TestRestartWhileRunningCompletesAtReady(t *testing.T) {
	var runs int32
	var mu sync.Mutex
	o := NewOwner()
	c := collect(o)
	done := start(o, blockingRun(&runs, &mu), Options{})
	c.wait(t, func(m map[string]any) bool { return m["state"] == "running" })
	o.Request("r1", "restart")
	fin := c.wait(t, answer("r1"))
	if fin["ok"] != true || fin["state"] != "running" {
		t.Fatalf("restart answer %v", fin)
	}
	mu.Lock()
	n := runs
	mu.Unlock()
	if n != 2 {
		t.Fatalf("ran %d times", n)
	}
	states := c.states()
	want := []string{"starting", "running", "stopped", "restarting", "running"}
	if len(states) < 5 || !eq(states[:5], want) {
		t.Fatalf("states %v", states)
	}
	o.Close()
	<-done
}

func TestRestartThatFailsBeforeReadyReportsFailure(t *testing.T) {
	var n int
	var mu sync.Mutex
	run := func(ctx context.Context, ready func()) error {
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if first {
			ready()
			<-ctx.Done()
			return nil
		}
		return errors.New("cannot bind")
	}
	o := NewOwner()
	c := collect(o)
	done := start(o, run, Options{})
	c.wait(t, func(m map[string]any) bool { return m["state"] == "running" })
	o.Request("r1", "restart")
	fin := c.wait(t, answer("r1"))
	if fin["ok"] != false || fin["state"] != "failed" || fin["error"] != "cannot bind" {
		t.Fatalf("answer %v", fin)
	}
	// A later stop reports the retained failure.
	o.Request("s1", "stop")
	if st := c.wait(t, answer("s1")); st["ok"] != false || st["state"] != "failed" {
		t.Fatalf("stop after failure %v", st)
	}
	o.Close()
	<-done
}

func TestRestartThatStopsBeforeReadyIsReported(t *testing.T) {
	var n int
	var mu sync.Mutex
	run := func(ctx context.Context, ready func()) error {
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if first {
			ready()
		}
		<-ctx.Done()
		return nil
	}
	o := NewOwner()
	c := collect(o)
	done := start(o, run, Options{})
	c.wait(t, func(m map[string]any) bool { return m["state"] == "running" })
	o.Request("r1", "restart")
	// second run never becomes ready; a stop would be refused as in-progress, so close it.
	c.wait(t, func(m map[string]any) bool { return m["state"] == "restarting" })
	if err := o.Request("s2", "stop"); err != nil {
		t.Fatal(err)
	}
	refused := c.wait(t, answer("s2"))
	if refused["ok"] != false || refused["error"] != "Supervisor operation already in progress" {
		t.Fatalf("concurrent request %v", refused)
	}
	o.Close()
	fin := c.wait(t, answer("r1"))
	if fin["ok"] != false || fin["error"] != "Client stopped before becoming ready" {
		t.Fatalf("answer %v", fin)
	}
	<-done
}

func TestInvalidCommandsRejected(t *testing.T) {
	o := NewOwner()
	for _, tc := range [][2]string{{"x", "shell"}, {"", "stop"}, {string(make([]byte, 65)), "stop"}, {"id", ""}} {
		if err := o.Request(tc[0], tc[1]); err == nil {
			t.Fatalf("%q accepted", tc)
		}
	}
}

func TestInitiallyStoppedWaitsForRestart(t *testing.T) {
	var runs int32
	var mu sync.Mutex
	o := NewOwner()
	c := collect(o)
	done := start(o, blockingRun(&runs, &mu), Options{InitiallyStopped: true})
	c.wait(t, func(m map[string]any) bool { return m["state"] == "stopped" })
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	if runs != 0 {
		t.Fatal("ran without a request")
	}
	mu.Unlock()
	o.Request("go", "restart")
	if fin := c.wait(t, answer("go")); fin["state"] != "running" || fin["ok"] != true {
		t.Fatalf("answer %v", fin)
	}
	o.Close()
	<-done
}

func TestStopArrivingBetweenRunsIsNotLost(t *testing.T) {
	// A stop queued while no run is bound must cancel the next run when it binds.
	o := NewOwner()
	o.Request("s1", "stop") // pending, no run yet
	ctx, cancel := context.WithCancel(context.Background())
	o.BindStop(cancel, "")
	if ctx.Err() == nil {
		t.Fatal("pending stop did not cancel the newly bound run")
	}
	// ...but the restart being served must not cancel itself.
	o2 := NewOwner()
	o2.Request("r1", "restart")
	ctx2, cancel2 := context.WithCancel(context.Background())
	o2.BindStop(cancel2, "r1")
	if ctx2.Err() != nil {
		t.Fatal("restart cancelled its own run")
	}
}

func TestOutgoingOverflowFailsClosed(t *testing.T) {
	o := NewOwner()
	ctx, cancel := context.WithCancel(context.Background())
	o.BindStop(cancel, "")
	for i := 0; i < 70; i++ { // nothing drains Outgoing
		o.SetState("running")
	}
	select {
	case <-o.Shutdown():
	default:
		t.Fatal("owner stayed open after the queue overflowed")
	}
	if ctx.Err() == nil {
		t.Fatal("running tunnel not stopped on overflow")
	}
}

func TestPanicInRunIsAFailure(t *testing.T) {
	o := NewOwner()
	collect(o)
	if st := <-start(o, func(context.Context, func()) error { panic("x") }, Options{Once: true}); st != 1 {
		t.Fatalf("status %d", st)
	}
}

func TestStopThatSurfacesContextCanceledIsNotAFailure(t *testing.T) {
	o := NewOwner()
	c := collect(o)
	done := start(o, func(ctx context.Context, ready func()) error { ready(); <-ctx.Done(); return ctx.Err() }, Options{})
	c.wait(t, func(m map[string]any) bool { return m["state"] == "running" })
	o.Request("s1", "stop")
	if fin := c.wait(t, answer("s1")); fin["ok"] != true || fin["state"] != "stopped" {
		t.Fatalf("answer %v", fin)
	}
	o.Close()
	<-done
}
