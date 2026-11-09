// Package launcher is the supervisor half of windows_launcher.py: the control
// owner (cooperative stop and restart only, never a shell) and the loop that
// runs the tunnel, stops it on request and relaunches it, while the elevated
// owner stays registered with the log relay.
package launcher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Owner holds the supervisor state and the request/response bookkeeping that
// ControlOwner keeps in Python. Messages for the relay are read from Outgoing.
type Owner struct {
	mu       sync.Mutex
	state    string
	pending  *request
	stop     context.CancelFunc
	requests chan request
	outgoing chan map[string]any
	down     chan struct{}
	downOnce sync.Once
}

type request struct{ id, command string }

// NewOwner is a ControlOwner in state "starting".
func NewOwner() *Owner {
	return &Owner{state: "starting", requests: make(chan request, 1), outgoing: make(chan map[string]any, 64), down: make(chan struct{})}
}

// Outgoing carries status events and request answers for the relay.
func (o *Owner) Outgoing() <-chan map[string]any { return o.outgoing }

// Shutdown is closed once the owner is closed.
func (o *Owner) Shutdown() <-chan struct{} { return o.down }

// State is the last reported state.
func (o *Owner) State() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.state
}

func (o *Owner) send(m map[string]any) {
	select {
	case o.outgoing <- m:
	default:
		// Fail closed rather than allowing unbounded command/response state.
		o.downOnce.Do(func() { close(o.down) })
		o.mu.Lock()
		stop := o.stop
		o.mu.Unlock()
		if stop != nil {
			stop()
		}
	}
}

// SetState records and announces a state.
func (o *Owner) SetState(state string) {
	o.mu.Lock()
	o.state = state
	o.mu.Unlock()
	o.send(map[string]any{"event": "status", "state": state})
}

// BindStop registers the cancel function of the running tunnel (nil clears it).
// A stop that arrived during startup must not be lost: unless the pending
// request is the restart being served, the new run is cancelled immediately.
func (o *Owner) BindStop(stop context.CancelFunc, restarting string) {
	o.mu.Lock()
	o.stop = stop
	cancel := stop != nil && o.pending != nil && o.pending.id != restarting
	o.mu.Unlock()
	if cancel {
		stop()
	}
}

// Complete answers a request and clears it if pending.
func (o *Owner) Complete(id string, ok bool, state string, err error) {
	o.mu.Lock()
	o.state = state
	if o.pending != nil && o.pending.id == id {
		o.pending = nil
	}
	o.mu.Unlock()
	m := map[string]any{"request_id": id, "complete": true, "ok": ok, "state": state}
	if err != nil {
		m["error"] = truncate(err.Error(), 1024)
	}
	o.send(m)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// Request is ControlOwner._request: validate, refuse concurrent operations,
// queue the command, ask a running tunnel to stop. Invalid commands return an
// error (Python raises, which drops the relay connection).
func (o *Owner) Request(id, command string) error {
	if (command != "stop" && command != "restart") || id == "" || len(id) > 64 {
		return errors.New("invalid supervisor command")
	}
	o.mu.Lock()
	if o.pending != nil {
		state := o.state
		o.mu.Unlock()
		o.send(map[string]any{"request_id": id, "complete": true, "ok": false, "state": state, "error": "Supervisor operation already in progress"})
		return nil
	}
	o.pending = &request{id, command}
	o.requests <- request{id, command} // capacity 1 and pending was empty
	stop := o.stop
	state := "stopped"
	switch {
	case stop != nil:
		state = "stopping"
	case command == "restart":
		state = "restarting"
	}
	o.mu.Unlock()
	if stop != nil {
		stop()
	}
	o.send(map[string]any{"request_id": id, "complete": false, "ok": true, "state": state})
	return nil
}

// Close ends the owner and stops any running tunnel.
func (o *Owner) Close() {
	o.downOnce.Do(func() { close(o.down) })
	o.mu.Lock()
	stop := o.stop
	o.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// RunFunc runs one tunnel session until ctx ends or it fails. It calls ready
// once the tunnel is usable. A nil error with ctx cancelled is a normal stop.
type RunFunc func(ctx context.Context, ready func()) error

// Options is the launcher's --once / --stopped.
type Options struct {
	Once             bool
	InitiallyStopped bool
	// Poll is how often the idle loop checks for shutdown (200 ms in Python).
	Poll time.Duration
	// Log receives the traceback equivalent for failed runs.
	Log func(string)
}

// Supervise is supervise(): run the tunnel, retain the owner after a
// cooperative stop, and serve stop/restart requests. It returns the process
// status: 1 if the last run failed in a --once launch, else 0.
func Supervise(ctx context.Context, owner *Owner, run RunFunc, opt Options) int {
	if opt.Poll == 0 {
		opt.Poll = 200 * time.Millisecond
	}
	if opt.Log == nil {
		opt.Log = func(string) {}
	}
	shouldRun, restart := !opt.InitiallyStopped, ""
	var rmu sync.Mutex // ready may be called from the tunnel's own goroutines
	status := 0
	var lastFailure error
	if opt.InitiallyStopped {
		owner.SetState("stopped")
	}
	for {
		select {
		case <-owner.Shutdown():
			return status
		case <-ctx.Done():
			return status
		default:
		}
		if shouldRun {
			runCtx, stop := context.WithCancel(ctx)
			rmu.Lock()
			cur := restart
			rmu.Unlock()
			owner.BindStop(stop, cur)
			rmu.Lock()
			restarting := restart != ""
			rmu.Unlock()
			if restarting {
				owner.SetState("restarting")
			} else {
				owner.SetState("starting")
			}
			ready := func() {
				owner.SetState("running")
				rmu.Lock()
				id := restart
				restart = ""
				rmu.Unlock()
				if id != "" {
					owner.Complete(id, true, "running", nil)
				}
			}
			var failed error
			lastFailure = nil
			func() {
				defer func() {
					if r := recover(); r != nil {
						failed = fmt.Errorf("panic: %v", r)
					}
				}()
				failed = run(runCtx, ready)
			}()
			if failed != nil && runCtx.Err() != nil && errors.Is(failed, context.Canceled) {
				failed = nil // a requested stop is not a failure
			}
			if failed != nil {
				opt.Log(failed.Error())
				lastFailure, status = failed, 1
			}
			owner.BindStop(nil, "")
			stop()
			if failed != nil {
				owner.SetState("failed")
			} else {
				owner.SetState("stopped")
			}
			rmu.Lock()
			id := restart
			restart = ""
			rmu.Unlock()
			if id != "" {
				err := failed
				if err == nil {
					err = errors.New("Client stopped before becoming ready")
				}
				owner.Complete(id, false, "failed", err)
			}
			if opt.Once {
				return status
			}
			shouldRun = false
		}
		select {
		case req := <-owner.requests:
			switch req.command {
			case "stop":
				state := "stopped"
				if lastFailure != nil {
					state = "failed"
				}
				owner.Complete(req.id, lastFailure == nil, state, lastFailure)
			case "restart":
				rmu.Lock()
				restart = req.id
				rmu.Unlock()
				shouldRun = true
			}
		case <-time.After(opt.Poll):
		case <-owner.Shutdown():
			return status
		case <-ctx.Done():
			return status
		}
	}
}
