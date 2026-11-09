package ttyrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"
)

// Supervisor is the control owner's state machine (package launcher): the
// relay forwards stop/restart requests to it and it answers asynchronously.
type Supervisor interface {
	Request(id, command string) error
	Outgoing() <-chan map[string]any
	State() string
}

// ServeSupervisor is ControlOwner._run: register as the exclusive control
// owner, send the supervisor's messages, feed forwarded commands to it, and
// reconnect (re-reading the metadata file) when the relay goes away. It
// returns when ctx ends. registered is closed after the first successful
// registration.
func ServeSupervisor(ctx context.Context, metadata string, sup Supervisor, registered func()) error {
	var once sync.Once
	rec, rerr := ReadMetadata(metadata)
	for ctx.Err() == nil {
		var conn net.Conn
		var err error
		if rerr == nil {
			conn, err = Connect(rec, "owner", map[string]any{"pid": ownerPID()})
		} else {
			err = rerr
		}
		if err != nil {
			rec, rerr = ReadMetadata(metadata)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(250 * time.Millisecond):
			}
			continue
		}
		once.Do(func() {
			if registered != nil {
				registered()
			}
		})
		serveSupervisorConn(ctx, conn, sup)
		conn.Close()
	}
	return nil
}

func serveSupervisorConn(ctx context.Context, conn net.Conn, sup Supervisor) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if send(conn, map[string]any{"event": "status", "state": sup.State()}) != nil {
		return
	}
	lines := make(chan []byte)
	failed := make(chan error, 1)
	go func() {
		var pending []byte
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			pending = append(pending, buf[:n]...)
			if len(pending) > 8192 {
				failed <- errors.New("oversized supervisor command")
				return
			}
			for {
				i := bytes.IndexByte(pending, '\n')
				if i < 0 {
					break
				}
				line := append([]byte(nil), pending[:i]...)
				pending = append([]byte(nil), pending[i+1:]...)
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				failed <- err
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-failed:
			return
		case m := <-sup.Outgoing():
			if send(conn, m) != nil {
				return
			}
		case line := <-lines:
			var req struct {
				ID      string `json:"request_id"`
				Command string `json:"command"`
			}
			if json.Unmarshal(line, &req) != nil || sup.Request(req.ID, req.Command) != nil {
				return // an invalid command drops the connection, as in Python
			}
		}
	}
}
