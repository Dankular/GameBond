package ttyrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"
)

// OwnerHandler runs a control command the relay forwarded (stop or restart).
// A nil error answers ok; the returned state must be one of the owner states.
// It runs after the reply has been sent, so a handler that ends the process
// still delivers its answer.
type OwnerHandler func(command string) (state string, err error)

func send(conn net.Conn, v map[string]any) error {
	line, _ := json.Marshal(v)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Write(append(line, '\n'))
	return err
}

// ServeOwner registers this process as the relay's control owner (the role the
// Python supervisor plays), reports state "running", and answers forwarded
// commands until ctx ends or the relay closes the connection. Commands that
// the handler rejects are answered ok=false/complete=true with its error text.
func ServeOwner(ctx context.Context, metadata string, handle OwnerHandler) error {
	rec, err := ReadMetadata(metadata)
	if err != nil {
		return err
	}
	conn, err := Connect(rec, "owner", map[string]any{"pid": os.Getpid()})
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	if err := send(conn, map[string]any{"event": "status", "state": "running"}); err != nil {
		return err
	}
	var pending []byte
	buf := make([]byte, 4096)
	for {
		n, rerr := conn.Read(buf)
		pending = append(pending, buf[:n]...)
		if len(pending) > maxOwnerLine {
			return errors.New("oversized relay request")
		}
		for {
			i := bytes.IndexByte(pending, '\n')
			if i < 0 {
				break
			}
			line := pending[:i]
			pending = append([]byte(nil), pending[i+1:]...)
			var req struct {
				ID      string `json:"request_id"`
				Command string `json:"command"`
			}
			if json.Unmarshal(line, &req) != nil || req.ID == "" {
				continue
			}
			state, herr := "stopping", error(nil)
			if req.Command == "stop" {
				// Answer first: the handler normally ends this process.
				if err := send(conn, map[string]any{"request_id": req.ID, "ok": true, "complete": true, "state": "stopping"}); err != nil {
					return err
				}
				if _, herr = handle(req.Command); herr != nil {
					return herr
				}
				continue
			}
			state, herr = handle(req.Command)
			reply := map[string]any{"request_id": req.ID, "ok": herr == nil, "complete": true, "state": state}
			if herr != nil {
				reply["error"] = herr.Error()
			}
			if err := send(conn, reply); err != nil {
				return err
			}
		}
		if rerr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return rerr
		}
	}
}

func ownerPID() int { return os.Getpid() }
