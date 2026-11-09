package ttyrelay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"gamebond.local/nativeedge/atomicio"
)

// Record is the validated metadata file (python read_metadata).
type Record struct {
	Version    int    `json:"version"`
	PID        int    `json:"pid"`
	Port       int    `json:"port"`
	Token      string `json:"token"`
	ConfigPath string `json:"config_path,omitempty"`
}

// ReadMetadata is tty_server.read_metadata.
func ReadMetadata(path string) (Record, error) {
	data, err := atomicio.ReadBytesShared(path, maxMetadataBytes)
	if err != nil {
		return Record{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &raw); err != nil || raw == nil {
		return Record{}, errors.New("invalid log relay metadata")
	}
	bad := errors.New("invalid log relay metadata")
	var rec Record
	vtext, ptext := string(bytes.TrimSpace(raw["version"])), string(bytes.TrimSpace(raw["port"]))
	var vnum, pnum json.Number
	if vtext != "true" {
		if vtext == "" || vtext[0] == '"' || json.Unmarshal(raw["version"], &vnum) != nil {
			return Record{}, bad
		}
		if f, err := vnum.Float64(); err != nil || f != 1 {
			return Record{}, bad
		}
	}
	if ptext == "" || ptext[0] == '"' || json.Unmarshal(raw["port"], &pnum) != nil {
		return Record{}, bad
	}
	port, err := pnum.Int64()
	if err != nil || port < 1 || port > 65535 {
		return Record{}, bad
	}
	if json.Unmarshal(raw["token"], &rec.Token) != nil || len(rec.Token) != 64 {
		return Record{}, bad
	}
	rec.Version, rec.Port = 1, int(port)
	_ = json.Unmarshal(raw["pid"], &rec.PID)
	if v, exists := raw["config_path"]; exists {
		if json.Unmarshal(v, &rec.ConfigPath) != nil {
			return Record{}, bad
		}
	}
	return rec, nil
}

// Connect is tty_server.connect: authenticate and return the open connection.
func Connect(rec Record, role string, fields map[string]any) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", rec.Port), time.Second)
	if err != nil {
		return nil, err
	}
	hello := map[string]any{"token": rec.Token, "role": role, "tail": 100}
	for k, v := range fields {
		hello[k] = v
	}
	line, _ := json.Marshal(hello)
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(append(line, '\n')); err != nil {
		conn.Close()
		return nil, err
	}
	var ack []byte
	one := make([]byte, 1)
	for len(ack) <= 4096 {
		if _, err := io.ReadFull(conn, one); err != nil {
			conn.Close()
			return nil, errors.New("log relay rejected the connection")
		}
		ack = append(ack, one[0])
		if one[0] == '\n' {
			break
		}
	}
	var reply map[string]any
	if json.Unmarshal(ack, &reply) != nil || len(reply) != 1 || reply["ok"] != true {
		conn.Close()
		return nil, errors.New("log relay authentication failed")
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func timedOut(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func slice(deadline time.Time) time.Duration {
	d := time.Until(deadline)
	if d > 250*time.Millisecond {
		d = 250 * time.Millisecond
	}
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return d
}

// Attach copies the relay's tail and live output to out for duration.
func Attach(path string, tail int, duration time.Duration, out io.Writer) error {
	if tail < 0 || tail > maxTail {
		return errors.New("tail must be 0..5000")
	}
	if d := duration.Seconds(); math.IsNaN(d) || d <= 0 || d > 3600 {
		return errors.New("duration must be positive and at most 3600 seconds")
	}
	rec, err := ReadMetadata(path)
	if err != nil {
		return err
	}
	conn, err := Connect(rec, "attach", map[string]any{"tail": tail})
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(duration)
	buf := make([]byte, readChunk)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(slice(deadline)))
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if timedOut(err) {
				continue
			}
			return nil // closed by the relay
		}
	}
	return nil
}

// Control runs stop/restart/status, writing each JSON line to out, and returns
// the message with complete=true.
func Control(path, command string, timeout time.Duration, out io.Writer) (map[string]any, error) {
	if command != "stop" && command != "restart" && command != "status" {
		return nil, errors.New("only stop/restart/status are supported")
	}
	if d := timeout.Seconds(); math.IsNaN(d) || d <= 0 || d > 180 {
		return nil, errors.New("timeout must be positive and at most 180 seconds")
	}
	rec, err := ReadMetadata(path)
	if err != nil {
		return nil, err
	}
	conn, err := Connect(rec, "control", map[string]any{"command": command})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	var pending []byte
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(slice(deadline)))
		n, rerr := conn.Read(buf)
		pending = append(pending, buf[:n]...)
		if len(pending) > 8192 {
			return nil, errors.New("invalid control response size")
		}
		for {
			i := bytes.IndexByte(pending, '\n')
			if i < 0 {
				break
			}
			line := append([]byte(nil), pending[:i]...)
			pending = pending[i+1:]
			var msg map[string]any
			if err := json.Unmarshal(line, &msg); err != nil {
				return nil, err
			}
			fmt.Fprintf(out, "%s\n", line)
			if msg["complete"] == true {
				return msg, nil
			}
		}
		if rerr != nil && !timedOut(rerr) {
			return nil, errors.New("Control connection ended before a completed result")
		}
	}
	return nil, errors.New("Control operation did not complete before timeout")
}
