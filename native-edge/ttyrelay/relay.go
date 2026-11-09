// Package ttyrelay is the Go port of gamebond/tty_server.py: a loopback log
// relay with authenticated publish/attach/owner/control roles. There is no
// shell and no arbitrary input; control is limited to stop, restart and
// status, executed by the registered owner (the elevated supervisor).
package ttyrelay

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultRing      = 256 * 1024
	DefaultReader    = 256 * 1024
	DefaultAttach    = 8
	maxClients       = 16
	maxAuthLine      = 4096
	maxOwnerLine     = 8192
	authTimeout      = 5 * time.Second
	maxTail          = 5000
	readChunk        = 16384
	metadataVersion  = 1
	maxMetadataBytes = 4096
)

// Options bound the relay. Zero values select the defaults.
type Options struct {
	Metadata       string
	RingLimit      int
	ReaderLimit    int
	MaxAttachments int
}

// Counts mirrors the Python counters.
type Counts struct {
	AuthRejected   int
	SlowReaders    int
	InputRejected  int
	PublishedBytes int
}

type client struct {
	conn       net.Conn
	role       string
	in         []byte
	out        []byte
	wake       chan struct{}
	closeAfter bool
	closed     bool
	pid        int
}

// Relay is a running log relay.
type Relay struct {
	opt      Options
	token    string
	listener net.Listener
	port     int

	mu         sync.Mutex
	ring       []byte
	counts     Counts
	clients    map[*client]struct{}
	owner      *client
	ownerState string
	pending    map[string]*client

	stop chan struct{}
	done sync.WaitGroup
	once sync.Once
}

// Start binds 127.0.0.1:0 and writes the metadata file (mode 0600).
func Start(opt Options) (*Relay, error) {
	if opt.RingLimit <= 0 {
		opt.RingLimit = DefaultRing
	}
	if opt.ReaderLimit <= 0 {
		opt.ReaderLimit = DefaultReader
	}
	if opt.MaxAttachments <= 0 {
		opt.MaxAttachments = DefaultAttach
	}
	if opt.Metadata == "" {
		return nil, errors.New("ttyrelay: metadata path required")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &Relay{opt: opt, token: hex.EncodeToString(raw), listener: l, port: l.Addr().(*net.TCPAddr).Port,
		clients: map[*client]struct{}{}, ownerState: "unavailable", pending: map[string]*client{}, stop: make(chan struct{})}
	if err := r.writeMetadata(); err != nil {
		l.Close()
		return nil, err
	}
	r.done.Add(1)
	go r.accept()
	return r, nil
}

func (r *Relay) writeMetadata() error {
	if err := os.MkdirAll(filepath.Dir(r.opt.Metadata), 0o755); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	rand.Read(suffix)
	tmp := r.opt.Metadata + ".tmp-" + hex.EncodeToString(suffix)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	enc := struct {
		Version int    `json:"version"`
		PID     int    `json:"pid"`
		Port    int    `json:"port"`
		Token   string `json:"token"`
	}{metadataVersion, os.Getpid(), r.port, r.token}
	err = json.NewEncoder(f).Encode(enc)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, r.opt.Metadata)
}

// Port is the loopback listening port.
func (r *Relay) Port() int { return r.port }

// Token is the shared secret (also in the metadata file).
func (r *Relay) Token() string { return r.token }

// Counts returns a snapshot of the counters.
func (r *Relay) Counts() Counts {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts
}

// OwnerState is the last state the owner reported.
func (r *Relay) OwnerState() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ownerState
}

// Close stops the relay and removes the metadata file if it is still ours.
func (r *Relay) Close() {
	r.once.Do(func() {
		close(r.stop)
		r.listener.Close()
		r.mu.Lock()
		for c := range r.clients {
			r.dropLocked(c)
		}
		r.mu.Unlock()
		r.done.Wait()
		if raw, err := os.ReadFile(r.opt.Metadata); err == nil {
			var m struct {
				Token string `json:"token"`
			}
			if json.Unmarshal(raw, &m) == nil && m.Token == r.token {
				os.Remove(r.opt.Metadata)
			}
		}
	})
}

func (r *Relay) accept() {
	defer r.done.Done()
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		if len(r.clients) >= maxClients {
			r.mu.Unlock()
			conn.Close()
			continue
		}
		c := &client{conn: conn, wake: make(chan struct{}, 1)}
		r.clients[c] = struct{}{}
		r.mu.Unlock()
		r.done.Add(2)
		go r.read(c)
		go r.write(c)
	}
}

func (r *Relay) read(c *client) {
	defer r.done.Done()
	buf := make([]byte, readChunk)
	c.conn.SetReadDeadline(time.Now().Add(authTimeout))
	for {
		n, err := c.conn.Read(buf)
		if n > 0 {
			r.mu.Lock()
			ok := r.serviceLocked(c, buf[:n])
			r.mu.Unlock()
			if !ok {
				return
			}
		}
		if err != nil {
			r.mu.Lock()
			r.dropLocked(c)
			r.mu.Unlock()
			return
		}
	}
}

func (r *Relay) write(c *client) {
	defer r.done.Done()
	for {
		select {
		case <-c.wake:
		case <-r.stop:
			return
		}
		for {
			r.mu.Lock()
			if c.closed {
				r.mu.Unlock()
				return
			}
			if len(c.out) == 0 {
				if c.closeAfter {
					r.dropLocked(c)
					r.mu.Unlock()
					return
				}
				r.mu.Unlock()
				break
			}
			chunk := append([]byte(nil), c.out[:min(len(c.out), readChunk)]...)
			r.mu.Unlock()
			c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			n, err := c.conn.Write(chunk)
			r.mu.Lock()
			if !c.closed {
				c.out = c.out[min(n, len(c.out)):]
			}
			if err != nil {
				r.dropLocked(c)
				r.mu.Unlock()
				return
			}
			r.mu.Unlock()
		}
	}
}

func (c *client) kick() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (r *Relay) dropLocked(c *client) {
	if c.closed {
		return
	}
	c.closed = true
	delete(r.clients, c)
	if c == r.owner {
		r.owner = nil
		r.ownerState = "unavailable"
		for id, reader := range r.pending {
			r.controlReplyLocked(reader, controlMsg{OK: false, Complete: true, RequestID: id, State: "unavailable", Error: "Control owner disconnected"})
		}
		r.pending = map[string]*client{}
	}
	for id, reader := range r.pending {
		if reader == c {
			delete(r.pending, id)
		}
	}
	c.conn.Close()
}

// controlMsg is a control-channel JSON line with Python's key order.
type controlMsg struct {
	OK        bool
	Complete  bool
	RequestID string
	State     string
	Command   string
	Error     string
	OwnerPID  *int
	withPID   bool
}

func (m controlMsg) encode() []byte {
	var b bytes.Buffer
	str := func(s string) string {
		var e bytes.Buffer
		enc := json.NewEncoder(&e)
		enc.SetEscapeHTML(false)
		enc.Encode(s)
		return string(bytes.TrimSpace(e.Bytes()))
	}
	b.WriteString(`{"ok":` + strconv.FormatBool(m.OK) + `,"complete":` + strconv.FormatBool(m.Complete))
	if m.RequestID != "" {
		b.WriteString(`,"request_id":` + str(m.RequestID))
	}
	if m.State != "" {
		b.WriteString(`,"state":` + str(m.State))
	}
	if m.Command != "" {
		b.WriteString(`,"command":` + str(m.Command))
	}
	if m.withPID {
		if m.OwnerPID == nil {
			b.WriteString(`,"owner_pid":null`)
		} else {
			b.WriteString(`,"owner_pid":` + strconv.Itoa(*m.OwnerPID))
		}
	}
	if m.Error != "" {
		b.WriteString(`,"error":` + str(m.Error))
	}
	b.WriteString("}\n")
	return b.Bytes()
}

func (r *Relay) queueLocked(c *client, data []byte) bool {
	if c.closed {
		return false
	}
	if len(c.out)+len(data) > r.opt.ReaderLimit {
		r.dropLocked(c)
		return false
	}
	c.out = append(c.out, data...)
	c.kick()
	return true
}

func (r *Relay) controlReplyLocked(c *client, m controlMsg) {
	if r.queueLocked(c, m.encode()) && m.Complete {
		c.closeAfter = true
	}
}

func (r *Relay) requestControlLocked(c *client, command string) {
	switch {
	case command == "status":
		m := controlMsg{OK: true, Complete: true, State: r.ownerState, withPID: true}
		if r.owner != nil {
			pid := r.owner.pid
			m.OwnerPID = &pid
		}
		r.controlReplyLocked(c, m)
	case r.owner == nil:
		r.controlReplyLocked(c, controlMsg{Complete: true, State: "unavailable", Error: "No elevated client supervisor is registered"})
	case len(r.pending) > 0:
		r.controlReplyLocked(c, controlMsg{Complete: true, State: r.ownerState, Error: "A previous control operation is still in progress"})
	default:
		raw := make([]byte, 12)
		rand.Read(raw)
		id := hex.EncodeToString(raw)
		r.pending[id] = c
		r.controlReplyLocked(c, controlMsg{OK: true, RequestID: id, State: "requested", Command: command})
		line, _ := json.Marshal(map[string]string{"request_id": id, "command": command}) // keys sort: command, request_id
		r.queueLocked(r.owner, append(line, '\n'))
	}
}

var ownerStates = map[string]bool{"starting": true, "running": true, "stopping": true, "stopped": true, "restarting": true, "failed": true}

// ownerDataLocked handles bytes from the owner; false means drop it.
func (r *Relay) ownerDataLocked(c *client, data []byte) bool {
	c.in = append(c.in, data...)
	if len(c.in) > maxOwnerLine {
		return false
	}
	for {
		i := bytes.IndexByte(c.in, '\n')
		if i < 0 {
			return true
		}
		line := c.in[:i]
		c.in = append([]byte(nil), c.in[i+1:]...)
		var msg map[string]any
		if err := json.Unmarshal(line, &msg); err != nil {
			return false
		}
		state, _ := msg["state"].(string)
		if !ownerStates[state] {
			return false
		}
		r.ownerState = state
		if msg["event"] == "status" {
			continue
		}
		id, _ := msg["request_id"].(string)
		reader, ok := r.pending[id]
		if !ok {
			continue
		}
		okv, ok1 := msg["ok"].(bool)
		complete, ok2 := msg["complete"].(bool)
		if !ok1 || !ok2 {
			return false
		}
		m := controlMsg{OK: okv, Complete: complete, RequestID: id, State: state}
		if e, has := msg["error"]; has {
			s, isStr := e.(string)
			if !isStr {
				s = fmt.Sprint(e)
			}
			if rs := []rune(s); len(rs) > 1024 {
				s = string(rs[:1024])
			}
			m.Error = s
		}
		r.controlReplyLocked(reader, m)
		if complete {
			delete(r.pending, id)
		}
	}
}

func (r *Relay) publishLocked(data []byte) {
	if len(data) > r.opt.RingLimit {
		data = data[len(data)-r.opt.RingLimit:]
	}
	r.ring = append(r.ring, data...)
	if len(r.ring) > r.opt.RingLimit {
		r.ring = append([]byte(nil), r.ring[len(r.ring)-r.opt.RingLimit:]...)
	}
	r.counts.PublishedBytes += len(data)
	for c := range r.clients {
		if c.role != "attach" {
			continue
		}
		if len(c.out)+len(data) > r.opt.ReaderLimit {
			r.counts.SlowReaders++
			r.dropLocked(c)
		} else {
			c.out = append(c.out, data...)
			c.kick()
		}
	}
}

// tail is bytes.splitlines(keepends=True)[-lines:] joined.
func tail(ring []byte, lines int) []byte {
	if lines == 0 {
		return nil
	}
	var starts []int
	for i := 0; i < len(ring); {
		starts = append(starts, i)
		j := i
		for j < len(ring) && ring[j] != '\n' && ring[j] != '\r' {
			j++
		}
		if j < len(ring) {
			if ring[j] == '\r' && j+1 < len(ring) && ring[j+1] == '\n' {
				j++
			}
			j++
		}
		i = j
	}
	if len(starts) > lines {
		return ring[starts[len(starts)-lines]:]
	}
	return ring
}

func intField(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || i < -1<<31 || i > 1<<31 {
		return 0, false
	}
	return int(i), true
}

func (r *Relay) authenticateLocked(c *client) {
	reject := func() {
		r.counts.AuthRejected++
		r.dropLocked(c)
	}
	i := bytes.IndexByte(c.in, '\n')
	line, remainder := c.in[:i], append([]byte(nil), c.in[i+1:]...)
	var auth map[string]any
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if dec.Decode(&auth) != nil || auth == nil || dec.More() {
		reject()
		return
	}
	token, ok := auth["token"].(string)
	if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(r.token)) != 1 {
		reject()
		return
	}
	role, _ := auth["role"].(string)
	tl := 100
	if v, has := auth["tail"]; has {
		var okTail bool
		if tl, okTail = intField(v); !okTail || tl < 0 || tl > maxTail {
			reject()
			return
		}
	}
	limit := map[string]int{"attach": r.opt.MaxAttachments, "owner": 1, "publish": 2, "control": 8}[role]
	if limit == 0 {
		reject()
		return
	}
	count := 0
	for o := range r.clients {
		if o.role == role {
			count++
		}
	}
	if count >= limit || ((role == "attach" || role == "control") && len(remainder) > 0) {
		reject()
		return
	}
	command, _ := auth["command"].(string)
	if role == "control" && command != "stop" && command != "restart" && command != "status" {
		reject()
		return
	}
	pid := 0
	if role == "owner" {
		var okPid bool
		if pid, okPid = intField(auth["pid"]); !okPid || pid <= 0 {
			reject()
			return
		}
	}
	c.in = nil
	c.role = role
	c.conn.SetReadDeadline(time.Time{})
	c.out = append(c.out, `{"ok":true}`+"\n"...)
	if role == "attach" {
		replay := tail(r.ring, tl)
		if remaining := max(0, r.opt.ReaderLimit-len(c.out)); remaining > 0 {
			if len(replay) > remaining {
				replay = replay[len(replay)-remaining:]
			}
			c.out = append(c.out, replay...)
		}
	}
	c.kick()
	switch role {
	case "owner":
		r.owner, r.ownerState, c.pid = c, "starting", pid
	case "control":
		r.requestControlLocked(c, command)
	}
	if role == "publish" && len(remainder) > 0 {
		r.publishLocked(remainder)
	} else if role == "owner" && len(remainder) > 0 {
		if !r.ownerDataLocked(c, remainder) {
			r.dropLocked(c)
		}
	}
}

// serviceLocked handles received bytes; false stops the reader.
func (r *Relay) serviceLocked(c *client, data []byte) bool {
	if c.closed {
		return false
	}
	switch c.role {
	case "":
		c.in = append(c.in, data...)
		if len(c.in) > maxAuthLine {
			r.dropLocked(c)
			return false
		}
		if bytes.IndexByte(c.in, '\n') >= 0 {
			r.authenticateLocked(c)
		}
	case "publish":
		r.publishLocked(data)
	case "owner":
		if !r.ownerDataLocked(c, data) {
			r.dropLocked(c)
		}
	default:
		r.counts.InputRejected++
		r.dropLocked(c)
	}
	return !c.closed
}
