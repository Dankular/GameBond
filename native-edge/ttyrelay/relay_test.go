package ttyrelay

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func start(t *testing.T, opt Options) *Relay {
	t.Helper()
	opt.Metadata = filepath.Join(t.TempDir(), "tty.json")
	r, err := Start(opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func dial(t *testing.T, r *Relay, auth string, extra string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(r.Port())))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, auth+"\n"+extra)
	return c, bufio.NewReader(c)
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func authLine(r *Relay, fields string) string {
	s := `{"token":"` + r.Token() + `"`
	if fields != "" {
		s += "," + fields
	}
	return s + "}"
}

func line(t *testing.T, br *bufio.Reader) map[string]any {
	t.Helper()
	l, err := br.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(l, &m); err != nil {
		t.Fatalf("%q: %v", l, err)
	}
	return m
}

func closed(br *bufio.Reader) bool {
	_, err := br.ReadByte()
	return err == io.EOF || (err != nil && !strings.Contains(err.Error(), "timeout"))
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func TestPublishReplayAndLiveAttach(t *testing.T) {
	r := start(t, Options{})
	pub, _ := dial(t, r, authLine(r, `"role":"publish"`), "one\ntwo\nthree\n")
	waitFor(t, "published", func() bool { return r.Counts().PublishedBytes == 14 })
	_, br := dial(t, r, authLine(r, `"role":"attach","tail":2`), "")
	if m := line(t, br); m["ok"] != true {
		t.Fatal(m)
	}
	if l, _ := br.ReadString('\n'); l != "two\n" {
		t.Fatalf("replay %q", l)
	}
	if l, _ := br.ReadString('\n'); l != "three\n" {
		t.Fatalf("replay %q", l)
	}
	io.WriteString(pub, "four\n")
	if l, _ := br.ReadString('\n'); l != "four\n" {
		t.Fatalf("live %q", l)
	}
}

func TestTailSplitsLikePythonBytes(t *testing.T) {
	cases := []struct {
		in    string
		lines int
		want  string
	}{
		{"a\nb\nc\n", 2, "b\nc\n"}, {"a\r\nb\rc", 2, "b\rc"}, {"a\r\nb\r\n", 1, "b\r\n"}, {"x", 5, "x"}, {"", 3, ""},
		{"a\nb", 0, ""}, {"a\x0bb\x0cc\n", 1, "a\x0bb\x0cc\n"}, {"\n\n\n", 2, "\n\n"}, {"a\n\rb", 3, "a\n\rb"},
	}
	for _, c := range cases {
		if got := string(tail([]byte(c.in), c.lines)); got != c.want {
			t.Errorf("tail(%q,%d)=%q want %q", c.in, c.lines, got, c.want)
		}
	}
}

func TestAuthRejections(t *testing.T) {
	r := start(t, Options{})
	bad := []string{
		`{"token":"nope","role":"attach"}`,
		`{"role":"attach"}`,
		authLine(r, `"role":"shell"`),
		authLine(r, `"role":"attach","tail":5001`),
		authLine(r, `"role":"attach","tail":-1`),
		authLine(r, `"role":"attach","tail":1.0`),
		authLine(r, `"role":"attach","tail":true`),
		authLine(r, `"role":"control","command":"exec"`),
		authLine(r, `"role":"control"`),
		authLine(r, `"role":"owner"`),
		authLine(r, `"role":"owner","pid":0`),
		authLine(r, `"role":"owner","pid":"7"`),
		`[1]`, `null`, `{"token":"` + r.Token() + `"} trailing`,
	}
	for _, a := range bad {
		_, br := dial(t, r, a, "")
		if !closed(br) {
			t.Errorf("accepted %s", a)
		}
	}
	waitFor(t, "counted", func() bool { return r.Counts().AuthRejected == len(bad) })
	// attach and control may not carry trailing bytes
	_, br := dial(t, r, authLine(r, `"role":"attach"`), "x")
	if !closed(br) {
		t.Error("attach with trailing bytes accepted")
	}
}

func TestRoleLimitsAndInputRejected(t *testing.T) {
	r := start(t, Options{MaxAttachments: 2})
	a1, b1 := dial(t, r, authLine(r, `"role":"attach"`), "")
	line(t, b1)
	_, b2 := dial(t, r, authLine(r, `"role":"attach"`), "")
	line(t, b2)
	_, b3 := dial(t, r, authLine(r, `"role":"attach"`), "")
	if !closed(b3) {
		t.Fatal("third attach accepted")
	}
	io.WriteString(a1, "typed input")
	if !closed(b1) {
		t.Fatal("attach input accepted")
	}
	waitFor(t, "input_rejected", func() bool { return r.Counts().InputRejected == 1 })
	for i := 0; i < 2; i++ {
		_, b := dial(t, r, authLine(r, `"role":"publish"`), "")
		line(t, b)
	}
	_, b := dial(t, r, authLine(r, `"role":"publish"`), "")
	if !closed(b) {
		t.Fatal("third publisher accepted")
	}
}

func TestSlowReaderDropped(t *testing.T) {
	r := start(t, Options{ReaderLimit: 1024})
	_, br := dial(t, r, authLine(r, `"role":"attach"`), "")
	line(t, br)
	pub, _ := dial(t, r, authLine(r, `"role":"publish"`), strings.Repeat("x", 4000))
	_ = pub
	waitFor(t, "slow reader", func() bool { return r.Counts().SlowReaders == 1 })
}

func TestUnauthenticatedTimeoutAndOversize(t *testing.T) {
	r := start(t, Options{})
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(r.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, strings.Repeat("a", 5000))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("oversized pre-auth input not dropped: %v", err)
	}
}

func TestControlStatusWithoutOwner(t *testing.T) {
	r := start(t, Options{})
	_, br := dial(t, r, authLine(r, `"role":"control","command":"status"`), "")
	line(t, br)
	m := line(t, br)
	if m["ok"] != true || m["complete"] != true || m["state"] != "unavailable" || m["owner_pid"] != nil {
		t.Fatal(m)
	}
	if _, has := m["owner_pid"]; !has {
		t.Fatal("owner_pid key missing")
	}
	_, br = dial(t, r, authLine(r, `"role":"control","command":"stop"`), "")
	line(t, br)
	m = line(t, br)
	if m["ok"] != false || m["state"] != "unavailable" || !strings.Contains(m["error"].(string), "No elevated client") {
		t.Fatal(m)
	}
}

func TestControlRoundTripThroughOwner(t *testing.T) {
	r := start(t, Options{})
	owner, ob := dial(t, r, authLine(r, `"role":"owner","pid":4242`), "")
	line(t, ob)
	waitFor(t, "owner", func() bool { return r.OwnerState() == "starting" })

	_, st := dial(t, r, authLine(r, `"role":"control","command":"status"`), "")
	line(t, st)
	if m := line(t, st); m["owner_pid"] != float64(4242) || m["state"] != "starting" {
		t.Fatal(m)
	}

	_, cb := dial(t, r, authLine(r, `"role":"control","command":"restart"`), "")
	line(t, cb)
	req := line(t, cb)
	if req["complete"] != false || req["state"] != "requested" || req["command"] != "restart" {
		t.Fatal(req)
	}
	id := req["request_id"].(string)
	if len(id) != 24 {
		t.Fatalf("request id %q", id)
	}
	if m := line(t, ob); m["request_id"] != id || m["command"] != "restart" {
		t.Fatal(m)
	}
	// a second control while one is pending is refused
	_, c2 := dial(t, r, authLine(r, `"role":"control","command":"stop"`), "")
	line(t, c2)
	if m := line(t, c2); m["ok"] != false || !strings.Contains(m["error"].(string), "still in progress") {
		t.Fatal(m)
	}
	io.WriteString(owner, `{"request_id":"`+id+`","ok":true,"complete":false,"state":"restarting"}`+"\n")
	if m := line(t, cb); m["complete"] != false || m["state"] != "restarting" {
		t.Fatal(m)
	}
	io.WriteString(owner, `{"request_id":"`+id+`","ok":true,"complete":true,"state":"running"}`+"\n")
	if m := line(t, cb); m["complete"] != true || m["ok"] != true || m["state"] != "running" {
		t.Fatal(m)
	}
	if !closed(cb) {
		t.Fatal("control connection left open after completion")
	}
	// status events and unknown request ids update state without a reply
	io.WriteString(owner, `{"event":"status","state":"stopping"}`+"\n"+`{"request_id":"ffff","ok":true,"complete":true,"state":"stopped"}`+"\n")
	waitFor(t, "state", func() bool { return r.OwnerState() == "stopped" })
}

func TestOwnerProtocolViolationsDropOwner(t *testing.T) {
	for _, msg := range []string{`{"state":"bogus"}`, `not json`} {
		r := start(t, Options{})
		owner, ob := dial(t, r, authLine(r, `"role":"owner","pid":1`), "")
		line(t, ob)
		io.WriteString(owner, msg+"\n")
		if !closed(ob) {
			t.Errorf("owner kept after %s", msg)
		}
		waitFor(t, "unavailable", func() bool { return r.OwnerState() == "unavailable" })
	}
	r := start(t, Options{})
	owner, ob := dial(t, r, authLine(r, `"role":"owner","pid":1`), "")
	line(t, ob)
	_, cb := dial(t, r, authLine(r, `"role":"control","command":"stop"`), "")
	line(t, cb)
	line(t, cb)
	line(t, ob)
	io.WriteString(owner, `{"state":"running","request_id":"`+"zz"+`"}`+"\n") // unknown id: ignored
	io.WriteString(owner, strings.Repeat("a", 9000))                          // oversized line
	if m := line(t, cb); m["ok"] != false || !strings.Contains(m["error"].(string), "owner disconnected") {
		t.Fatal(m)
	}
}

func TestMetadataFileLifecycle(t *testing.T) {
	r := start(t, Options{})
	raw, err := os.ReadFile(r.opt.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Version, PID, Port int
		Token              string
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.Version != 1 || m.Port != r.Port() || len(m.Token) != 64 || m.PID != os.Getpid() {
		t.Fatalf("%s %v", raw, err)
	}
	r.Close()
	if _, err := os.Stat(r.opt.Metadata); !os.IsNotExist(err) {
		t.Fatal("metadata left behind")
	}
}

// The Python tty_server client functions must work against the Go relay.
func TestPythonClientInterop(t *testing.T) {
	py, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not installed")
	}
	root, _ := filepath.Abs("../..")
	r := start(t, Options{})
	pub, _ := dial(t, r, authLine(r, `"role":"publish"`), "alpha\nbeta\n")
	_ = pub
	waitFor(t, "published", func() bool { return r.Counts().PublishedBytes == 11 })
	script := "import sys,io\nsys.path.insert(0,sys.argv[1])\nfrom gamebond import tty_server as t\n" +
		"record=t.read_metadata(sys.argv[2])\nout=io.BytesIO()\nt.attach(sys.argv[2],tail=1,duration=.6,output=out)\n" +
		"sys.stdout.write(repr(out.getvalue())+'\\n')\nprint(t.control('status',sys.argv[2],timeout=5,output=io.StringIO()))\n"
	cmd := exec.Command(py, "-c", script, root, r.opt.Metadata)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(string(out), `b'beta\n'`) || !strings.Contains(string(out), "'owner_pid': None") {
		t.Fatalf("unexpected python client output:\n%s", out)
	}
}
