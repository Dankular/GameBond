package ttyrelay

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startWithMeta(t *testing.T) (*Relay, string) {
	r := start(t, Options{})
	return r, r.opt.Metadata
}

func TestReadMetadataValidation(t *testing.T) {
	_, path := startWithMeta(t)
	rec, err := ReadMetadata(path)
	if err != nil || rec.Port == 0 || len(rec.Token) != 64 || rec.PID != os.Getpid() {
		t.Fatalf("%+v %v", rec, err)
	}
	tok := strings.Repeat("a", 64)
	cases := map[string]bool{
		`{"version":1,"pid":5,"port":80,"token":"` + tok + `"}`:          true,
		`{"version":true,"pid":5,"port":80,"token":"` + tok + `"}`:       true,
		`{"version":1.0,"port":80,"token":"` + tok + `"}`:                true,
		"\xef\xbb\xbf" + `{"version":1,"port":80,"token":"` + tok + `"}`: true,
		`{"version":2,"port":80,"token":"` + tok + `"}`:                  false,
		`{"version":"1","port":80,"token":"` + tok + `"}`:                false,
		`{"version":1,"port":0,"token":"` + tok + `"}`:                   false,
		`{"version":1,"port":65536,"token":"` + tok + `"}`:               false,
		`{"version":1,"port":80.5,"token":"` + tok + `"}`:                false,
		`{"version":1,"port":"80","token":"` + tok + `"}`:                false,
		`{"version":1,"port":true,"token":"` + tok + `"}`:                false,
		`{"version":1,"port":80,"token":"` + tok[:63] + `"}`:             false,
		`{"version":1,"port":80,"token":5}`:                              false,
		`{"version":1,"port":80}`:                                        false,
		`[]`:                                                             false,
		`null`:                                                           false,
		`{`:                                                              false,
		`{"version":1,"port":80,"token":"` + tok + `","pad":"` + strings.Repeat("x", 4100) + `"}`: false,
	}
	dir := t.TempDir()
	for text, want := range cases {
		p := filepath.Join(dir, "m.json")
		os.WriteFile(p, []byte(text), 0o600)
		if _, err := ReadMetadata(p); (err == nil) != want {
			t.Errorf("%.80q: ok=%v, want %v (%v)", text, err == nil, want, err)
		}
	}
	if _, err := ReadMetadata(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestConnectRejectsWrongToken(t *testing.T) {
	r, path := startWithMeta(t)
	rec, _ := ReadMetadata(path)
	c, err := Connect(rec, "attach", map[string]any{"tail": 0})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	rec.Token = strings.Repeat("0", 64)
	if c, err := Connect(rec, "attach", nil); err == nil {
		c.Close()
		t.Fatal("wrong token accepted")
	}
	_ = r
}

func TestAttachSeesPublishedTailAndLive(t *testing.T) {
	_, path := startWithMeta(t)
	rec, _ := ReadMetadata(path)
	pub, err := Connect(rec, "publish", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	pub.Write([]byte("one\ntwo\n"))
	time.Sleep(200 * time.Millisecond)

	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- Attach(path, 10, 1500*time.Millisecond, &out) }()
	time.Sleep(400 * time.Millisecond)
	pub.Write([]byte("three\n"))
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "one\ntwo\nthree\n" {
		t.Fatalf("attach output %q", got)
	}
	if err := Attach(path, -1, time.Second, &out); err == nil {
		t.Error("negative tail accepted")
	}
	if err := Attach(path, 5001, time.Second, &out); err == nil {
		t.Error("tail 5001 accepted")
	}
	if err := Attach(path, 1, 0, &out); err == nil {
		t.Error("zero duration accepted")
	}
	if err := Attach(path, 1, 3601*time.Second, &out); err == nil {
		t.Error("oversized duration accepted")
	}
}

func TestControlStatusViaClient(t *testing.T) {
	_, path := startWithMeta(t)
	var out bytes.Buffer
	msg, err := Control(path, "status", 5*time.Second, &out)
	if err != nil || msg["complete"] != true || msg["state"] != "unavailable" {
		t.Fatalf("%v %v", msg, err)
	}
	if !strings.Contains(out.String(), `"complete":true`) {
		t.Fatalf("output %q", out.String())
	}
	msg, err = Control(path, "stop", 5*time.Second, &out)
	if err != nil || msg["ok"] != false {
		t.Fatalf("%v %v", msg, err)
	}
	for _, bad := range []struct {
		cmd string
		d   time.Duration
	}{{"reboot", time.Second}, {"status", 0}, {"status", 181 * time.Second}} {
		if _, err := Control(path, bad.cmd, bad.d, &out); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
