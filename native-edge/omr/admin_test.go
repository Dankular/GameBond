package omr

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTunnelSettingsAndPinsMatchPython(t *testing.T) {
	f, err := os.Open("testdata/tunnel-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, _ := gzip.NewReader(f)
	raw, _ := io.ReadAll(zr)
	var doc struct {
		Tunnels []struct {
			Config json.RawMessage `json:"config"`
			Result struct {
				OK       bool    `json:"ok"`
				Key      string  `json:"key"`
				TunnelIP *string `json:"tunnel_ip"`
				Chacha   bool    `json:"chacha"`
			} `json:"result"`
		} `json:"tunnels"`
		Pins []struct {
			Pin json.RawMessage `json:"pin"`
			OK  bool            `json:"ok"`
			Out string          `json:"out"`
		} `json:"pins"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	ok := 0
	for i, c := range doc.Tunnels {
		cfg, err := ParseConfig(c.Config)
		if err != nil {
			t.Fatal(err)
		}
		got, err := TunnelSettings(cfg)
		if (err == nil) != c.Result.OK {
			t.Fatalf("case %d: go err=%v python ok=%v: %s", i, err, c.Result.OK, c.Config)
		}
		if err != nil {
			continue
		}
		ok++
		wantIP := ""
		if c.Result.TunnelIP != nil {
			wantIP = *c.Result.TunnelIP
		}
		if hex.EncodeToString(got.Key) != strings.ToLower(c.Result.Key) || got.TunnelIP != wantIP || got.Chacha != c.Result.Chacha {
			t.Fatalf("case %d: go %+v python %+v: %s", i, got, c.Result, c.Config)
		}
	}
	if ok < 100 || len(doc.Tunnels)-ok < 100 {
		t.Fatalf("vector mix %d/%d", ok, len(doc.Tunnels))
	}
	for _, p := range doc.Pins {
		var s string
		if json.Unmarshal(p.Pin, &s) != nil {
			if p.OK {
				t.Fatal("python accepted a non-string pin")
			}
			continue
		}
		out, err := NormalizePin(s)
		if (err == nil) != p.OK || (err == nil && out != p.Out) {
			t.Fatalf("pin %q: go %q/%v python %q/%v", s, out, err, p.Out, p.OK)
		}
	}
}

type fakeAdmin struct {
	srv       *httptest.Server
	pin       string
	tokens    atomic.Int32
	configs   atomic.Int32
	badLogins atomic.Int32
	cfg       string
}

func newFakeAdmin(t *testing.T) (*fakeAdmin, string, int) {
	t.Helper()
	fa := &fakeAdmin{cfg: `{"glorytun":{"key":"` + strings.Repeat("ab", 32) + `","udp":{"client_ip":"10.255.254.7"},"chacha":true,"port":9}}`}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		fa.tokens.Add(1)
		r.ParseForm()
		if r.Method != "POST" || r.PostForm.Get("username") != "admin" || r.PostForm.Get("password") != "s3cret &=" {
			fa.badLogins.Add(1)
			http.Error(w, `{"detail":"bad"}`, 400)
			return
		}
		w.Write([]byte(`{"access_token":"tok123","token_type":"bearer"}`))
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		fa.configs.Add(1)
		if r.Header.Get("Authorization") != "Bearer tok123" {
			http.Error(w, "no", 401)
			return
		}
		w.Write([]byte(fa.cfg))
	})
	fa.srv = httptest.NewUnstartedServer(mux)
	fa.srv.TLS = &tls.Config{}
	fa.srv.StartTLS()
	t.Cleanup(fa.srv.Close)
	pin, err := SPKIPin(fa.srv.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	fa.pin = pin
	host, portS, _ := net.SplitHostPort(fa.srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portS)
	return fa, host, port
}

func TestAdminLoginAndConfig(t *testing.T) {
	fa, host, port := newFakeAdmin(t)
	learned, err := LearnPin(host, port, 3*time.Second)
	if err != nil || learned != fa.pin {
		t.Fatalf("learned %q %v want %q", learned, err, fa.pin)
	}
	a, err := NewAdminClient(host, port, "sha256//"+fa.pin, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetConfig(); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("config before login: %v", err)
	}
	if err := a.Login("admin", "s3cret &="); err != nil {
		t.Fatal(err)
	}
	cfg, err := a.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	tun, err := TunnelSettings(cfg)
	if err != nil || tun.TunnelIP != "10.255.254.7" || !tun.Chacha || len(tun.Key) != 32 || tun.Key[0] != 0xab {
		t.Fatalf("%+v %v", tun, err)
	}
}

func TestAdminWrongPinSendsNothing(t *testing.T) {
	fa, host, port := newFakeAdmin(t)
	wrong := strings.Repeat("B", 43) + "="
	a, _ := NewAdminClient(host, port, wrong, 3*time.Second)
	err := a.Login("admin", "s3cret &=")
	if !errors.Is(err, ErrPin) {
		t.Fatalf("want ErrPin, got %v", err)
	}
	if fa.tokens.Load() != 0 {
		t.Fatal("credentials reached a server with the wrong key")
	}
	if _, err := NewAdminClient(host, port, "", time.Second); !errors.Is(err, ErrPin) {
		t.Fatalf("empty pin: %v", err)
	}
	if _, err := NewAdminClient(host, port, "garbage", time.Second); err == nil {
		t.Fatal("garbage pin accepted")
	}
}

func TestAdminRefusedLoginAndExpiredToken(t *testing.T) {
	fa, host, port := newFakeAdmin(t)
	a, _ := NewAdminClient(host, port, fa.pin, 3*time.Second)
	if err := a.Login("admin", "wrong"); !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
	if fa.badLogins.Load() != 1 {
		t.Fatal("a refused login must be a single attempt")
	}
	a.Login("admin", "s3cret &=")
	a.token = "stale"
	if _, err := a.GetConfig(); !errors.Is(err, ErrAuth) || a.token != "" {
		t.Fatalf("stale token: %v token=%q", err, a.token)
	}
}

func TestAdminRejectsOversizeAndBadJSON(t *testing.T) {
	fa, host, port := newFakeAdmin(t)
	a, _ := NewAdminClient(host, port, fa.pin, 3*time.Second)
	a.Login("admin", "s3cret &=")
	fa.cfg = strings.Repeat("x", 2*1024*1024+10)
	if _, err := a.GetConfig(); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversize: %v", err)
	}
	fa.cfg = `{"glorytun": `
	if _, err := a.GetConfig(); err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("bad json: %v", err)
	}
	fa.cfg = `[1]`
	if _, err := a.GetConfig(); err == nil || !strings.Contains(err.Error(), "unexpected /config") {
		t.Fatalf("non-dict: %v", err)
	}
}

// Our pin must equal Python's spki_pin for the same certificate.
func TestSPKIPinMatchesPython(t *testing.T) {
	py, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python missing")
	}
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "gamebond", "omr_admin.py")); err != nil {
		t.Skip("python package missing")
	}
	fa, _, _ := newFakeAdmin(t)
	der := filepath.Join(t.TempDir(), "c.der")
	os.WriteFile(der, fa.srv.Certificate().Raw, 0o600)
	script := "import sys;sys.path.insert(0,sys.argv[1]);from gamebond.omr_admin import spki_pin;print(spki_pin(open(sys.argv[2],'rb').read()))"
	out, err := exec.Command(py, "-c", script, root, der).Output()
	if err != nil || string(bytes.TrimSpace(out)) != fa.pin {
		t.Fatalf("python %q err=%v go %q", out, err, fa.pin)
	}
}
