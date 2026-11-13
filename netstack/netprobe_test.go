package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func plainDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// speedServer serves /__down and /__up like the real thing, optionally limited to about mbps megabits per
// second per connection and with an artificial delay on every request.
func speedServer(t *testing.T, mbps float64, delay time.Duration) (*httptest.Server, *atomic.Int64, *atomic.Int64) {
	var sent, got atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/__down", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		n, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		chunk := make([]byte, 16<<10)
		for n > 0 {
			k := int64(len(chunk))
			if k > n {
				k = n
			}
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			sent.Add(k)
			n -= k
			if mbps > 0 {
				time.Sleep(time.Duration(float64(k) * 8 / (mbps * 1e6) * float64(time.Second)))
			}
		}
	})
	mux.HandleFunc("/__up", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		buf := make([]byte, 16<<10)
		for {
			k, err := r.Body.Read(buf)
			got.Add(int64(k))
			if mbps > 0 {
				time.Sleep(time.Duration(float64(k) * 8 / (mbps * 1e6) * float64(time.Second)))
			}
			if err != nil {
				break
			}
		}
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &sent, &got
}

func quickConfig(base string) speedConfig {
	return speedConfig{BaseURL: base, Dial: plainDial, Streams: 2, Duration: 1500 * time.Millisecond, Warmup: 300 * time.Millisecond}
}

func TestSpeedTestMeasuresARateLimitedServer(t *testing.T) {
	srv, _, _ := speedServer(t, 20, 0) // about 20 Mbps per connection, two connections: about 40 Mbps
	var phases []string
	res, err := runSpeedTest(context.Background(), quickConfig(srv.URL), func(phase string, _, _ float64) {
		if len(phases) == 0 || phases[len(phases)-1] != phase {
			phases = append(phases, phase)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(phases, ",") != "latency,download,upload" {
		t.Fatalf("phases: %v", phases)
	}
	for name, v := range map[string]float64{"download": res.DownMbps, "upload": res.UpMbps} {
		if v < 20 || v > 60 { // wide: CI machines are noisy, the point is the right order of magnitude
			t.Errorf("%s = %.1f Mbps, expected roughly 40", name, v)
		}
	}
	if res.DownBytes <= 0 || res.UpBytes <= 0 || res.Streams != 2 || res.Server == "" {
		t.Fatalf("%+v", res)
	}
}

func TestLatencyReflectsTheServerDelay(t *testing.T) {
	srv, _, _ := speedServer(t, 0, 25*time.Millisecond)
	ms, _, err := measureLatency(context.Background(), speedConfig{Dial: plainDial, Streams: 1}.client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if ms < 22 || ms > 120 {
		t.Fatalf("latency %.1f ms with a 25 ms server delay", ms)
	}
}

func TestSpeedTestStopsAtTheByteCap(t *testing.T) {
	srv, sent, _ := speedServer(t, 0, 0) // as fast as the loopback allows
	cfg := quickConfig(srv.URL)
	cfg.Duration, cfg.MaxBytes = 10*time.Second, 4<<20
	start := time.Now()
	res, err := runSpeedTest(context.Background(), cfg, func(string, float64, float64) {})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 8*time.Second {
		t.Fatalf("the cap did not end the test early: %v", time.Since(start))
	}
	if res.DownBytes > 4<<20+2*(25<<20) || sent.Load() > 200<<20 {
		t.Fatalf("far more data than the cap allows: %d received, %d sent", res.DownBytes, sent.Load())
	}
}

func TestSpeedTestCanBeCancelled(t *testing.T) {
	srv, _, _ := speedServer(t, 5, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cfg := quickConfig(srv.URL)
	cfg.Duration = 20 * time.Second
	go func() { time.Sleep(700 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := runSpeedTest(ctx, cfg, func(string, float64, float64) {})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("cancel: err=%v after %v", err, time.Since(start))
	}
}

func TestSpeedTestReportsAnUnreachableServer(t *testing.T) {
	cfg := quickConfig("http://127.0.0.1:1")
	if _, err := runSpeedTest(context.Background(), cfg, func(string, float64, float64) {}); err == nil || !strings.Contains(err.Error(), "latency") {
		t.Fatalf("err = %v", err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := runSpeedTest(context.Background(), quickConfig(srv.URL), func(string, float64, float64) {}); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("a server without the speed endpoints must be reported: %v", err)
	}
}

func TestRateUsesTheWindowAfterWarmup(t *testing.T) {
	t0 := time.Unix(1000, 0)
	// 1 MB in the first second (slow start), then 1 MB per second: the rate after a 1 s warm-up is 8 Mbps.
	s := []sample{{t0, 0}, {t0.Add(time.Second), 1 << 20}, {t0.Add(2 * time.Second), 2 << 20}, {t0.Add(3 * time.Second), 3 << 20}}
	if got := rate(s, time.Second); got < 8.3 || got > 8.5 {
		t.Fatalf("rate = %.2f", got)
	}
	if got := rate(s[:2], 5*time.Second); got < 8.3 || got > 8.5 { // never left the warm-up: whole run
		t.Fatalf("short run rate = %.2f", got)
	}
	if rate(nil, time.Second) != 0 || rate(s[:1], time.Second) != 0 {
		t.Fatal("no samples, no rate")
	}
}

func TestPingsTimeTCPConnects(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	targets := []pingTarget{{"Up", l.Addr().String()}, {"Down", "127.0.0.1:1"}}
	out := runPings(context.Background(), plainDial, targets, time.Second)
	if len(out) != 2 || !out[0].OK || out[0].MS <= 0 || out[1].OK || out[1].Error == "" {
		t.Fatalf("%+v", out)
	}
}

func TestPingTimeoutIsHonoured(t *testing.T) {
	slow := func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	start := time.Now()
	out := runPings(context.Background(), slow, []pingTarget{{"Slow", "203.0.113.1:443"}}, 200*time.Millisecond)
	if time.Since(start) > 2*time.Second || out[0].OK || out[0].Error != "timed out" {
		t.Fatalf("%+v after %v", out, time.Since(start))
	}
}

// capture replaces emitEvent for a test and returns what was emitted.
type capture struct {
	mu     sync.Mutex
	events []map[string]any
}

func (c *capture) install(t *testing.T) {
	old := emitEvent
	emitEvent = func(v any) {
		raw, _ := json.Marshal(v)
		var m map[string]any
		json.Unmarshal(raw, &m)
		c.mu.Lock()
		c.events = append(c.events, m)
		c.mu.Unlock()
	}
	t.Cleanup(func() { emitEvent = old })
}

func (c *capture) find(kind, id string) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e["type"] == kind && e["id"] == id {
			return e
		}
	}
	return nil
}

func (c *capture) waitFor(t *testing.T, kind, id string) map[string]any {
	t.Helper()
	for i := 0; i < 200; i++ {
		if e := c.find(kind, id); e != nil {
			return e
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no %s for %s; events: %v", kind, id, c.events)
	return nil
}

func installRunner(t *testing.T, base string) *probeRunner {
	r := newProbeRunner(plainDial)
	r.speed = quickConfig(base)
	probes.mu.Lock()
	old := probes.r
	probes.r = r
	probes.mu.Unlock()
	t.Cleanup(func() { probes.mu.Lock(); probes.r = old; probes.mu.Unlock() })
	return r
}

func TestControlFrameRunsASpeedTestAndReportsIt(t *testing.T) {
	var c capture
	c.install(t)
	srv, _, _ := speedServer(t, 30, 0)
	installRunner(t, srv.URL)
	handleControlFrame([]byte(`{"type":"speedtest_request","id":"t1"}`))
	res := c.waitFor(t, "speedtest_result", "t1")
	if res["ok"] != true || res["down_mbps"].(float64) <= 0 || res["up_mbps"].(float64) <= 0 || res["latency_ms"].(float64) <= 0 || res["server"] == "" {
		t.Fatalf("%v", res)
	}
	if c.find("speedtest_progress", "t1") == nil {
		t.Fatal("progress was never reported")
	}
}

func TestOnlyOneSpeedTestAtATimeAndACooldown(t *testing.T) {
	var c capture
	c.install(t)
	srv, _, _ := speedServer(t, 10, 0)
	r := installRunner(t, srv.URL)
	handleControlFrame([]byte(`{"type":"speedtest_request","id":"a"}`))
	time.Sleep(200 * time.Millisecond)
	handleControlFrame([]byte(`{"type":"speedtest_request","id":"b"}`))
	if e := c.waitFor(t, "speedtest_result", "b"); e["ok"] != false || !strings.Contains(e["error"].(string), "already running") {
		t.Fatalf("a second test must be refused while one runs: %v", e)
	}
	c.waitFor(t, "speedtest_result", "a")
	for i := 0; i < 40 && r.busy(); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	handleControlFrame([]byte(`{"type":"speedtest_request","id":"c"}`))
	if e := c.waitFor(t, "speedtest_result", "c"); e["ok"] != false || !strings.Contains(e["error"].(string), "wait") {
		t.Fatalf("back-to-back tests must be refused: %v", e)
	}
}

func TestSpeedTestCancelFrame(t *testing.T) {
	var c capture
	c.install(t)
	srv, _, _ := speedServer(t, 5, 0)
	r := installRunner(t, srv.URL)
	r.speed.Duration = 30 * time.Second
	handleControlFrame([]byte(`{"type":"speedtest_request","id":"x"}`))
	time.Sleep(600 * time.Millisecond)
	handleControlFrame([]byte(`{"type":"speedtest_cancel"}`))
	if e := c.waitFor(t, "speedtest_result", "x"); e["ok"] != false || e["error"] != "cancelled" {
		t.Fatalf("%v", e)
	}
}

func TestSpeedTestWithoutAHelperModeIsReported(t *testing.T) {
	var c capture
	c.install(t)
	probes.mu.Lock()
	old := probes.r
	probes.r = nil
	probes.mu.Unlock()
	defer func() { probes.mu.Lock(); probes.r = old; probes.mu.Unlock() }()
	handleControlFrame([]byte(`{"type":"speedtest_request","id":"n"}`))
	if e := c.find("speedtest_result", "n"); e == nil || e["ok"] != false {
		t.Fatalf("%v", e)
	}
	handleControlFrame([]byte(`not json`))                              // must not panic
	handleControlFrame([]byte(`{"type":"app_authorization_response"}`)) // goes to the authorization handler, which ignores a malformed one
}

func TestRunnerIsBusyWhileATestRuns(t *testing.T) {
	var c capture
	c.install(t)
	srv, _, _ := speedServer(t, 10, 0)
	r := installRunner(t, srv.URL)
	r.speed.Duration = 3 * time.Second
	handleControlFrame([]byte(`{"type":"speedtest_request","id":"p"}`))
	time.Sleep(200 * time.Millisecond)
	if !r.busy() {
		t.Fatal("the test should be running")
	}
	r.mu.Lock()
	r.cancel()
	r.mu.Unlock()
	c.waitFor(t, "speedtest_result", "p")
}
