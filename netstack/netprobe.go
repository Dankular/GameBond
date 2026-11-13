package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// This file measures the tunnel from inside the netstack: how long a TCP connection to a few well-known hosts
// takes to open, and how fast data moves with several parallel streams. Every connection is made through the
// userspace stack, so it crosses the bonded tunnel and uses all the links together. Nothing here touches the
// host's own network stack except name resolution.

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ---------------------------------------------------------------- latency to well-known hosts

type pingTarget struct{ Name, Address string }

// pingTargets: a TCP handshake to port 443 is what "ping" means here (ICMP cannot be sent through the tunnel).
var pingTargets = []pingTarget{
	{"Google", "8.8.8.8:443"},
	{"Microsoft", "www.msftconnecttest.com:80"},
	{"Cloudflare", "1.1.1.1:443"},
}

type pingResult struct {
	Name   string  `json:"name"`
	Target string  `json:"target"`
	MS     float64 `json:"ms"`
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
}

// runPings times the TCP connect to each target, one after another.
func runPings(ctx context.Context, dial dialFunc, targets []pingTarget, timeout time.Duration) []pingResult {
	out := make([]pingResult, 0, len(targets))
	for _, t := range targets {
		r := pingResult{Name: t.Name, Target: t.Address}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		conn, err := dial(cctx, "tcp4", t.Address)
		cancel()
		if err != nil {
			r.Error = shortError(err)
		} else {
			r.MS, r.OK = float64(time.Since(start).Microseconds())/1000, true
			conn.Close()
		}
		out = append(out, r)
		if ctx.Err() != nil {
			break
		}
	}
	return out
}

func shortError(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	msg := err.Error()
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return msg
}

// ---------------------------------------------------------------- speed test

type speedConfig struct {
	BaseURL  string        // https://speed.cloudflare.com
	Dial     dialFunc      // through the tunnel
	Streams  int           // parallel connections per direction
	Duration time.Duration // per direction
	Warmup   time.Duration // not counted: TCP slow start and window growth
	MaxBytes int64         // per direction; the test stops early so it cannot use unlimited data
}

func (c *speedConfig) defaults() {
	if c.BaseURL == "" {
		c.BaseURL = "https://speed.cloudflare.com"
	}
	if c.Streams <= 0 {
		c.Streams = 4
	}
	if c.Duration <= 0 {
		c.Duration = 8 * time.Second
	}
	if c.Warmup < 0 || c.Warmup >= c.Duration {
		c.Warmup = c.Duration / 5
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = 250 << 20
	}
}

type speedResult struct {
	DownMbps  float64 `json:"down_mbps"`
	UpMbps    float64 `json:"up_mbps"`
	LatencyMS float64 `json:"latency_ms"`
	JitterMS  float64 `json:"jitter_ms"`
	DownBytes int64   `json:"down_bytes"`
	UpBytes   int64   `json:"up_bytes"`
	Streams   int     `json:"streams"`
	Server    string  `json:"server"`
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// countingReader counts what the HTTP transport takes from it, that is, what has been handed to the connection.
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c speedConfig) client() *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: c.Dial, TLSHandshakeTimeout: 10 * time.Second, MaxIdleConnsPerHost: c.Streams,
		DisableCompression: true, ResponseHeaderTimeout: 15 * time.Second}}
}

// measureLatency times small requests on one connection; the first one pays for the handshake and is dropped.
func measureLatency(ctx context.Context, cl *http.Client, base string) (median, jitter float64, err error) {
	var samples []float64
	for i := 0; i < 6; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/__down?bytes=0", nil)
		start := time.Now()
		resp, err := cl.Do(req)
		if err != nil {
			return 0, 0, err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return 0, 0, fmt.Errorf("the speed server answered HTTP %d", resp.StatusCode)
		}
		if i > 0 {
			samples = append(samples, float64(time.Since(start).Microseconds())/1000)
		}
	}
	sort.Float64s(samples)
	median = samples[len(samples)/2]
	for i := 1; i < len(samples); i++ {
		jitter += abs(samples[i] - samples[i-1])
	}
	return median, jitter / float64(len(samples)-1), nil
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

type sample struct {
	t time.Time
	n int64
}

// rate is the throughput in megabits per second between the first sample taken after the warm-up and the last
// sample. With no sample past the warm-up (a very short run) it falls back to the whole run, so a short test
// still reports something. samples[0] is the start.
func rate(samples []sample, warmup time.Duration) float64 {
	if len(samples) < 2 {
		return 0
	}
	base := samples[0]
	for _, s := range samples {
		if s.t.Sub(samples[0].t) >= warmup {
			base = s
			break
		}
	}
	last := samples[len(samples)-1]
	if span := last.t.Sub(base.t).Seconds(); span > 0 {
		return float64(last.n-base.n) * 8 / 1e6 / span
	}
	if span := last.t.Sub(samples[0].t).Seconds(); span > 0 {
		return float64(last.n-samples[0].n) * 8 / 1e6 / span
	}
	return 0
}

// transfer runs `streams` workers for the configured time (or until MaxBytes) and returns the throughput after the
// warm-up, in megabits per second, and the bytes moved in total.
func (c speedConfig) transfer(ctx context.Context, cl *http.Client, upload bool, progress func(mbps, elapsed float64)) (mbps float64, total int64, err error) {
	var counter atomic.Int64
	tctx, cancel := context.WithTimeout(ctx, c.Duration)
	defer cancel()
	var wg sync.WaitGroup
	var firstErr atomic.Value
	fail := func(e error) { firstErr.CompareAndSwap(nil, e) }
	for i := 0; i < c.Streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tctx.Err() == nil && counter.Load() < c.MaxBytes {
				var req *http.Request
				var rerr error
				if upload {
					req, rerr = http.NewRequestWithContext(tctx, http.MethodPost, c.BaseURL+"/__up", countingReader{io.LimitReader(zeroReader{}, 8<<20), &counter})
					if req != nil {
						req.ContentLength = 8 << 20
					}
				} else {
					req, rerr = http.NewRequestWithContext(tctx, http.MethodGet, fmt.Sprintf("%s/__down?bytes=%d", c.BaseURL, 25<<20), nil)
				}
				if rerr != nil {
					fail(rerr)
					return
				}
				resp, derr := cl.Do(req)
				if derr != nil {
					if tctx.Err() == nil {
						fail(derr)
					}
					return
				}
				if resp.StatusCode != 200 {
					resp.Body.Close()
					fail(fmt.Errorf("the speed server answered HTTP %d", resp.StatusCode))
					return
				}
				if upload {
					io.Copy(io.Discard, resp.Body)
				} else {
					buf := make([]byte, 64<<10)
					for {
						n, rerr := resp.Body.Read(buf)
						counter.Add(int64(n))
						if rerr != nil || tctx.Err() != nil || counter.Load() >= c.MaxBytes {
							break
						}
					}
				}
				resp.Body.Close()
			}
		}()
	}
	start := time.Now()
	samples := []sample{{start, 0}}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var recent []sample
loop:
	for {
		select {
		case <-tctx.Done():
			break loop
		case now := <-tick.C:
			n := counter.Load()
			samples = append(samples, sample{now, n})
			recent = append(recent, sample{now, n})
			for len(recent) > 1 && now.Sub(recent[0].t) > time.Second {
				recent = recent[1:]
			}
			if progress != nil && len(recent) > 1 {
				progress(float64(n-recent[0].n)*8/1e6/now.Sub(recent[0].t).Seconds(), now.Sub(start).Seconds())
			}
			if n >= c.MaxBytes {
				break loop
			}
		}
	}
	samples = append(samples, sample{time.Now(), counter.Load()})
	cancel()
	wg.Wait()
	total = counter.Load()
	if e, _ := firstErr.Load().(error); e != nil && total == 0 {
		return 0, 0, e
	}
	return rate(samples, c.Warmup), total, nil
}

// runSpeedTest measures latency, then download, then upload. progress is told the phase and the current rate.
func runSpeedTest(ctx context.Context, cfg speedConfig, progress func(phase string, mbps, elapsed float64)) (speedResult, error) {
	cfg.defaults()
	if cfg.Dial == nil {
		return speedResult{}, errors.New("no way to reach the network")
	}
	cl := cfg.client()
	defer cl.CloseIdleConnections()
	res := speedResult{Streams: cfg.Streams, Server: hostOf(cfg.BaseURL)}
	var err error
	progress("latency", 0, 0)
	if res.LatencyMS, res.JitterMS, err = measureLatency(ctx, cl, cfg.BaseURL); err != nil {
		return res, fmt.Errorf("latency: %w", err)
	}
	progress("download", 0, 0)
	if res.DownMbps, res.DownBytes, err = cfg.transfer(ctx, cl, false, func(m, e float64) { progress("download", m, e) }); err != nil {
		return res, fmt.Errorf("download: %w", err)
	}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	progress("upload", 0, 0)
	if res.UpMbps, res.UpBytes, err = cfg.transfer(ctx, cl, true, func(m, e float64) { progress("upload", m, e) }); err != nil {
		return res, fmt.Errorf("upload: %w", err)
	}
	return res, ctx.Err()
}

func hostOf(base string) string {
	base = strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if i := strings.IndexByte(base, '/'); i >= 0 {
		base = base[:i]
	}
	return base
}
