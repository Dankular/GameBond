package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// emitEvent sends one JSON record to the daemon (frame endpoint 2). Tests replace it.
var emitEvent = func(v any) {
	raw, err := json.Marshal(v)
	if err == nil && len(raw) <= 65535 {
		_ = writeFrame(2, raw)
	}
}

const (
	pingEvery     = 10 * time.Second
	pingTimeout   = 3 * time.Second
	speedTimeout  = 90 * time.Second // the whole test, however it goes
	speedCooldown = 5 * time.Second
)

// stackDialer connects through the userspace stack, by the stream gateway when it is healthy (as application
// traffic does). Host names are resolved by the operating system and cached for a minute: the answer only chooses
// an address, the connection itself always goes through the tunnel.
func stackDialer(stack *netstack.Net) dialFunc {
	type entry struct {
		ip netip.Addr
		at time.Time
	}
	var mu sync.Mutex
	cache := map[string]entry{}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return nil, err
		}
		ip, perr := netip.ParseAddr(host)
		if perr != nil {
			mu.Lock()
			e, ok := cache[host]
			mu.Unlock()
			if ok && time.Since(e.at) < time.Minute {
				ip = e.ip
			} else {
				addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
				if err != nil || len(addrs) == 0 {
					return nil, errors.New("could not resolve " + host)
				}
				ip = addrs[0]
				mu.Lock()
				cache[host] = entry{ip, time.Now()}
				mu.Unlock()
			}
		}
		target := netip.AddrPortFrom(ip.Unmap(), uint16(port))
		if !validTarget(target) {
			return nil, errors.New("not a usable destination")
		}
		return dialTCP(ctx, stack, target)
	}
}

// probeRunner owns the periodic pings and the one speed test that may run at a time.
type probeRunner struct {
	dial dialFunc
	mu   sync.Mutex
	// speed test state
	cancel  context.CancelFunc
	running bool
	lastEnd time.Time
	// speed is the configuration a test starts from; tests override it.
	speed speedConfig
}

var probes struct {
	mu sync.Mutex
	r  *probeRunner
}

func currentProbes() *probeRunner {
	probes.mu.Lock()
	defer probes.mu.Unlock()
	return probes.r
}

// startNetProbes begins the ping loop and makes speed tests available.
func startNetProbes(ctx context.Context, stack *netstack.Net) {
	r := newProbeRunner(stackDialer(stack))
	probes.mu.Lock()
	probes.r = r
	probes.mu.Unlock()
	go r.pingLoop(ctx)
}

func newProbeRunner(dial dialFunc) *probeRunner {
	cfg := speedConfig{Dial: dial, BaseURL: os.Getenv("GAMEBOND_SPEEDTEST_URL")}
	if mb, err := strconv.Atoi(os.Getenv("GAMEBOND_SPEEDTEST_MAX_MB")); err == nil && mb > 0 {
		cfg.MaxBytes = int64(mb) << 20
	}
	return &probeRunner{dial: dial, speed: cfg}
}

func (r *probeRunner) busy() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

func (r *probeRunner) pingLoop(ctx context.Context) {
	t := time.NewTimer(4 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !r.busy() { // a speed test fills the queues, so a ping taken now would only measure the test
			emitEvent(map[string]any{"type": "internet_ping", "at": time.Now().Unix(), "results": runPings(ctx, r.dial, pingTargets, pingTimeout)})
		}
		t.Reset(pingEvery)
	}
}

func speedFail(id, msg string) {
	emitEvent(map[string]any{"type": "speedtest_result", "id": id, "ok": false, "error": msg, "at": time.Now().Unix()})
}

// startSpeed runs one test in the background, reporting progress and finally the result.
func (r *probeRunner) startSpeed(id string) {
	r.mu.Lock()
	switch {
	case r.running:
		r.mu.Unlock()
		speedFail(id, "a speed test is already running")
		return
	case time.Since(r.lastEnd) < speedCooldown:
		r.mu.Unlock()
		speedFail(id, "wait a few seconds between speed tests")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), speedTimeout)
	r.cancel, r.running = cancel, true
	cfg := r.speed
	r.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			r.mu.Lock()
			r.running, r.cancel, r.lastEnd = false, nil, time.Now()
			r.mu.Unlock()
		}()
		var lastEmit time.Time
		res, err := runSpeedTest(ctx, cfg, func(phase string, mbps, elapsed float64) {
			if time.Since(lastEmit) < 500*time.Millisecond && elapsed > 0 {
				return
			}
			lastEmit = time.Now()
			emitEvent(map[string]any{"type": "speedtest_progress", "id": id, "phase": phase, "mbps": mbps, "elapsed_s": elapsed})
		})
		if err != nil {
			msg := shortError(err)
			if errors.Is(err, context.Canceled) {
				msg = "cancelled"
			}
			speedFail(id, msg)
			return
		}
		emitEvent(map[string]any{"type": "speedtest_result", "id": id, "ok": true, "at": time.Now().Unix(), "down_mbps": res.DownMbps, "up_mbps": res.UpMbps,
			"latency_ms": res.LatencyMS, "jitter_ms": res.JitterMS, "down_bytes": res.DownBytes, "up_bytes": res.UpBytes, "streams": res.Streams, "server": res.Server})
	}()
}

func (r *probeRunner) cancelSpeed() {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// handleControlFrame takes the JSON the daemon sends to the helper: speed test requests and cancels, and
// everything else is an application authorization answer.
func handleControlFrame(packet []byte) {
	var head struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	if json.Unmarshal(packet, &head) != nil {
		return
	}
	switch head.Type {
	case "speedtest_request":
		if r := currentProbes(); r != nil && len(head.ID) <= 64 {
			r.startSpeed(head.ID)
		} else {
			speedFail(head.ID, "speed tests are not available in this mode")
		}
	case "speedtest_cancel":
		if r := currentProbes(); r != nil {
			r.cancelSpeed()
		}
	default:
		handleAppAuthorizationFrame(packet)
	}
}
