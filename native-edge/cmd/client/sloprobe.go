package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/promexport"
	"gamebond.local/nativeedge/slo"
	"gamebond.local/nativeedge/store"
	"github.com/Dankular/GameBond.Core/bond"
)

// sloRuntime sends the in-tunnel echo probes, keeps their outcome in a small SQLite file, evaluates
// the objectives and serves the Prometheus endpoint. It is optional: with slo_probe off only the
// metrics endpoint (if configured) runs and the probe series are absent.
type sloRuntime struct {
	tracker *slo.Tracker
	prober  *slo.Prober
	db      *sql.DB
	eval    atomic.Pointer[slo.Evaluation]

	lastRecv atomic.Int64 // unix nanos of the last answered probe's arrival
	mu       sync.Mutex
	pending  *pendingSwitch
}

type pendingSwitch struct {
	at       time.Time
	lastGood time.Time
	detail   string
}

// sloSink wraps the tracker so the runtime also learns when traffic last came back.
type sloSink struct {
	*slo.Tracker
	r *sloRuntime
}

func (s sloSink) Received(sent time.Time, rtt time.Duration) {
	s.Tracker.Received(sent, rtt)
	arrived := sent.Add(rtt)
	s.r.lastRecv.Store(arrived.UnixNano())
	s.r.mu.Lock()
	p := s.r.pending
	if p != nil && arrived.After(p.at) {
		s.r.pending = nil
		s.r.mu.Unlock()
		// Restoration time is the traffic blackout: last answered probe before the switch until the
		// first answered probe after it.
		s.Tracker.Event(arrived, "failover", p.detail, arrived.Sub(p.lastGood))
		return
	}
	s.r.mu.Unlock()
}

// NoteSwitch records an exit failover; its restoration time is settled by the next answered probe.
func (r *sloRuntime) NoteSwitch(from, to netip.AddrPort, reason string) {
	if r == nil {
		return
	}
	now := time.Now()
	good := time.Unix(0, r.lastRecv.Load())
	if r.lastRecv.Load() == 0 {
		good = now
	}
	detail := fmt.Sprintf("%s -> %s (%s)", from, to, reason)
	r.tracker.Event(now, "exit-switch", detail, 0)
	r.mu.Lock()
	r.pending = &pendingSwitch{at: now, lastGood: good, detail: detail}
	r.mu.Unlock()
}

// Handle lets the delivery path hand echo replies to the prober. It reports whether it consumed pkt.
func (r *sloRuntime) Handle(pkt []byte) bool {
	if r == nil || r.prober == nil {
		return false
	}
	return r.prober.Handle(pkt, time.Now())
}

type sloOptions struct {
	Probe    bool
	Interval time.Duration
	Src, Dst netip.Addr
	DBPath   string
	Metrics  string // loopback listen address, or empty
}

func loopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("metrics_addr %q must be a loopback address", addr)
	}
	return nil
}

func newSLO(o sloOptions) (*sloRuntime, error) {
	r := &sloRuntime{}
	var db *sql.DB
	if o.DBPath != "" {
		var err error
		if db, err = store.Open(o.DBPath, []string{slo.Schema}); err != nil {
			return nil, fmt.Errorf("slo database: %w", err)
		}
	}
	r.db = db
	r.tracker = slo.NewTracker(db)
	if o.Probe {
		r.prober = slo.NewProber(slo.ProbeConfig{Src: o.Src, Dst: o.Dst, ID: 0x6742, Size: 100, Timeout: time.Second}, sloSink{r.tracker, r})
	}
	return r, nil
}

// run drives probes, settles and flushes outcomes, refreshes the evaluation and serves /metrics.
func (r *sloRuntime) run(ctx context.Context, o sloOptions, up gbUplink, snap func() client.Snapshot, alarms func() []bond.Alarm, logOut io.Writer) {
	if r.prober != nil {
		go func() {
			t := time.NewTicker(o.Interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-t.C:
					up.Submit(bond.QueuedPacket{Payload: r.prober.Build(now), Flow: "slo-probe", Priority: true, Replicate: true, Expires: now.Add(time.Second)})
				}
			}
		}()
	}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var lastEval time.Time
		for {
			select {
			case <-ctx.Done():
				_ = r.tracker.Flush(time.Now().Add(time.Hour), 0)
				return
			case now := <-t.C:
				if r.prober != nil {
					r.prober.Expire(now)
				}
				if err := r.tracker.Flush(now, 3*time.Second); err != nil {
					fmt.Fprintln(logOut, "slo flush failed:", err)
				}
				if r.db != nil && r.prober != nil && now.Sub(lastEval) >= 30*time.Second {
					lastEval = now
					if ev, err := slo.Evaluate(r.db, now, slo.DefaultObjectives()); err == nil {
						r.eval.Store(&ev)
					}
				}
			}
		}
	}()
	if o.Metrics == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		in := promexport.Input{Snap: snap(), Alarms: alarms(), Eval: r.eval.Load()}
		if r.prober != nil {
			t := r.tracker.Totals()
			in.Totals = &t
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		if err := promexport.Write(w, in); err != nil {
			fmt.Fprintln(logOut, "metrics scrape failed:", err)
		}
	})
	srv := &http.Server{Addr: o.Metrics, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(logOut, "metrics endpoint:", err)
		}
	}()
}

// finite maps +Inf (the open top histogram bucket) and NaN to nil, which JSON can carry.
func finite(v float64) any {
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return nil
	}
	return v
}

func indicatorDoc(i slo.Indicator) map[string]any {
	return map[string]any{"good": i.Good, "total": i.Total, "ratio": finite(i.Ratio), "burn_rate": finite(i.BurnRate), "met": i.Met}
}

// status is the "slo" section of the status document. Keys are stable: the tray's alert watcher and
// the dashboard read them.
func (r *sloRuntime) status() map[string]any {
	if r == nil || r.prober == nil {
		return map[string]any{"enabled": false}
	}
	doc := map[string]any{"enabled": true}
	t := r.tracker.Totals()
	doc["sent"], doc["received"], doc["lost"] = t.Sent, t.Received, t.Lost
	if ev := r.eval.Load(); ev != nil {
		ws := make([]map[string]any, 0, len(ev.Windows))
		for _, w := range ev.Windows {
			ws = append(ws, map[string]any{
				"window_hours": w.Window.Hours(), "measured_hours": w.Measured.Hours(), "sent": w.Sent, "lost": w.Lost, "late": w.Late,
				"loss_ratio": finite(w.LossRatio), "loss_upper_95": finite(w.LossUpper95),
				"rtt_p50_ms": finite(w.P50), "rtt_p95_ms": finite(w.P95), "rtt_p99_ms": finite(w.P99),
				"delivery_ratio": finite(w.Delivery.Ratio), "delivery_burn_rate": finite(w.Delivery.BurnRate), "delivery_met": w.Delivery.Met,
				"availability_ratio": finite(w.Availability.Ratio), "availability_burn_rate": finite(w.Availability.BurnRate), "availability_met": w.Availability.Met,
				"latency_ratio": finite(w.Latency.Ratio), "latency_burn_rate": finite(w.Latency.BurnRate), "latency_met": w.Latency.Met,
			})
		}
		doc["evaluation"] = map[string]any{
			"at": float64(ev.At.UnixNano()) / 1e9, "windows": ws, "error_budget_left": finite(ev.BudgetLeft),
			"failovers": map[string]any{"count": ev.Failovers.Count, "p95_s": ev.Failovers.P95.Seconds(), "max_s": ev.Failovers.Max.Seconds(), "met": ev.Failovers.Met},
		}
	}
	return doc
}
