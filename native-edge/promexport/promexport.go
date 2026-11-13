// Package promexport renders the client's state in the Prometheus text format. Counters end in
// _total, gauges do not, and every name starts with gamebond_. The alert rules under ops/ are
// checked against this output by a test, so a rule cannot refer to a metric that does not exist.
package promexport

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/slo"
	"github.com/Dankular/GameBond.Core/bond"
)

// Input is everything one scrape reports. Eval and Totals may be nil when the probe is off.
type Input struct {
	Snap   client.Snapshot
	Alarms []bond.Alarm
	Totals *slo.Totals
	Eval   *slo.Evaluation
	// Extra carries samples the caller owns (the soak harness's fault state, for example).
	Extra []Sample
}

// Sample is one line of output.
type Sample struct {
	Name, Help, Type string // Type: counter or gauge
	Labels           map[string]string
	Value            float64
}

type writer struct {
	w    io.Writer
	seen map[string]bool
	err  error
}

func (o *writer) put(name, help, typ string, labels map[string]string, v float64) {
	if o.err != nil {
		return
	}
	// Histogram series share one family: the TYPE line names the family, not the _bucket suffix.
	family := strings.TrimSuffix(name, "_bucket")
	if !o.seen[family] {
		o.seen[family] = true
		_, o.err = fmt.Fprintf(o.w, "# HELP %s %s\n# TYPE %s %s\n", family, help, family, typ)
	}
	_, o.err = fmt.Fprintf(o.w, "%s%s %s\n", name, labelString(labels), num(v))
}

func num(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func labelString(l map[string]string) string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", k, l[k])
	}
	b.WriteByte('}')
	return b.String()
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Write renders in.
func Write(w io.Writer, in Input) error {
	o := &writer{w: w, seen: map[string]bool{}}
	s := in.Snap
	ready := 0
	for _, p := range s.Paths {
		l := map[string]string{"slot": strconv.Itoa(p.Local)}
		if p.Ready {
			ready++
		}
		o.put("gamebond_path_ready", "1 when the path has completed its handshake and is hearing the server.", "gauge", l, b2f(p.Ready))
		o.put("gamebond_path_healthy", "1 when the path is ready and not suspected.", "gauge", l, b2f(p.Healthy))
		o.put("gamebond_path_suspect", "1 when the sender suspects the path and avoids it for bulk.", "gauge", l, b2f(p.Suspect))
		o.put("gamebond_path_rtt_ms", "Smoothed round-trip time of the path.", "gauge", l, p.RTTMilliseconds)
		o.put("gamebond_path_jitter_ms", "Round-trip jitter of the path.", "gauge", l, p.JitterMilliseconds)
		o.put("gamebond_path_wire_tx_bytes_total", "Bytes sent on the path, headers included.", "counter", l, float64(p.WireTX))
		o.put("gamebond_path_wire_rx_bytes_total", "Bytes received on the path, headers included.", "counter", l, float64(p.WireRX))
		state, _ := p.BFD["state"].(string)
		o.put("gamebond_path_bfd_up", "1 when BFD reports the path up in both directions.", "gauge", l, b2f(state == "up"))
		if d, ok := p.BFD["downs"].(uint64); ok {
			o.put("gamebond_path_bfd_downs_total", "Times BFD declared the path down.", "counter", l, float64(d))
		}
	}
	o.put("gamebond_paths_ready", "Number of paths ready.", "gauge", nil, float64(ready))
	o.put("gamebond_paths_configured", "Number of uplink slots.", "gauge", nil, float64(len(s.Paths)))
	r := s.Receiver
	o.put("gamebond_rx_frames_authenticated_total", "Authenticated frames received.", "counter", nil, float64(r.Authenticated))
	o.put("gamebond_rx_authentication_errors_total", "Frames rejected by authentication.", "counter", nil, float64(r.AuthenticationErrors))
	o.put("gamebond_rx_duplicates_total", "Second copies discarded: redundancy working, not loss.", "counter", nil, float64(r.Duplicates))
	o.put("gamebond_rx_replay_too_old_total", "Frames dropped as older than the replay window.", "counter", nil, float64(r.ReplayTooOld))
	o.put("gamebond_rx_floor_drops_total", "Frames dropped below the receive floor.", "counter", nil, float64(r.FloorDrops))
	o.put("gamebond_rx_data_reordered_total", "Data frames that arrived out of order.", "counter", nil, float64(r.DataReordered))
	o.put("gamebond_rx_fec_recovered_total", "Packets rebuilt from parity.", "counter", nil, float64(r.FECRecovered+r.FECRecoveredRS))
	o.put("gamebond_rx_payload_packets_total", "Payload packets delivered.", "counter", nil, float64(r.PayloadPackets))
	o.put("gamebond_rx_peer_restarts_total", "Times the server restarted its sender domain.", "counter", nil, float64(r.PeerRestarts))
	o.put("gamebond_rx_bfd_down_events_total", "BFD down transitions seen.", "counter", nil, float64(r.BFDDown))
	x := s.Sender
	o.put("gamebond_tx_payload_packets_total", "Payload packets sent.", "counter", nil, float64(x.PayloadPackets))
	o.put("gamebond_tx_copies_total", "Redundant copies sent.", "counter", nil, float64(x.Copies))
	o.put("gamebond_tx_sack_lost_total", "Frames the sender found lost through selective acknowledgement.", "counter", nil, float64(x.SackLost))
	o.put("gamebond_tx_sack_resent_total", "Lost frames answered with an immediate resend.", "counter", nil, float64(x.SackResent))
	o.put("gamebond_tx_sack_unrecoverable_total", "Lost frames that could not be resent.", "counter", nil, float64(x.SackUnrecoverable))
	o.put("gamebond_tx_failover_replayed_total", "Frames replayed on another path after a path was suspected.", "counter", nil, float64(x.FailoverReplayed))
	o.put("gamebond_tx_repair_exhausted_total", "Repair requests that ran out of retries.", "counter", nil, float64(x.RepairExhausted))
	o.put("gamebond_tx_socket_errors_total", "Socket write errors.", "counter", nil, float64(x.SocketErrors))
	q := s.Queue
	o.put("gamebond_queue_expired_total", "Packets that outlived their queue age before being sent.", "counter", nil, float64(q.Expired))
	o.put("gamebond_queue_rejected_total", "Packets refused because the queue was full.", "counter", nil, float64(q.Rejected))
	o.put("gamebond_queue_packets", "Packets waiting in the transmit queue.", "gauge", nil, float64(q.QueuedPackets))
	o.put("gamebond_submit_rejected_total", "Packets dropped because the submission buffer was full.", "counter", nil, float64(s.Rejected))
	o.put("gamebond_deliver_dropped_total", "Packets dropped because the consumer fell behind.", "counter", nil, float64(s.Loop.DeliverDropped))
	o.put("gamebond_loop_busy_over_20ms_total", "Protocol loop passes slower than 20 ms.", "counter", nil, float64(s.Loop.BusyOver20))
	ou := s.Outages
	o.put("gamebond_link_downs_total", "Times a line stopped carrying traffic.", "counter", nil, float64(ou.LinkDowns))
	o.put("gamebond_no_links_total", "Full outages (no line carrying traffic).", "counter", nil, float64(ou.NoLinksCount))
	o.put("gamebond_no_links", "1 while no line carries traffic.", "gauge", nil, b2f(ou.NoLinksNow))
	o.put("gamebond_link_downs_last_hour", "Line failures in the last hour.", "gauge", nil, float64(ou.DownsLastHour))
	for i, d := range ou.SlotDownMS {
		o.put("gamebond_slot_down_seconds_total", "Time a slot spent down.", "counter", map[string]string{"slot": strconv.Itoa(i)}, d/1000)
	}
	e := s.Exit
	if e.Active.IsValid() {
		o.put("gamebond_exit_active", "1 for the exit server in use.", "gauge", map[string]string{"address": e.Active.Addr().String()}, 1)
		o.put("gamebond_exit_on_backup", "1 when traffic uses a backup exit instead of the primary.", "gauge", nil, b2f(e.Active != e.Primary))
		o.put("gamebond_exit_switches_total", "Failovers between exit servers.", "counter", nil, float64(e.Switches))
		o.put("gamebond_exit_silent_seconds", "How long the active exit has been silent.", "gauge", nil, e.SilentMS/1000)
		o.put("gamebond_exit_searching", "1 while the active exit is silent and standbys are being tried.", "gauge", nil, b2f(e.Probing))
		for _, sv := range e.Servers {
			if sv.Active {
				continue
			}
			l := map[string]string{"address": sv.Addr.Addr().String()}
			o.put("gamebond_exit_standby_reachable", "1 when the last probe handshake with the standby succeeded.", "gauge", l, b2f(sv.State == "reachable"))
			o.put("gamebond_exit_standby_probed", "1 when the standby has been probed at least once.", "gauge", l, b2f(sv.State != "unknown"))
			if sv.State == "reachable" {
				o.put("gamebond_exit_standby_handshake_ms", "Handshake time of the last successful standby probe.", "gauge", l, sv.HandshakeMS)
			}
		}
	}
	o.put("gamebond_build_info", "Client and server builds in use (value is always 1).", "gauge",
		map[string]string{"client": short(s.ClientVersion), "server": short(s.ServerVersion), "server_state": s.ServerState}, 1)
	for _, a := range in.Alarms {
		o.put("gamebond_health_alarm", "1 for each transport health alarm that is raised.", "gauge", map[string]string{"kind": a.Kind, "link": strconv.Itoa(a.Link)}, 1)
	}
	if t := in.Totals; t != nil {
		o.put("gamebond_probe_sent_total", "End-to-end echo probes sent through the tunnel.", "counter", nil, float64(t.Sent))
		o.put("gamebond_probe_received_total", "Echo probes answered within the timeout.", "counter", nil, float64(t.Received))
		o.put("gamebond_probe_lost_total", "Echo probes not answered within the timeout.", "counter", nil, float64(t.Lost))
		o.put("gamebond_probe_late_total", "Replies that arrived after the timeout (the probe stays lost).", "counter", nil, float64(t.Late))
		o.put("gamebond_probe_seconds_total", "Seconds in which probes were sent and settled.", "counter", nil, float64(t.Seconds))
		o.put("gamebond_probe_bad_seconds_total", "Settled seconds in which no probe came back.", "counter", nil, float64(t.BadSeconds))
		var cum uint64
		for i, n := range t.Hist {
			cum += n
			le := "+Inf"
			if i < len(slo.BucketsMS) {
				le = num(slo.BucketsMS[i])
			}
			o.put("gamebond_probe_rtt_ms_bucket", "Round-trip time of answered probes.", "histogram", map[string]string{"le": le}, float64(cum))
		}
		o.put("gamebond_probe_rtt_ms_sum", "Sum of probe round-trip times.", "gauge", nil, t.RTTSumMS)
		o.put("gamebond_probe_rtt_ms_count", "Count of answered probes.", "gauge", nil, float64(t.Received))
	}
	if ev := in.Eval; ev != nil {
		for _, wr := range ev.Windows {
			win := WindowLabel(wr.Window)
			inds := []struct {
				name string
				ind  slo.Indicator
			}{{"delivery", wr.Delivery}, {"availability", wr.Availability}, {"latency", wr.Latency}}
			for _, it := range inds {
				l := map[string]string{"slo": it.name, "window": win}
				o.put("gamebond_slo_ratio", "Share of good events over the window.", "gauge", l, it.ind.Ratio)
				o.put("gamebond_slo_burn_rate", "Error-budget burn rate over the window (1 = budget lasts exactly the budget period).", "gauge", l, it.ind.BurnRate)
			}
			o.put("gamebond_measured_loss_ratio", "Measured end-to-end probe loss over the window.", "gauge", map[string]string{"window": win}, wr.LossRatio)
		}
		o.put("gamebond_slo_error_budget_left", "Share of the delivery error budget left over the budget period.", "gauge", nil, ev.BudgetLeft)
		o.put("gamebond_failover_restore_seconds_p95", "95th percentile failover restoration time.", "gauge", nil, ev.Failovers.P95.Seconds())
	}
	for _, sm := range in.Extra {
		o.put(sm.Name, sm.Help, sm.Type, sm.Labels, sm.Value)
	}
	return o.err
}

// WindowLabel names an evaluation window the way rules refer to it: 1h, 6h, 24h, 7d, 30d.
func WindowLabel(d time.Duration) string {
	if d >= 48*time.Hour || d%(24*time.Hour) == 0 && d > 24*time.Hour {
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
	return strconv.Itoa(int(d/time.Hour)) + "h"
}

func short(v string) string {
	if len(v) > 12 {
		return v[:12]
	}
	return v
}

// Names returns the metric names present in rendered output.
func Names(text string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		end := strings.IndexAny(line, "{ ")
		if end > 0 {
			out[line[:end]] = true
		}
	}
	return out
}
