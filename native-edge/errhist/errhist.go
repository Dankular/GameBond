// Package errhist keeps a history of transport errors by type: how often each kind happened, minute by
// minute, for the last 24 hours. The client's counters only ever grow, so the tracker turns them into
// per-minute counts (a counter that goes backwards has been reset, and counts from zero again) and
// persists them so a restart does not erase the picture.
package errhist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const historyMinutes = 24 * 60

// The last hour is also kept in 5 second slots, so the chart can be zoomed in far below a minute.
const (
	fineSeconds = 5
	fineSlots   = 3600 / fineSeconds
)

// Kind is one error type. Key is stable (storage and the UI use it), Group is the heading it is
// listed under, Help says what it means in one sentence.
type Kind struct {
	Key, Label, Group, Help string
}

// Kinds is the fixed list, in display order.
var Kinds = []Kind{
	{"lost_on_wire", "Upload copies lost on a link", "Absorbed", "A copy one link dropped on the way to the server, counted per copy. Usually recovered by the other link's duplicate or a resend; a loss only counts as a fault when it appears under Loss (never arrived)."},
	{"path_stalls", "Link went quiet briefly", "Absorbed", "A link delivered nothing for 150 ms or more and was heard again within a second. Every packet was already copied onto the other link, so nothing was lost."},
	{"never_arrived", "Never arrived", "Loss", "Packets from the server that did not arrive, even after repair."},
	{"holes_given_up", "Download delivered ahead of a gap", "Absorbed", "A packet was handed on the moment its first copy arrived, ahead of an earlier one still in flight on the other link. Nothing waits, so nothing stalls; the earlier one normally follows."},
	{"arrived_late", "Download gap filled by the other copy", "Absorbed", "The earlier packet turned up afterwards from the other link and was delivered, out of order."},
	{"repairs_exhausted", "Repair gave up", "Loss", "Repair requests ran out of attempts for a missing packet."},
	{"socket_send_errors", "Socket send errors", "Local", "The operating system refused to send a datagram."},
	{"os_udp_receive_errors", "OS receive errors", "Local", "The operating system dropped incoming datagrams before the client read them."},
	{"queue_expired", "Queue expired", "Local", "Packets waited so long in the send queue that they were dropped."},
	{"queue_rejected", "Queue full", "Local", "The send queue had no room for a packet."},
	{"delivery_queue_full", "Delivery queue full", "Local", "The consumer fell behind and received packets were dropped."},
	{"reorder_buffer_dropped", "Reorder buffer dropped", "Local", "Packets dropped because the reorder buffer was full."},
	{"auth_errors", "Authentication failures", "Protocol", "Frames that failed authentication (wrong key, or not from the server)."},
	{"malformed_frames", "Malformed frames", "Protocol", "Frames that could not be decoded."},
	{"handshake_rejected", "Handshake rejected", "Protocol", "Handshake messages that were not accepted."},
	{"replay_rejected", "Replays rejected", "Protocol", "Authentic frames dropped as too old or too far ahead of the replay window."},
	{"link_down", "Link went down", "Links", "A link changed from healthy to unhealthy."},
	{"failover_suspected", "Failover suspected", "Links", "A path stopped answering and traffic was moved off it."},
}

// Recoveries are the mechanisms that absorb errors, charted over the errors to show the connection holding up.
// Group is Recovery (retransmission), Parity (forward error correction) or Failover.
var Recoveries = []Kind{
	{"repair_sent", "Repair packets sent", "Recovery", "Copies resent because the peer reported a gap."},
	{"resent_at_once", "Resent at once", "Recovery", "Frames resent immediately after the peer's selective acknowledgement showed them missing."},
	{"parity_sent", "Parity packets sent", "Parity", "Redundant packets sent all the time so the peer can rebuild a lost one without waiting. Routine overhead, not a reaction to an error."},
	{"parity_recovered", "Rebuilt from parity", "Parity", "Lost packets reconstructed from parity, so nothing had to be resent."},
	{"failover_replayed", "Replayed after failover", "Failover", "Packets re-sent on another link after the one carrying them stopped answering."},
	{"failover_recovered", "Failover recoveries", "Failover", "A suspected link failure that turned out to be recovered."},
	{"fast_reroutes", "Fast reroutes", "Failover", "Traffic moved to a healthier link before a failure was declared."},
}

// routine marks recovery kinds that run all the time as protection overhead rather than in reaction to an
// error. They are reported and totalled but must not be read as "recovery happened here".
var routine = map[string]bool{"parity_sent": true}

// Connection state seconds, counted once a second while at least one link is configured.
const (
	secUp       = "t_up"       // every link healthy
	secDegraded = "t_degraded" // some links down, traffic still flowing on the rest
	secDown     = "t_down"     // no healthy link
)

var recIndex = func() map[string]int {
	m := map[string]int{}
	for i, k := range Recoveries {
		m[k.Key] = i
	}
	return m
}()

var index = func() map[string]int {
	m := map[string]int{}
	for i, k := range Kinds {
		m[k.Key] = i
	}
	return m
}()

type bucket struct {
	Minute int64             `json:"m"`
	Counts map[string]uint32 `json:"c"`
}

// Tracker is safe for concurrent use.
type Tracker struct {
	mu      sync.Mutex
	now     func() time.Time
	prev    map[string]uint64
	hasPrev bool
	linkUp  map[int]bool
	buckets []bucket
	fine    []bucket // Minute holds the 5 second slot (unix seconds / 5); in memory only
	session map[string]uint64
	dirty   bool
}

func New() *Tracker {
	return &Tracker{now: time.Now, prev: map[string]uint64{}, linkUp: map[int]bool{}, session: map[string]uint64{}}
}

func (t *Tracker) add(key string, n uint64) {
	if n == 0 {
		return
	}
	_, isErr := index[key]
	_, isRec := recIndex[key]
	if !isErr && !isRec && key != secUp && key != secDegraded && key != secDown {
		return
	}
	now := t.now().Unix()
	t.buckets = bump(t.buckets, now/60, historyMinutes, key, n)
	t.fine = bump(t.fine, now/fineSeconds, fineSlots, key, n)
	t.session[key] += n
	t.dirty = true
}

// bump adds n to key in the bucket for the given slot, opening a new bucket when the slot has changed and
// keeping at most limit buckets.
func bump(list []bucket, slot int64, limit int, key string, n uint64) []bucket {
	if l := len(list); l == 0 || list[l-1].Minute != slot {
		list = append(list, bucket{Minute: slot, Counts: map[string]uint32{}})
		if len(list) > limit {
			list = list[len(list)-limit:]
		}
	}
	c := list[len(list)-1].Counts
	c[key] = uint32(min(uint64(c[key])+n, 1<<32-1))
	return list
}

// Observe takes the current cumulative counter values by Kind key. The first call only records a
// baseline: errors that happened before the tracker started are not attributed to this minute.
func (t *Tracker) Observe(counters map[string]uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.hasPrev {
		for key, v := range counters {
			p := t.prev[key]
			if v >= p {
				t.add(key, v-p)
			} else {
				t.add(key, v) // the counter was reset: everything since then is new
			}
		}
	}
	for key, v := range counters {
		t.prev[key] = v
	}
	t.hasPrev = true
}

// Links records a link_down for every link that was healthy at the previous call and is not now.
// healthy maps the link's slot to its health.
func (t *Tracker) Links(healthy map[int]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for slot, ok := range healthy {
		if was, seen := t.linkUp[slot]; seen && was && !ok {
			t.add("link_down", 1)
		}
		t.linkUp[slot] = ok
	}
}

// Health records one second of connection state: total links configured, healthy links among them.
// With no links nothing is recorded (the tunnel is not running).
func (t *Tracker) Health(total, healthy int) {
	if total <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case healthy >= total:
		t.add(secUp, 1)
	case healthy > 0:
		t.add(secDegraded, 1)
	default:
		t.add(secDown, 1)
	}
}

// View is the status document section. kinds/minutes are the errors: one row per minute that had any,
// [unix seconds, count per kind in Kinds order]. recovery_kinds/recovery are the same for the mechanisms
// that absorb errors (Recoveries order). stability has one row per minute with connection state:
// [unix seconds, seconds all links healthy, seconds degraded, seconds with no healthy link].
func (t *Tracker) View() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := t.now().Unix()/60 - historyMinutes
	rows, recRows, stab, errTotals, recTotals := fold(t.buckets, 60, cutoff)
	meta := func(list []Kind, totals []uint64) []map[string]any {
		out := make([]map[string]any, len(list))
		for i, k := range list {
			out[i] = map[string]any{"key": k.Key, "label": k.Label, "group": k.Group, "help": k.Help, "total_24h": totals[i], "session": t.session[k.Key], "routine": routine[k.Key]}
		}
		return out
	}
	fRows, fRec, fStab, _, _ := fold(t.fine, fineSeconds, t.now().Unix()/fineSeconds-fineSlots)
	return map[string]any{"kinds": meta(Kinds, errTotals), "minutes": rows, "recovery_kinds": meta(Recoveries, recTotals), "recovery": recRows, "stability": stab,
		"fine": map[string]any{"seconds": fineSeconds, "minutes": fRows, "recovery": fRec, "stability": fStab}}
}

// fold turns buckets (each covering unit seconds) newer than cutoff into the row lists of View.
func fold(buckets []bucket, unit, cutoff int64) (rows, recRows, stab [][]uint64, errTotals, recTotals []uint64) {
	errTotals, recTotals = make([]uint64, len(Kinds)), make([]uint64, len(Recoveries))
	rows, recRows, stab = make([][]uint64, 0), make([][]uint64, 0), make([][]uint64, 0)
	for _, b := range buckets {
		if b.Minute <= cutoff {
			continue
		}
		er, rr := make([]uint64, 1+len(Kinds)), make([]uint64, 1+len(Recoveries))
		er[0], rr[0] = uint64(b.Minute*unit), uint64(b.Minute*unit)
		var anyErr, anyRec bool
		for key, n := range b.Counts {
			if i, ok := index[key]; ok && n > 0 {
				er[1+i], errTotals[i], anyErr = uint64(n), errTotals[i]+uint64(n), true
			} else if i, ok := recIndex[key]; ok && n > 0 {
				rr[1+i], recTotals[i], anyRec = uint64(n), recTotals[i]+uint64(n), true
			}
		}
		if anyErr {
			rows = append(rows, er)
		}
		if anyRec {
			recRows = append(recRows, rr)
		}
		if up, dg, dn := b.Counts[secUp], b.Counts[secDegraded], b.Counts[secDown]; up+dg+dn > 0 {
			stab = append(stab, []uint64{uint64(b.Minute * unit), uint64(up), uint64(dg), uint64(dn)})
		}
	}
	return
}

type saved struct {
	Version int      `json:"version"`
	Buckets []bucket `json:"buckets"`
}

// Save writes the history to path (atomically) when it changed since the last save.
func (t *Tracker) Save(path string) error {
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return nil
	}
	data, err := json.Marshal(saved{Version: 1, Buckets: t.buckets})
	t.dirty = false
	t.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load restores a saved history, dropping minutes older than 24 hours. A missing or damaged file
// leaves the tracker empty: the history is a convenience, never a dependency.
func (t *Tracker) Load(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var s saved
	if json.Unmarshal(data, &s) != nil || s.Version != 1 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := t.now().Unix()/60 - historyMinutes
	sort.Slice(s.Buckets, func(i, j int) bool { return s.Buckets[i].Minute < s.Buckets[j].Minute })
	t.buckets = t.buckets[:0]
	for _, b := range s.Buckets {
		if b.Minute > cutoff && b.Counts != nil {
			t.buckets = append(t.buckets, b)
		}
	}
}

// SavePath is where a client keeps its error history, next to its status file.
func SavePath(statusPath string) string {
	return filepath.Join(filepath.Dir(statusPath), "error-history.json")
}
