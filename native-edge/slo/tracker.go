package slo

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

// BucketsMS are the upper bounds of the round-trip histogram; the last bucket is everything above.
var BucketsMS = [...]float64{5, 10, 20, 30, 50, 75, 100, 150, 250, 500, 1000}

const nBuckets = len(BucketsMS) + 1

// Schema is the table set the tracker keeps; pass it to store.Open as a step.
const Schema = `
CREATE TABLE slo_minute(
  minute INTEGER PRIMARY KEY,           -- unix time / 60 of the send time
  sent INTEGER NOT NULL, recv INTEGER NOT NULL, lost INTEGER NOT NULL, late INTEGER NOT NULL,
  secs INTEGER NOT NULL, bad_secs INTEGER NOT NULL, -- seconds with probes, and those where none came back
  h0 INTEGER NOT NULL, h1 INTEGER NOT NULL, h2 INTEGER NOT NULL, h3 INTEGER NOT NULL, h4 INTEGER NOT NULL, h5 INTEGER NOT NULL,
  h6 INTEGER NOT NULL, h7 INTEGER NOT NULL, h8 INTEGER NOT NULL, h9 INTEGER NOT NULL, h10 INTEGER NOT NULL, h11 INTEGER NOT NULL);
CREATE TABLE slo_event(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL, duration_ms REAL);
CREATE INDEX slo_event_ts ON slo_event(ts);`

type minuteRow struct {
	sent, recv, lost, late, secs, badSecs uint64
	h                                     [nBuckets]uint64
	dirty                                 bool
}

type secondRow struct{ sent, recv uint64 }

// Tracker aggregates probe outcomes per minute, and persists them. It implements Sink.
type Tracker struct {
	mu      sync.Mutex
	db      *sql.DB
	minutes map[int64]*minuteRow
	seconds map[int64]*secondRow
	retain  time.Duration
	pruned  time.Time
	events  []pendingEvent
	// Totals since the tracker started (never reset), for Prometheus counters.
	tot Totals
}

type pendingEvent struct {
	ts       time.Time
	kind     string
	detail   string
	duration time.Duration
}

// Totals are monotonic counters since the process started.
type Totals struct {
	Sent, Received, Lost, Late, Seconds, BadSeconds uint64
	Hist                                            [nBuckets]uint64
	RTTSumMS                                        float64
}

// NewTracker returns a tracker writing to db (which may be nil: counters only).
func NewTracker(db *sql.DB) *Tracker {
	return &Tracker{db: db, minutes: map[int64]*minuteRow{}, seconds: map[int64]*secondRow{}, retain: 35 * 24 * time.Hour}
}

func (t *Tracker) minute(ts time.Time) *minuteRow {
	k := ts.Unix() / 60
	m := t.minutes[k]
	if m == nil {
		m = &minuteRow{}
		t.minutes[k] = m
	}
	m.dirty = true
	return m
}

func (t *Tracker) second(ts time.Time) *secondRow {
	k := ts.Unix()
	s := t.seconds[k]
	if s == nil {
		s = &secondRow{}
		t.seconds[k] = s
	}
	return s
}

func bucket(rtt time.Duration) int {
	ms := float64(rtt) / float64(time.Millisecond)
	for i, b := range BucketsMS {
		if ms <= b {
			return i
		}
	}
	return len(BucketsMS)
}

func (t *Tracker) Sent(sent time.Time) {
	t.mu.Lock()
	t.minute(sent).sent++
	t.second(sent).sent++
	t.tot.Sent++
	t.mu.Unlock()
}

func (t *Tracker) Received(sent time.Time, rtt time.Duration) {
	t.mu.Lock()
	m := t.minute(sent)
	m.recv++
	b := bucket(rtt)
	m.h[b]++
	t.second(sent).recv++
	t.tot.Received++
	t.tot.Hist[b]++
	t.tot.RTTSumMS += float64(rtt) / float64(time.Millisecond)
	t.mu.Unlock()
}

func (t *Tracker) Lost(sent time.Time) {
	t.mu.Lock()
	t.minute(sent).lost++
	t.tot.Lost++
	t.mu.Unlock()
}

func (t *Tracker) Late(sent time.Time, rtt time.Duration) {
	t.mu.Lock()
	t.minute(sent).late++
	t.tot.Late++
	t.mu.Unlock()
}

// Event records a notable moment (a failover with how long recovery took, a link going down...).
func (t *Tracker) Event(ts time.Time, kind, detail string, duration time.Duration) {
	t.mu.Lock()
	t.events = append(t.events, pendingEvent{ts, kind, detail, duration})
	t.mu.Unlock()
}

// Totals returns the process-lifetime counters.
func (t *Tracker) Totals() Totals {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tot
}

// settle closes seconds old enough that every probe sent in them has been answered or given up on.
func (t *Tracker) settle(now time.Time, grace time.Duration) {
	cut := now.Add(-grace).Unix()
	for k, s := range t.seconds {
		if k >= cut {
			continue
		}
		m := t.minute(time.Unix(k, 0))
		m.secs++
		t.tot.Seconds++
		if s.sent > 0 && s.recv == 0 {
			m.badSecs++
			t.tot.BadSeconds++
		}
		delete(t.seconds, k)
	}
}

// Flush settles finished seconds and writes changed minutes and queued events. grace must exceed the
// probe timeout. Old rows are pruned about once an hour.
func (t *Tracker) Flush(now time.Time, grace time.Duration) error {
	t.mu.Lock()
	t.settle(now, grace)
	type row struct {
		k int64
		m minuteRow
	}
	var rows []row
	for k, m := range t.minutes {
		if m.dirty {
			rows = append(rows, row{k, *m})
			*m = minuteRow{} // the stored row now holds these counts; the next flush adds only what follows
		}
		if now.Unix()/60-k > 10 { // nothing can still change a minute this old
			delete(t.minutes, k)
		}
	}
	events := t.events
	t.events = nil
	t.mu.Unlock()
	if t.db == nil {
		return nil
	}
	tx, err := t.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A minute can be flushed while it is still open, and again when a late outcome arrives, so a
	// write adds the deltas to the stored row; the in-memory row holds only what is not yet stored.
	for _, r := range rows {
		m := r.m
		args := []any{r.k, m.sent, m.recv, m.lost, m.late, m.secs, m.badSecs}
		for _, h := range m.h {
			args = append(args, h)
		}
		if _, err := tx.Exec(upsertMinute, args...); err != nil {
			return err
		}
	}
	for _, e := range events {
		if _, err := tx.Exec(`INSERT INTO slo_event(ts,kind,detail,duration_ms) VALUES (?,?,?,?)`,
			float64(e.ts.UnixNano())/1e9, e.kind, e.detail, float64(e.duration)/float64(time.Millisecond)); err != nil {
			return err
		}
	}
	if now.Sub(t.pruned) >= time.Hour {
		t.pruned = now
		cut := now.Add(-t.retain)
		if _, err := tx.Exec(`DELETE FROM slo_minute WHERE minute < ?`, cut.Unix()/60); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM slo_event WHERE ts < ?`, float64(cut.Unix())); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

var upsertMinute = func() string {
	cols := []string{"sent", "recv", "lost", "late", "secs", "bad_secs"}
	for i := 0; i < nBuckets; i++ {
		cols = append(cols, fmt.Sprintf("h%d", i))
	}
	var set []string
	for _, c := range cols {
		set = append(set, fmt.Sprintf("%s = %s + excluded.%s", c, c, c))
	}
	ph := strings.TrimRight(strings.Repeat("?,", len(cols)+1), ",")
	return "INSERT INTO slo_minute(minute," + strings.Join(cols, ",") + ") VALUES (" + ph + ") ON CONFLICT(minute) DO UPDATE SET " + strings.Join(set, ", ")
}()
