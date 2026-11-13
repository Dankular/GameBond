package slo

import (
	"database/sql"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Objectives are the targets the tunnel is judged against.
type Objectives struct {
	Delivery     float64       // share of probes echoed within the probe timeout
	Availability float64       // share of seconds in which at least one probe came back
	LatencyMS    float64       // round-trip bound for the latency objective (a histogram bucket edge)
	Latency      float64       // share of echoed probes at or under LatencyMS
	FailoverP95  time.Duration // 95th percentile of the time a failover took to restore traffic
}

// DefaultObjectives are deliberately strict for a bonded link carrying game traffic.
func DefaultObjectives() Objectives {
	return Objectives{Delivery: 0.9999, Availability: 0.9995, LatencyMS: 150, Latency: 0.99, FailoverP95: 5 * time.Second}
}

// Windows are the look-back periods reported, shortest first. The last one is the budget period.
var Windows = []time.Duration{time.Hour, 6 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour}

// Indicator is one objective over one window.
type Indicator struct {
	Good, Total uint64
	Ratio       float64 // Good/Total; 1 when nothing was measured
	// BurnRate is how fast the error budget is being spent: 1 spends it exactly over the budget
	// period, 14.4 spends 2% of a 30-day budget in an hour. Zero when nothing was measured.
	BurnRate float64
	Met      bool
}

// WindowResult holds every indicator for one window.
type WindowResult struct {
	Window       time.Duration
	Measured     time.Duration // time actually covered by data (a young database is shorter than its window)
	Sent         uint64
	Lost, Late   uint64
	LossRatio    float64
	LossUpper95  float64 // upper bound of the true loss ratio at 95% confidence
	P50, P95     float64 // round-trip ms (histogram bucket upper edge; the top bucket reports as +Inf)
	P99          float64
	Delivery     Indicator
	Availability Indicator
	Latency      Indicator
}

// Failovers summarises how long failovers took to restore traffic.
type Failovers struct {
	Count         int
	P50, P95, Max time.Duration
	Met           bool
}

// Evaluation is the full report.
type Evaluation struct {
	At         time.Time
	Objectives Objectives
	Windows    []WindowResult
	Failovers  Failovers
	Events     []Event
	// BudgetLeft is the share of the delivery error budget not yet spent over the longest window.
	BudgetLeft float64
}

// Event is a row of slo_event.
type Event struct {
	At       time.Time
	Kind     string
	Detail   string
	Duration time.Duration
}

func indicator(good, total uint64, target float64) Indicator {
	i := Indicator{Good: good, Total: total, Ratio: 1, Met: true}
	if total == 0 {
		return i
	}
	i.Ratio = float64(good) / float64(total)
	i.Met = i.Ratio >= target
	if target < 1 {
		i.BurnRate = (1 - i.Ratio) / (1 - target)
	}
	return i
}

// wilsonUpper is the upper end of the 95% Wilson interval for k events in n trials; for k = 0 it is
// close to the "rule of three" (3/n).
func wilsonUpper(k, n uint64) float64 {
	if n == 0 {
		return 1
	}
	const z = 1.959964
	p, nf := float64(k)/float64(n), float64(n)
	d := 1 + z*z/nf
	c := p + z*z/(2*nf)
	h := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf))
	return math.Min(1, (c+h)/d)
}

func percentile(h [nBuckets]uint64, q float64) float64 {
	var total uint64
	for _, v := range h {
		total += v
	}
	if total == 0 {
		return 0
	}
	want := uint64(math.Ceil(q * float64(total)))
	var run uint64
	for i, v := range h {
		run += v
		if run >= want {
			if i < len(BucketsMS) {
				return BucketsMS[i]
			}
			return math.Inf(1)
		}
	}
	return math.Inf(1)
}

const sumColumns = `COALESCE(SUM(sent),0),COALESCE(SUM(recv),0),COALESCE(SUM(lost),0),COALESCE(SUM(late),0),COALESCE(SUM(secs),0),COALESCE(SUM(bad_secs),0),COALESCE(MIN(minute),0),COALESCE(MAX(minute),0),` +
	`COALESCE(SUM(h0),0),COALESCE(SUM(h1),0),COALESCE(SUM(h2),0),COALESCE(SUM(h3),0),COALESCE(SUM(h4),0),COALESCE(SUM(h5),0),COALESCE(SUM(h6),0),COALESCE(SUM(h7),0),COALESCE(SUM(h8),0),COALESCE(SUM(h9),0),COALESCE(SUM(h10),0),COALESCE(SUM(h11),0)`

// WindowSince aggregates the minutes in [from, to) (the current, unsettled minute is never included
// because outcomes of its probes are still arriving).
func WindowSince(db *sql.DB, from, to time.Time, obj Objectives) (WindowResult, error) {
	var w WindowResult
	var sent, recv, lost, late, secs, bad uint64
	var minM, maxM int64
	var h [nBuckets]uint64
	dest := []any{&sent, &recv, &lost, &late, &secs, &bad, &minM, &maxM}
	for i := range h {
		dest = append(dest, &h[i])
	}
	end := to.Unix() / 60
	if err := db.QueryRow(`SELECT `+sumColumns+` FROM slo_minute WHERE minute >= ? AND minute < ?`, from.Unix()/60, end).Scan(dest...); err != nil {
		return w, err
	}
	w.Window, w.Sent, w.Lost, w.Late = to.Sub(from), sent, lost, late
	if maxM >= minM && sent > 0 {
		w.Measured = time.Duration(maxM-minM+1) * time.Minute
	}
	if sent > 0 {
		w.LossRatio = float64(lost) / float64(sent)
		w.LossUpper95 = wilsonUpper(lost, sent)
	}
	w.P50, w.P95, w.P99 = percentile(h, .50), percentile(h, .95), percentile(h, .99)
	w.Delivery = indicator(sent-min(lost, sent), sent, obj.Delivery)
	w.Availability = indicator(secs-min(bad, secs), secs, obj.Availability)
	var fast uint64
	for i, v := range h {
		if i < len(BucketsMS) && BucketsMS[i] <= obj.LatencyMS {
			fast += v
		}
	}
	w.Latency = indicator(fast, recv, obj.Latency)
	return w, nil
}

// Evaluate computes every window up to now, the failover statistics over the longest window and the
// most recent events.
func Evaluate(db *sql.DB, now time.Time, obj Objectives) (Evaluation, error) {
	ev := Evaluation{At: now, Objectives: obj}
	for _, win := range Windows {
		w, err := WindowSince(db, now.Add(-win), now, obj)
		if err != nil {
			return ev, err
		}
		w.Window = win
		ev.Windows = append(ev.Windows, w)
	}
	last := ev.Windows[len(ev.Windows)-1]
	ev.BudgetLeft = 1
	if last.Delivery.Total > 0 && obj.Delivery < 1 {
		ev.BudgetLeft = math.Max(0, 1-last.Delivery.BurnRate)
	}
	rows, err := db.Query(`SELECT ts,kind,detail,COALESCE(duration_ms,0) FROM slo_event WHERE ts >= ? ORDER BY ts DESC LIMIT 200`, float64(now.Add(-Windows[len(Windows)-1]).Unix()))
	if err != nil {
		return ev, err
	}
	defer rows.Close()
	var fo []time.Duration
	for rows.Next() {
		var ts, ms float64
		var e Event
		if err := rows.Scan(&ts, &e.Kind, &e.Detail, &ms); err != nil {
			return ev, err
		}
		e.At, e.Duration = time.Unix(0, int64(ts*1e9)), time.Duration(ms*float64(time.Millisecond))
		ev.Events = append(ev.Events, e)
		if e.Kind == "failover" {
			fo = append(fo, e.Duration)
		}
	}
	ev.Failovers = summariseFailovers(fo, obj.FailoverP95)
	return ev, rows.Err()
}

func summariseFailovers(d []time.Duration, p95 time.Duration) Failovers {
	f := Failovers{Count: len(d), Met: true}
	if len(d) == 0 {
		return f
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	at := func(q float64) time.Duration { return d[min(len(d)-1, int(math.Ceil(q*float64(len(d))))-1)] }
	f.P50, f.P95, f.Max = at(.50), at(.95), d[len(d)-1]
	f.Met = f.P95 <= p95
	return f
}

func pct(r float64) string {
	if r >= 0.99999 && r < 1 {
		return fmt.Sprintf("%.5f%%", r*100)
	}
	return fmt.Sprintf("%.4f%%", r*100)
}

func ms(v float64) string {
	if math.IsInf(v, 1) {
		return "> 1000"
	}
	return fmt.Sprintf("%g", v)
}

func mark(ok bool, total uint64) string {
	switch {
	case total == 0:
		return "no data"
	case ok:
		return "met"
	}
	return "MISSED"
}

// Markdown renders the evaluation as a report.
func (e Evaluation) Markdown() string {
	var b strings.Builder
	o := e.Objectives
	fmt.Fprintf(&b, "# Tunnel SLO and measured loss\n\nGenerated %s.\n\n", e.At.UTC().Format("2006-01-02 15:04:05 MST"))
	b.WriteString("Loss is measured end to end: an ICMP echo goes through the tunnel to the server's tunnel address and back, ")
	b.WriteString("and a probe not echoed within one second counts as lost. It is charged to the minute it was sent in.\n\n")
	fmt.Fprintf(&b, "## Objectives\n\n- Delivery: at least %s of probes echoed\n- Availability: at least %s of seconds with a probe answered\n- Latency: at least %s of echoed probes at or under %g ms\n- Failover: 95th percentile of restoration time at most %s\n\n",
		pct(o.Delivery), pct(o.Availability), pct(o.Latency), o.LatencyMS, o.FailoverP95)
	b.WriteString("## Measured loss\n\n| Window | Covered | Probes sent | Lost | Loss | Loss, 95% upper bound |\n|---|---|---|---|---|---|\n")
	for _, w := range e.Windows {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %s | %s |\n", dur(w.Window), dur(w.Measured), w.Sent, w.Lost, lossPct(w.LossRatio), lossPct(w.LossUpper95))
	}
	b.WriteString("\n## Objectives by window\n\n| Window | Delivery | Burn | Availability | Burn | Latency | Burn | RTT p50 / p95 / p99 (ms) |\n|---|---|---|---|---|---|---|---|\n")
	for _, w := range e.Windows {
		fmt.Fprintf(&b, "| %s | %s %s | %.2f | %s %s | %.2f | %s %s | %.2f | %s / %s / %s |\n", dur(w.Window),
			pct(w.Delivery.Ratio), mark(w.Delivery.Met, w.Delivery.Total), w.Delivery.BurnRate,
			pct(w.Availability.Ratio), mark(w.Availability.Met, w.Availability.Total), w.Availability.BurnRate,
			pct(w.Latency.Ratio), mark(w.Latency.Met, w.Latency.Total), w.Latency.BurnRate, ms(w.P50), ms(w.P95), ms(w.P99))
	}
	fmt.Fprintf(&b, "\nBurn rate 1.0 spends the error budget exactly over the budget period; above 1.0 it runs out early. Delivery error budget left over %s: %.1f%%.\n\n", dur(Windows[len(Windows)-1]), e.BudgetLeft*100)
	f := e.Failovers
	b.WriteString("## Failovers\n\n")
	if f.Count == 0 {
		b.WriteString("None recorded in the period.\n\n")
	} else {
		fmt.Fprintf(&b, "%d failover(s): restoration time p50 %s, p95 %s, max %s (%s).\n\n", f.Count, f.P50.Round(time.Millisecond), f.P95.Round(time.Millisecond), f.Max.Round(time.Millisecond), mark(f.Met, uint64(f.Count)))
	}
	if len(e.Events) > 0 {
		b.WriteString("## Recent events\n\n| Time (UTC) | Kind | Detail | Duration |\n|---|---|---|---|\n")
		for i, ev := range e.Events {
			if i == 30 {
				break
			}
			d := ""
			if ev.Duration > 0 {
				d = ev.Duration.Round(time.Millisecond).String()
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", ev.At.UTC().Format("01-02 15:04:05"), ev.Kind, strings.ReplaceAll(ev.Detail, "|", "/"), d)
		}
	}
	return b.String()
}

func lossPct(r float64) string {
	if r == 0 {
		return "0"
	}
	return fmt.Sprintf("%.5f%%", r*100)
}

func dur(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f d", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.1f h", d.Hours())
	}
	return fmt.Sprintf("%.0f min", d.Minutes())
}
