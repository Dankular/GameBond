package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gamebond.local/nativeedge/client"
)

// reporter writes report.md and results.json. Everything in them is counted from probes the run sent;
// nothing is estimated.
type reporter struct {
	out     string
	started time.Time
	st      *stats
	db      *sql.DB
	c       *client.Client
	links   int
	servers []string
	seed    int64
	planned time.Duration
}

func (r *reporter) write(final bool) {
	now := time.Now()
	unexplained := r.st.settle(now)
	r.st.mu.Lock()
	defer r.st.mu.Unlock()

	game, bulk := r.st.total("game"), r.st.total("bulk")
	var done, skipped int
	for _, w := range r.st.windows {
		switch {
		case w.Skipped != "":
			skipped++
		case !w.End.IsZero():
			done++
		}
	}
	var b strings.Builder
	state := "in progress"
	if final {
		state = "finished"
	}
	fmt.Fprintf(&b, "# GameBond soak report (%s)\n\n", state)
	fmt.Fprintf(&b, "- Ran %s of a planned %s (started %s)\n", now.Sub(r.started).Round(time.Second), r.planned, r.started.Format(time.RFC3339))
	fmt.Fprintf(&b, "- %d emulated links on loopback, real exit servers: %s; seed %d\n", r.links, strings.Join(r.servers, ", "), r.seed)
	fmt.Fprintf(&b, "- %d faults injected and finished, %d skipped\n", done, skipped)
	if sn := r.c.Snapshot(); true {
		fmt.Fprintf(&b, "- Exit switches seen by the client: %d\n", sn.Exit.Switches)
	}
	fmt.Fprintf(&b, "- Game probe: 100 B, priority, duplicated on every link. Bulk probe: 1200 B, best effort, single copy.\n")
	fmt.Fprintf(&b, "- A probe is lost if its echo is not back within 1 s. Faults are charged by send time plus a %s margin after they end.\n\n", r.st.margin)

	fmt.Fprintf(&b, "## Overall\n\n| stream | sent | lost | loss | loss 95%% upper |\n|---|---:|---:|---:|---:|\n")
	fmt.Fprintf(&b, "| game | %d | %d | %s | %s |\n", game.Sent, game.Lost, pct(ratio(game.Lost, game.Sent)), pct(wilsonUpper(game.Lost, game.Sent)))
	fmt.Fprintf(&b, "| bulk | %d | %d | %s | %s |\n\n", bulk.Sent, bulk.Lost, pct(ratio(bulk.Lost, bulk.Sent)), pct(wilsonUpper(bulk.Lost, bulk.Sent)))

	fmt.Fprintf(&b, "## Game stream, by fault class\n\nBlackout is the longest stretch with no answered game probe while the fault was active or recovering.\n\n%s\n", r.st.classTable("game", true))
	fmt.Fprintf(&b, "## Bulk stream, by fault class\n\n%s\n", r.st.classTable("bulk", false))

	fmt.Fprintf(&b, "## Faults\n\n| # | class | link | start | length | blackout | recovery after clear | game lost / sent |\n|---:|---|---:|---|---:|---:|---:|---:|\n")
	for _, w := range r.st.windows {
		if w.Skipped != "" {
			fmt.Fprintf(&b, "| %d | %s | | %s | skipped: %s | | | |\n", w.ID, w.Class, w.Start.Format("15:04:05"), w.Skipped)
			continue
		}
		var lost, sent uint64
		if c := w.Counts["game"]; c != nil {
			lost, sent = c.Lost, c.Sent
		}
		end := "active"
		if !w.End.IsZero() {
			end = w.End.Sub(w.Start).Round(time.Second).String()
		}
		fmt.Fprintf(&b, "| %d | %s | %d | %s | %s | %.0f ms | %.0f ms | %d / %d |\n", w.ID, w.Class, w.Link, w.Start.Format("15:04:05"), end, w.BlackoutMS, w.RecoverMS, lost, sent)
	}
	fmt.Fprintf(&b, "\n## Silences outside any fault\n\n")
	if len(unexplained) == 0 {
		b.WriteString("None.\n")
	}
	for _, g := range unexplained {
		fmt.Fprintf(&b, "- %s: %.0f ms\n", g.From.Format("15:04:05.000"), float64(g.dur())/float64(time.Millisecond))
	}
	_ = os.WriteFile(filepath.Join(r.out, "report.md"), []byte(b.String()), 0o644)

	res := map[string]any{"final": final, "elapsed_s": now.Sub(r.started).Seconds(), "game": game, "bulk": bulk,
		"by": r.st.by, "faults": r.st.windows, "unexplained_gaps": len(unexplained)}
	if j, err := json.MarshalIndent(res, "", " "); err == nil {
		_ = os.WriteFile(filepath.Join(r.out, "results.json"), j, 0o644)
	}
}
