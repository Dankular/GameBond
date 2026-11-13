package promexport

import (
	"bytes"
	"github.com/Dankular/GameBond.Core/bond"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/slo"
)

func TestWriteEmitsFamiliesOnceAndProbeSeries(t *testing.T) {
	tr := slo.NewTracker(nil)
	var buf bytes.Buffer
	in := Input{Snap: client.Snapshot{}, Totals: ptr(tr.Totals())}
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	names := Names(out)
	for _, n := range []string{"gamebond_paths_ready", "gamebond_rx_duplicates_total", "gamebond_probe_lost_total", "gamebond_probe_rtt_ms_bucket", "gamebond_build_info"} {
		if !names[n] {
			t.Errorf("missing %s", n)
		}
	}
	if c := strings.Count(out, "# TYPE gamebond_probe_rtt_ms histogram"); c != 1 {
		t.Errorf("histogram TYPE lines = %d", c)
	}
	if strings.Contains(out, "+Inf\"} 0\n") == false {
		t.Errorf("no +Inf bucket in output")
	}
}

func ptr[T any](v T) *T { return &v }

// fullInput renders every family the exporter can emit.
func fullInput() Input {
	tr := slo.NewTracker(nil)
	tot := tr.Totals()
	ev := &slo.Evaluation{Windows: []slo.WindowResult{{Window: time.Hour}, {Window: 6 * time.Hour}, {Window: 24 * time.Hour}, {Window: 7 * 24 * time.Hour}}}
	primary := netip.MustParseAddrPort("10.0.0.1:4434")
	backup := netip.MustParseAddrPort("10.0.0.2:4433")
	var s client.Snapshot
	s.Paths = []bond.PathSnapshot{{Local: 0, Ready: true}}
	s.Outages.SlotDownMS = []float64{1}
	s.Exit = client.ExitStatus{Active: primary, Primary: primary, Servers: []client.ExitServer{{Addr: primary, Active: true}, {Addr: backup, State: "reachable"}}}
	return Input{Snap: s, Alarms: []bond.Alarm{{Kind: "x", Link: 1}}, Totals: &tot, Eval: ev}
}

func TestAlertRulesUseExportedMetrics(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, fullInput()); err != nil {
		t.Fatal(err)
	}
	have := Names(buf.String())
	raw, err := os.ReadFile(filepath.Join("..", "..", "ops", "prometheus", "gamebond-alerts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	used := regexp.MustCompile(`gamebond_[a-z0-9_]+`).FindAllString(string(raw), -1)
	if len(used) < 15 {
		t.Fatalf("only %d metric references found in the rules", len(used))
	}
	for _, n := range used {
		if strings.HasPrefix(n, "gamebond_client") || have[n] {
			continue
		}
		t.Errorf("alert rules use %s, which the exporter does not emit", n)
	}
}
