package tray

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"
)

type step struct {
	Runtime       map[string]any `json:"runtime"`
	Busy          bool           `json:"busy"`
	Problem       *string        `json:"problem"`
	Redrawn       bool           `json:"redrawn"`
	Color         string         `json:"color"`
	Title         string         `json:"title"`
	Toggle        string         `json:"toggle"`
	ToggleEnabled bool           `json:"toggle_enabled"`
}

func TestModelReplaysPythonTrayAgent(t *testing.T) {
	f, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, _ := gzip.NewReader(f)
	var seqs [][]step
	if err := json.NewDecoder(z).Decode(&seqs); err != nil {
		t.Fatal(err)
	}
	redraws := 0
	for i, seq := range seqs {
		m := NewModel()
		for j, s := range seq {
			problem := ""
			if s.Problem != nil {
				problem = *s.Problem
			}
			got := m.Update(s.Runtime, s.Busy, problem)
			if got != s.Redrawn || m.Color != s.Color || m.Title != s.Title || m.ToggleLabel != s.Toggle || m.ToggleEnabled != s.ToggleEnabled {
				t.Fatalf("seq %d step %d: go %v %s %q %s %v, python %v %s %q %s %v (runtime %v busy %v problem %v)", i, j,
					got, m.Color, m.Title, m.ToggleLabel, m.ToggleEnabled, s.Redrawn, s.Color, s.Title, s.Toggle, s.ToggleEnabled, s.Runtime, s.Busy, s.Problem)
			}
			if got {
				redraws++
			}
		}
	}
	if redraws < 500 {
		t.Fatalf("only %d redraws exercised", redraws)
	}
}
