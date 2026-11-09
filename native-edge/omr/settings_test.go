package omr

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"math"
	"os"
	"reflect"
	"testing"
)

type vecCase struct {
	Config json.RawMessage `json:"config"`
	Result struct {
		OK       bool   `json:"ok"`
		Mode     string `json:"mode"`
		Settings *struct {
			Server      []any   `json:"server"`
			KeyFile     string  `json:"key_file"`
			Admin       *Admin  `json:"admin"`
			TunnelIP    string  `json:"tunnel_ip"`
			TunnelIPSet bool    `json:"tunnel_ip_set"`
			RateMbps    float64 `json:"rate_mbps"`
			BeatMS      int     `json:"beat_ms"`
			DSCP        []int   `json:"gamebond_dscp"`
		} `json:"settings"`
	} `json:"result"`
}

func TestSettingsMatchPython(t *testing.T) {
	f, err := os.Open("testdata/settings-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, _ := gzip.NewReader(f)
	raw, _ := io.ReadAll(zr)
	var cases []vecCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for i, c := range cases {
		cfg, err := ParseConfig(c.Config)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		mode, s, err := LoadServerMode(cfg)
		if (err == nil) != c.Result.OK {
			t.Fatalf("case %d: go err=%v, python ok=%v\n%s", i, err, c.Result.OK, bytes.TrimSpace(c.Config))
		}
		if err != nil {
			continue
		}
		accepted++
		if mode != c.Result.Mode {
			t.Fatalf("case %d: mode %q vs %q", i, mode, c.Result.Mode)
		}
		w := c.Result.Settings
		if (w == nil) != (s == nil) {
			t.Fatalf("case %d: settings presence", i)
		}
		if w == nil {
			continue
		}
		if s.ServerHost() != w.Server[0].(string) || float64(s.ServerPort()) != w.Server[1].(float64) || s.KeyFile != w.KeyFile || s.TunnelIP != w.TunnelIP ||
			s.TunnelIPSet != w.TunnelIPSet || math.Abs(s.RateMbps-w.RateMbps) > 1e-12 || s.BeatMS != w.BeatMS || !reflect.DeepEqual(s.Admin, w.Admin) ||
			!reflect.DeepEqual(append([]int{}, s.GamebondDSCP...), append([]int{}, w.DSCP...)) {
			t.Fatalf("case %d: settings differ\n go: %+v admin=%+v\n py: %+v admin=%+v\n%s", i, s, s.Admin, w, w.Admin, c.Config)
		}
	}
	t.Logf("%d cases, %d accepted", len(cases), accepted)
	if accepted < 1000 || len(cases)-accepted < 1000 {
		t.Fatalf("vector mix too lopsided: %d/%d", accepted, len(cases))
	}
}
