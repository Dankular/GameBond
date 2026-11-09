package appevents

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type scenario struct {
	Name       string                     `json:"name"`
	AppLimit   int                        `json:"app_limit"`
	EventLimit int                        `json:"event_limit"`
	Table      map[string]json.RawMessage `json:"table"`
	SeedFile   *string                    `json:"seed_file"`
	Ops        []json.RawMessage          `json:"ops"`
	Results    []any                      `json:"results"`
	BuildOK    bool                       `json:"build_ok"`
}

func loadVectors(t *testing.T) []scenario {
	f, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var v []scenario
	if err := json.NewDecoder(z).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func decodeAny(t *testing.T, raw []byte) any {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// normalise turns a Go result into the same shape json.load gives Python's.
func normalise(t *testing.T, v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestStoreMatchesPython(t *testing.T) {
	vectors := loadVectors(t)
	newApps, snapshots, trimmed, loaded, refused := 0, 0, 0, 0, 0
	for _, sc := range vectors {
		t.Run(sc.Name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "history.json")
			if sc.SeedFile != nil {
				os.WriteFile(path, []byte(*sc.SeedFile), 0o600)
			}
			var now float64 = 1700000000.0
			table := map[string]map[string]any{}
			for k, v := range sc.Table {
				table[k] = decodeAny(t, v).(map[string]any)
			}
			resolver := func(pid int64, created string) map[string]any {
				row := table[fmt.Sprintf("%d:%s", pid, created)]
				if row == nil {
					return nil
				}
				return copyMap(row)
			}
			opt := Options{Resolver: resolver, Clock: func() float64 { return now }, AppLimit: sc.AppLimit, EventLimit: sc.EventLimit}
			store, err := New(path, opt)
			if (err == nil) != sc.BuildOK {
				t.Fatalf("New ok=%v want %v (%v)", err == nil, sc.BuildOK, err)
			}
			if err != nil {
				refused++
				return
			}
			if sc.SeedFile != nil {
				loaded++
			}
			for i, rawOp := range sc.Ops {
				op := decodeAny(t, rawOp).(map[string]any)
				want := sc.Results[i]
				var got any
				switch op["op"] {
				case "observe":
					rec, _ := op["record"].(map[string]any)
					if e := store.Observe(rec); e != nil {
						got = e
						newApps++
					}
				case "remember":
					store.RememberAuthorizedOwner(op["identity"].(map[string]any))
				case "usage":
					rec, _ := op["record"].(map[string]any)
					store.RecordUsage(rec)
				case "traffic":
					got = store.TrafficSnapshot(int(num(op["limit"])))
				case "snapshot":
					got = store.Snapshot(int64(num(op["after"])), int(num(op["limit"])))
					snapshots++
					if m := got.(map[string]any); len(m["events"].([]map[string]any)) == 0 && m["latest_id"].(int64) > 0 {
						trimmed++
					}
				case "tick":
					now += num(op["dt"])
				case "forget":
					for _, k := range op["keys"].([]any) {
						delete(table, k.(string))
					}
				case "flush":
					if err := store.Flush(); err != nil {
						t.Fatal(err)
					}
					if raw, err := os.ReadFile(path); err == nil {
						got = decodeFile(t, raw)
					}
				case "reload":
					s2, err := New(path, opt)
					if err != nil {
						got = "error"
					} else {
						store, got = s2, s2.Snapshot(0, 256)
					}
				default:
					t.Fatalf("unknown op %v", op["op"])
				}
				if g, w := normalise(t, got), want; !reflect.DeepEqual(g, w) {
					gj, _ := json.Marshal(g)
					wj, _ := json.Marshal(w)
					t.Fatalf("op %d %v: result differs\n got %s\nwant %s", i, summary(op), clip(gj), clip(wj))
				}
			}
		})
	}
	if newApps < 500 || snapshots < 200 || trimmed < 1 || loaded < 6 || refused < 15 {
		t.Fatalf("thin coverage: newApps=%d snapshots=%d trimmed=%d loaded=%d refused=%d", newApps, snapshots, trimmed, loaded, refused)
	}
}

func decodeFile(t *testing.T, raw []byte) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("history file is not JSON: %v", err)
	}
	return v
}

func summary(op map[string]any) string {
	raw, _ := json.Marshal(op)
	return clip(raw)
}

func clip(b []byte) string {
	s := string(b)
	if len(s) > 600 {
		s = s[:600] + "..."
	}
	return strings.ReplaceAll(s, "\n", " ")
}

func TestCasefoldMatchesPythonForSpecialCases(t *testing.T) {
	for in, want := range map[string]string{"Stra\u00dfe": "strasse", "\u1e9e": "ss", "\u0130": "i\u0307", "\u03a3": "\u03c3", "\u03c2": "\u03c3", "ABC": "abc", "": ""} {
		if got := casefold(in); got != want {
			t.Errorf("casefold(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPyFloatReprMatchesPython(t *testing.T) {
	for in, want := range map[float64]string{0: "0.0", 1: "1.0", 1700000030.5: "1700000030.5", 1e16: "1e+16", 3.3250000000000104e16: "3.3250000000000104e+16",
		1e15: "1000000000000000.0", 0.0001: "0.0001", 0.00001: "1e-05", 123456789.125: "123456789.125", -2.5: "-2.5", 1.5e-7: "1.5e-07", 100: "100.0"} {
		if got := pyFloatRepr(in); got != want {
			t.Errorf("pyFloatRepr(%v)=%q want %q", in, got, want)
		}
	}
}

func num(v any) float64 { f, _ := v.(json.Number).Float64(); return f }
