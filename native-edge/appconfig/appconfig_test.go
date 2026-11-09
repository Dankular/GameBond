package appconfig

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"
)

type vector struct {
	Config  json.RawMessage `json:"config"`
	Windows bool            `json:"windows"`
	Allow   bool            `json:"allow"`
	OK      bool            `json:"ok"`
}

func TestPythonVectors(t *testing.T) {
	f, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	dec := json.NewDecoder(zr)
	if err := dec.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	var okN, deferred, failed int
	for i, v := range vectors {
		res, err := Load(bytes.TrimSpace(v.Config), Options{Windows: v.Windows, AllowUnavailableLinks: v.Allow})
		got := err == nil
		if got && !v.OK && len(res.Unchecked) > 0 {
			deferred++ // python rejected it in a section validated by another package
			continue
		}
		if got != v.OK {
			failed++
			if failed <= 15 {
				t.Errorf("case %d windows=%v allow=%v: go ok=%v (%v), python ok=%v\n%s", i, v.Windows, v.Allow, got, err, v.OK, v.Config)
			}
		}
		if v.OK {
			okN++
		}
	}
	if failed > 0 {
		t.Fatalf("%d mismatches of %d", failed, len(vectors))
	}
	t.Logf("%d vectors, %d accepted, %d deferred to section validators", len(vectors), okN, deferred)
	if okN < 2500 {
		t.Fatalf("vector mix degenerated: ok=%d deferred=%d", okN, deferred)
	}
}
