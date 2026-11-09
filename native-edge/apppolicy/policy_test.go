package apppolicy

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type pathCase struct {
	Path *string `json:"path"`
	Raw  any     `json:"raw"`
	OK   bool    `json:"ok"`
	Out  string  `json:"out"`
}

type decisionCase struct {
	App         any `json:"app"`
	Protocol    any `json:"protocol"`
	Destination any `json:"destination"`
	Out         struct {
		Allow   bool   `json:"allow"`
		Profile string `json:"profile"`
		Reason  string `json:"reason"`
	} `json:"out"`
}

type configCase struct {
	Config    any            `json:"config"`
	OK        bool           `json:"ok"`
	Snapshot  map[string]any `json:"snapshot"`
	Digest    string         `json:"digest"`
	Decisions []decisionCase `json:"decisions"`
}

type vectors struct {
	Paths   []pathCase   `json:"paths"`
	Configs []configCase `json:"configs"`
}

func load(t *testing.T) vectors {
	f, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.NewDecoder(z).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCanonicalPathMatchesPython(t *testing.T) {
	v := load(t)
	ok := 0
	for i, c := range v.Paths {
		var in any = c.Raw
		if c.Path != nil {
			in = *c.Path
		}
		got, err := CanonicalPath(in)
		if (err == nil) != c.OK {
			t.Fatalf("case %d %q: ok=%v want %v (got %q)", i, in, err == nil, c.OK, got)
		}
		if c.OK {
			ok++
			if got != c.Out {
				t.Fatalf("case %d %q: got %q want %q", i, in, got, c.Out)
			}
		}
	}
	if ok < 100 {
		t.Fatalf("only %d accepted paths: vectors lost coverage", ok)
	}
}

func TestPolicyMatchesPython(t *testing.T) {
	v := load(t)
	accepted, decisions, blocked := 0, 0, 0
	for i, c := range v.Configs {
		p, err := New(c.Config)
		if (err == nil) != c.OK {
			t.Fatalf("config %d %v: ok=%v want %v (%v)", i, c.Config, err == nil, c.OK, err)
		}
		if !c.OK {
			continue
		}
		accepted++
		if got := p.Snapshot(); !reflect.DeepEqual(got, c.Snapshot) {
			t.Fatalf("config %d snapshot\n got %v\nwant %v", i, got, c.Snapshot)
		}
		if got := p.Digest(); got != c.Digest {
			t.Fatalf("config %d digest %s want %s", i, got, c.Digest)
		}
		for j, d := range c.Decisions {
			got := p.Authorize(d.App, d.Protocol, d.Destination)
			if got.Allow != d.Out.Allow || got.Profile != d.Out.Profile || got.Reason != d.Out.Reason {
				t.Fatalf("config %d decision %d app=%v %v %v: got %+v want %+v", i, j, d.App, d.Protocol, d.Destination, got, d.Out)
			}
			decisions++
			if !got.Allow {
				blocked++
			}
		}
	}
	if accepted < 100 || decisions < 5000 || blocked < 500 {
		t.Fatalf("thin coverage: accepted=%d decisions=%d blocked=%d", accepted, decisions, blocked)
	}
}
