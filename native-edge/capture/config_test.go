package capture

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type vectors struct {
	Root      string `json:"root"`
	Normalize []struct {
		In  []any `json:"in"`
		Out struct {
			Ok    []string `json:"ok"`
			Error string   `json:"error"`
		} `json:"out"`
	} `json:"normalize"`
	Configs []struct {
		Config   map[string]any `json:"config"`
		Netstack *string        `json:"netstack"`
		Carriers []string       `json:"carriers"`
		Out      struct {
			Ok    *Configuration `json:"ok"`
			Error string         `json:"error"`
		} `json:"out"`
	} `json:"configs"`
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

func TestNormalizeAppsMatchesPython(t *testing.T) {
	v := load(t)
	for i, c := range v.Normalize {
		got, err := NormalizeApps(c.In)
		if c.Out.Error != "" {
			if err == nil || err.Error() != c.Out.Error {
				t.Fatalf("%d %q: got %v %v want error %s", i, c.In, got, err, c.Out.Error)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, c.Out.Ok) {
			t.Fatalf("%d %q: got %q %v want %q", i, c.In, got, err, c.Out.Ok)
		}
	}
}

func TestProxyConfigurationMatchesPython(t *testing.T) {
	v := load(t)
	for i, c := range v.Configs {
		mode, _ := c.Config["capture_mode"].(string)
		apps, _ := c.Config["cod_executables"].([]any)
		ns := ""
		if c.Netstack != nil {
			ns = *c.Netstack
		}
		got, err := ProxyConfiguration(mode, apps, "127.0.0.1:1080", v.Root, c.Carriers, ns)
		if c.Out.Error != "" {
			if err == nil || err.Error() != c.Out.Error {
				t.Fatalf("%d: got %v %v want %s", i, got, err, c.Out.Error)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, c.Out.Ok) {
			t.Fatalf("%d %v:\n got %+v %v\nwant %+v", i, c.Config, got, err, c.Out.Ok)
		}
	}
}

func TestVerifyExtension(t *testing.T) {
	dir := t.TempDir()
	if ext, err := VerifyExtension(dir); ext != "" || err != nil {
		t.Fatalf("empty dir: %q %v", ext, err)
	}
	body := []byte("dll bytes")
	os.WriteFile(filepath.Join(dir, "socksify.dll"), body, 0o600)
	sum := sha256.Sum256(body)
	write := func(m map[string]any) {
		raw, _ := json.Marshal(m)
		os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600)
	}
	good := map[string]any{"schema": 1, "feature": "gamebond-owner-v1", "dll_sha256": hex.EncodeToString(sum[:])}
	write(good)
	if ext, err := VerifyExtension(dir); err != nil || ext != filepath.Join(dir, "socksify.dll") {
		t.Fatalf("%q %v", ext, err)
	}
	for _, mut := range []map[string]any{
		{"schema": 2, "feature": "gamebond-owner-v1", "dll_sha256": good["dll_sha256"]},
		{"schema": 1, "feature": "other", "dll_sha256": good["dll_sha256"]},
		{"schema": 1, "feature": "gamebond-owner-v1", "dll_sha256": "00"},
		{"feature": "gamebond-owner-v1", "dll_sha256": good["dll_sha256"]},
	} {
		write(mut)
		if ext, err := VerifyExtension(dir); err == nil || ext != "" {
			t.Fatalf("accepted %v", mut)
		}
	}
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{bad"), 0o600)
	if _, err := VerifyExtension(dir); err == nil {
		t.Fatal("bad json accepted")
	}
}
