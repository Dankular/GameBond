package ttyrelay

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMetadataLeasePreventsDuplicateAndReleasesOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.json")
	r, err := Start(Options{Metadata: path, ConfigPath: "client.json"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	before, _ := os.ReadFile(path)
	if other, err := Start(Options{Metadata: path}); !errors.Is(err, ErrMetadataInUse) {
		if other != nil {
			other.Close()
		}
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("duplicate replaced metadata")
	}
	if rec, err := ReadMetadata(path); err != nil || rec.ConfigPath != "client.json" {
		t.Fatal(rec.ConfigPath, err)
	}
	r.Close()
	replacement, err := Start(Options{Metadata: path})
	if err != nil {
		t.Fatal(err)
	}
	replacement.Close()
}

func TestLiveLegacyRelayCannotBeReplacedWithoutLease(t *testing.T) {
	r := start(t, Options{})
	r.lease.Close() // Model a live older binary without the new OS lock.
	if other, err := Start(Options{Metadata: r.opt.Metadata}); !errors.Is(err, ErrMetadataInUse) {
		if other != nil {
			other.Close()
		}
		t.Fatal(err)
	}
}
