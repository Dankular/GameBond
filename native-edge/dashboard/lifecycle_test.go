package dashboard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSupervisorOverridesStaleRunningMetrics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(path, []byte(`{"state":"running","updated_at":1,"transport":{"paths":[{"healthy":true}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"stopped", "restarting", "stopping"} {
		doc := ReadStatus(path, func() (map[string]any, error) { return map[string]any{"state": state}, nil })
		if doc["state"] != state || doc["transport"] != nil {
			t.Fatal(doc)
		}
	}
	doc := ReadStatus(path, nil)
	if doc["state"] != "unavailable" {
		t.Fatal("stale file accepted", doc)
	}
	doc = ReadStatus(path, func() (map[string]any, error) { return nil, errors.New("relay offline") })
	if doc["state"] != "unavailable" || doc["transport"] != nil {
		t.Fatal(doc)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	doc = ReadStatus(path, func() (map[string]any, error) { return map[string]any{"state": "stopped"}, nil })
	if doc["state"] != "stopped" {
		t.Fatal("missing metrics hid supervisor", doc)
	}
}
