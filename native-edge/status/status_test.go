package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriteJSONReplacesAtomicallyAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "userspace-status.json")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := WriteJSON(path, map[string]any{"state": "running", "n": i}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	for i := 0; i < 200; i++ { // readers never see a partial document
		if raw, err := os.ReadFile(path); err == nil {
			var m map[string]any
			if json.Unmarshal(raw, &m) != nil {
				t.Fatalf("partial read: %q", raw)
			}
		}
	}
	wg.Wait()
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}
