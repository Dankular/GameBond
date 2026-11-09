package dashboard

import (
	"path/filepath"
	"strings"
	"testing"

	"gamebond.local/nativeedge/eventjournal"
)

func TestEventJournalEndpointAndPersistentReadMarker(t *testing.T) {
	s, url, config, _ := start(t)
	j, err := eventjournal.Open(filepath.Join(filepath.Dir(config), "events.json"), 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.Ingest([]any{map[string]any{"id": 1, "timestamp": 1000.5, "application": map[string]any{"name": "Test app", "path": `C:\test.exe`}}})
	s.o.Journal = j
	endpoint := url[:strings.Index(url, "/?t=")] + "/api/events"
	if code, _ := do(t, "GET", endpoint, "", ""); code != 403 {
		t.Fatal(code)
	}
	if code, body := do(t, "GET", endpoint, s.token, ""); code != 200 || !strings.Contains(body, "Test app") {
		t.Fatal(code, body)
	}
	if code, body := do(t, "POST", endpoint, s.token, `{"action":"mark_read"}`); code != 200 || !strings.Contains(body, `"read_through":1`) {
		t.Fatal(code, body)
	}
	if code, _ := do(t, "POST", endpoint, s.token, `{"action":"append"}`); code != 422 {
		t.Fatal(code)
	}
}
