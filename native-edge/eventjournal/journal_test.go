package eventjournal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func appEvent(id int, name string, at float64) any {
	return map[string]any{"id": id, "timestamp": at, "application": map[string]any{"name": name, "path": `C:\Games\Straße.exe`}, "destination": "203.0.113.1:443"}
}

func TestJournalPersistsDeduplicatesAndMarksRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	j, err := Open(path, 2048)
	if err != nil {
		t.Fatal(err)
	}
	event := appEvent(1, "Example", 1000.5)
	j.Ingest([]any{event, event})
	j.MarkRead()
	j.Close()
	j, err = Open(path, 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.Ingest([]any{event})
	s := j.Snapshot()
	if s.Sequence != 1 || s.ReadThrough != 1 || len(s.Events) != 1 || s.Error != "" {
		t.Fatal(s)
	}
	if s.Events[0].Source != `app:1:1000.5:c:\games\strasse.exe` || s.Events[0].Text != "Example used the tunnel for the first time" {
		t.Fatal(s.Events)
	}
	s.Events[0].Application["name"] = "mutated"
	if j.Snapshot().Events[0].Application["name"] != "Example" {
		t.Fatal("snapshot shares application metadata")
	}
}

func TestCorruptJournalIsPreserved(t *testing.T) {
	for _, raw := range []string{`broken`, `{"version":1,"sequence":1,"events":[{"id":true}]}`, `{"version":2,"events":[]}`, `{"version":1,"sequence":0,"events":[{"id":1,"source":"x","timestamp":2}]}`} {
		path := filepath.Join(t.TempDir(), "events.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		j, err := Open(path, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if j.Snapshot().Error == "" {
			t.Fatal("corruption hidden")
		}
		j.Ingest([]any{appEvent(1, "App", 1)})
		j.MarkRead()
		j.Close()
		after, _ := os.ReadFile(path)
		if string(after) != raw {
			t.Fatal("corrupt journal overwritten")
		}
	}
}

func TestJournalConnectionTransitionsAndBoundedHistory(t *testing.T) {
	j, err := Open("", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	doc := map[string]any{"pid": 1, "state": "running", "peer": []any{"192.0.2.1", 4433}, "transport": map[string]any{"paths": []any{map[string]any{"interface_index": 22, "healthy": true}}}}
	j.Observe(doc)
	j.Observe(doc)
	if j.Snapshot().Sequence != 0 {
		t.Fatal("initial/repeated state created an event")
	}
	doc["state"] = "stopped"
	j.Observe(doc)
	j.Observe(doc)
	j.Observe(nil)
	j.Observe(nil)
	s := j.Snapshot()
	if len(s.Events) != 2 || s.Events[0].Kind != "connection_state" || !strings.Contains(s.Events[0].Text, "1/1 enabled links") || s.Events[1].Text != "Tunnel disconnected" {
		t.Fatal(s)
	}
	for i := 0; i < 30; i++ {
		j.Ingest([]any{appEvent(i+1, "App", float64(i+1000))})
	}
	s = j.Snapshot()
	if len(s.Events) != 3 || s.Sequence != 32 {
		t.Fatal(s)
	}
}

func TestCoalescingWriterFlushesLatestSnapshotOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	j, err := Open(path, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 30; i++ {
		j.Ingest([]any{appEvent(i, "App", float64(1000+i))})
	}
	j.MarkRead()
	j.Close()
	j, err = Open(path, 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	s := j.Snapshot()
	if s.Error != "" || len(s.Events) != 30 || s.ReadThrough != 30 {
		t.Fatal(s)
	}
}

func TestSlowWriterDoesNotBlockAndCoalescesIntermediate(t *testing.T) {
	j, err := Open(filepath.Join(t.TempDir(), "events.json"), 2048)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var writes []int64
	j.write = func(raw []byte) error {
		var doc Snapshot
		_ = json.Unmarshal(raw, &doc)
		writes = append(writes, doc.Sequence)
		if len(writes) == 1 {
			close(entered)
			<-release
		}
		return nil
	}
	j.Ingest([]any{appEvent(1, "First", 1)})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer never started")
	}
	finished := make(chan struct{})
	go func() {
		j.Ingest([]any{appEvent(2, "Intermediate", 2)})
		j.Ingest([]any{appEvent(3, "Latest", 3)})
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		close(release)
		j.Close()
		t.Fatal("slow disk blocked ingestion")
	}
	close(release)
	j.Close()
	if len(writes) != 2 || writes[0] != 1 || writes[1] != 3 {
		t.Fatal(writes)
	}
}

func TestLoadsPythonIntegerTimestampWithoutDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	raw := `{"version":1,"sequence":1,"read_through":0,"events":[{"id":1,"source":"app:1:1234:c:\\test.exe","kind":"new_app_tunnel_use","text":"Test used the tunnel for the first time","timestamp":1234,"application":{"name":"Test","path":"C:\\test.exe"},"destination":null}]}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	j, err := Open(path, 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	j.Ingest([]any{map[string]any{"id": float64(1), "timestamp": float64(1234), "application": map[string]any{"name": "Test", "path": `C:\test.exe`}}})
	if s := j.Snapshot(); s.Error != "" || s.Sequence != 1 {
		t.Fatal(s)
	}
}
