package dashboard

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func activityDoc(at float64, processes string) map[string]any {
	var rows []any
	_ = json.Unmarshal([]byte(processes), &rows)
	return map[string]any{"pid": float64(1), "created": float64(10), "state": "running", "updated_at": at, "applications": rows}
}

func activityNow(at float64) time.Time { return time.Unix(0, int64(at*1e9)) }

const browserProcess = `{"path":"C:\\Apps\\Browser.exe","name":"Browser","pid":1,"created_filetime":"100","generation":1,"downloaded_bytes":1000,"uploaded_bytes":200,"active_connections":2,"destinations":["example.test:443"]}`

func TestAppActivityUsesObservedTimeAndDeduplicatesPolls(t *testing.T) {
	var s AppActivitySampler
	doc := activityDoc(100, "["+browserProcess+"]")
	first := s.Sample(doc, activityNow(100))
	if len(first.Applications) != 1 || first.Applications[0].Down != nil {
		t.Fatal(first)
	}
	doc = activityDoc(102, `[{"path":"c:\\apps\\browser.exe","name":"Browser","pid":1,"created_filetime":"100","generation":1,"downloaded_bytes":3000,"uploaded_bytes":1200,"active_connections":2}]`)
	second := s.Sample(doc, activityNow(102))
	r := second.Applications[0]
	if r.Path != `c:\apps\browser.exe` || r.Down == nil || *r.Down != 1000 || *r.Up != 500 || len(r.History) != 2 {
		t.Fatal(r)
	}
	if repeated := s.Sample(doc, activityNow(103)); !reflect.DeepEqual(second, repeated) {
		t.Fatal("repeated poll changed measured history")
	}
	if len(first.Applications[0].History) != 1 {
		t.Fatal("new sample mutated an earlier snapshot")
	}
}

func TestAppActivityMergesProcessesAndRejectsInvalidCounters(t *testing.T) {
	var s AppActivitySampler
	doc := activityDoc(100, "["+browserProcess+`,{"path":"c:\\apps\\browser.exe","name":"Browser","pid":2,"created_filetime":"200","generation":2,"downloaded_bytes":20,"uploaded_bytes":30,"active_connections":1,"destinations":["second.test:443"]},{"path":"c:\\invalid.exe","downloaded_bytes":-1,"uploaded_bytes":3},{"path":"c:\\missing.exe","uploaded_bytes":3},{"path":"c:\\null.exe","downloaded_bytes":null,"uploaded_bytes":3}]`)
	result := s.Sample(doc, activityNow(100))
	if len(result.Applications) != 1 {
		t.Fatal(result)
	}
	r := result.Applications[0]
	if r.Downloaded != 1020 || r.Uploaded != 230 || r.Connections != 3 || len(r.PIDs) != 2 || len(r.Destinations) != 2 {
		t.Fatal(r)
	}
}

func TestAppActivityResetsOnCounterPIDGenerationAndSessionChanges(t *testing.T) {
	for _, change := range []string{"counter", "generation", "birth", "session", "disconnect", "stale"} {
		t.Run(change, func(t *testing.T) {
			var s AppActivitySampler
			s.Sample(activityDoc(100, "["+browserProcess+"]"), activityNow(100))
			doc := activityDoc(101, "["+browserProcess+"]")
			p := doc["applications"].([]any)[0].(map[string]any)
			p["downloaded_bytes"] = float64(3000)
			switch change {
			case "counter":
				p["uploaded_bytes"] = float64(1)
			case "generation":
				p["generation"] = float64(2)
			case "birth":
				p["created_filetime"] = "200"
			case "session":
				doc["created"] = float64(11)
			case "disconnect":
				doc["state"] = "stopped"
			case "stale":
				doc["updated_at"] = float64(90)
			}
			v := s.Sample(doc, activityNow(101))
			if change == "disconnect" || change == "stale" {
				if v.Available || len(v.Applications) != 0 {
					t.Fatal(v)
				}
			} else if v.Applications[0].Down != nil {
				t.Fatal("reset invented a rate", v)
			}
		})
	}
}

func TestAppActivitySamplesWhileHiddenAndKeepsBoundedHistory(t *testing.T) {
	var s AppActivitySampler
	for i := 0; i < 80; i++ {
		doc := activityDoc(float64(100+i), "["+browserProcess+"]")
		doc["applications"].([]any)[0].(map[string]any)["downloaded_bytes"] = float64(1000 + i*1000)
		s.Sample(doc, activityNow(float64(100+i)))
	}
	if r := s.last.Applications[0]; len(r.History) != 60 || r.Down == nil || *r.Down != 1000 {
		t.Fatal(r)
	}
	s.Sample(activityDoc(180, "[]"), activityNow(180))
	if len(s.previous) != 0 || len(s.histories) != 0 {
		t.Fatal("removed processes retained baselines")
	}
}
