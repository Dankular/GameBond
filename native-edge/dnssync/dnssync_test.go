package dnssync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCF is a tiny Cloudflare: zone khosa.co with a record table.
type fakeCF struct {
	mu      sync.Mutex
	records []Record
	calls   []string
	auth    http.Header
	fail    bool
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Clone()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	reply := func(ok bool, result any, msg string) {
		out := map[string]any{"success": ok, "result": result}
		if !ok {
			out["errors"] = []apiError{{Code: 9109, Message: msg}}
		}
		json.NewEncoder(w).Encode(out)
	}
	if f.fail {
		w.WriteHeader(403)
		reply(false, nil, "Invalid access token")
		return
	}
	switch {
	case r.URL.Path == "/zones":
		if r.URL.Query().Get("name") == "khosa.co" {
			reply(true, []map[string]string{{"id": "z1"}}, "")
		} else {
			reply(true, []map[string]string{}, "")
		}
	case r.Method == "GET" && r.URL.Path == "/zones/z1/dns_records":
		var out []Record
		for _, x := range f.records {
			if x.Name == r.URL.Query().Get("name") {
				out = append(out, x)
			}
		}
		reply(true, out, "")
	case r.Method == "POST":
		var rec Record
		json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = "r" + string(rune('0'+len(f.records)))
		f.records = append(f.records, rec)
		reply(true, rec, "")
	case r.Method == "PUT":
		var rec Record
		json.NewDecoder(r.Body).Decode(&rec)
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		for i := range f.records {
			if f.records[i].ID == id {
				rec.ID = id
				f.records[i] = rec
			}
		}
		reply(true, rec, "")
	case r.Method == "DELETE":
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		for i := range f.records {
			if f.records[i].ID == id {
				f.records = append(f.records[:i], f.records[i+1:]...)
				break
			}
		}
		reply(true, map[string]string{"id": id}, "")
	default:
		w.WriteHeader(404)
		reply(false, nil, "no route")
	}
}

func newClient(t *testing.T, a Auth) (*Client, *fakeCF) {
	f := &fakeCF{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &Client{API: srv.URL, Auth: a}, f
}

func TestUpsertCreatesUpdatesAndSkips(t *testing.T) {
	c, f := newClient(t, Auth{Token: "tok"})
	ctx := context.Background()
	if ch, err := c.Upsert(ctx, "bond.khosa.co", "138.199.201.16", 60); err != nil || !ch {
		t.Fatalf("create: changed=%v err=%v", ch, err)
	}
	if len(f.records) != 1 || f.records[0].Content != "138.199.201.16" || f.records[0].Proxied {
		t.Fatalf("records: %+v", f.records)
	}
	if ch, err := c.Upsert(ctx, "bond.khosa.co", "138.199.201.16", 60); err != nil || ch {
		t.Fatalf("same address must not write: changed=%v err=%v", ch, err)
	}
	if ch, err := c.Upsert(ctx, "bond.khosa.co", "195.154.119.136", 60); err != nil || !ch {
		t.Fatalf("switch: changed=%v err=%v", ch, err)
	}
	if len(f.records) != 1 || f.records[0].Content != "195.154.119.136" {
		t.Fatalf("records after switch: %+v", f.records)
	}
}

func TestUpsertRemovesDuplicatesAndFixesProxying(t *testing.T) {
	c, f := newClient(t, Auth{Token: "tok"})
	f.records = []Record{{ID: "a", Type: "A", Name: "bond.khosa.co", Content: "1.1.1.1", Proxied: true}, {ID: "b", Type: "A", Name: "bond.khosa.co", Content: "2.2.2.2"}}
	if _, err := c.Upsert(context.Background(), "bond.khosa.co", "3.3.3.3", 60); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 || f.records[0].Content != "3.3.3.3" || f.records[0].Proxied {
		t.Fatalf("records: %+v", f.records)
	}
}

func TestAuthHeadersAndErrorsNeverLeakTheSecret(t *testing.T) {
	c, f := newClient(t, Auth{Email: "me@example.com", Key: "SECRETKEY"})
	if _, err := c.Upsert(context.Background(), "bond.khosa.co", "1.2.3.4", 60); err != nil {
		t.Fatal(err)
	}
	if f.auth.Get("X-Auth-Key") != "SECRETKEY" || f.auth.Get("X-Auth-Email") != "me@example.com" || f.auth.Get("Authorization") != "" {
		t.Fatalf("headers: %v", f.auth)
	}
	f.fail = true
	c.zone = nil
	_, err := c.Upsert(context.Background(), "bond.khosa.co", "1.2.3.4", 60)
	if err == nil || strings.Contains(err.Error(), "SECRETKEY") {
		t.Fatalf("want a clean error, got %v", err)
	}
	if _, err := (&Client{}).Upsert(context.Background(), "bond.khosa.co", "1.2.3.4", 60); err == nil {
		t.Fatal("no credentials must fail")
	}
}

func TestUnknownZone(t *testing.T) {
	c, _ := newClient(t, Auth{Token: "tok"})
	if _, err := c.Upsert(context.Background(), "x.example.org", "1.2.3.4", 60); err == nil || !strings.Contains(err.Error(), "no Cloudflare zone") {
		t.Fatalf("got %v", err)
	}
}
