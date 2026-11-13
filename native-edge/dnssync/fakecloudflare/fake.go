// Package fakecloudflare is an in-memory stand-in for the parts of Cloudflare's API the client uses (token and key
// verification, zones, DNS records), for tests.
package fakecloudflare

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type apiErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// account is a small Cloudflare with a token, a global key, several zones and a record table.
type Account struct {
	mu          sync.Mutex
	Token       string // accepted bearer token
	TokenStatus string
	Email, Key  string
	Zones       []Zone
	Records     map[string][]Record // zone id -> records
	ZoneCalls   int
}

// New returns an account with a token, a global key and two zones (example.com holds two records).
func New() *Account {
	return &Account{Token: "good-token", TokenStatus: "active", Email: "me@example.com", Key: "good-key",
		Zones:   []Zone{{"z1", "example.com"}, {"z2", "other.net"}},
		Records: map[string][]Record{"z1": {{ID: "r0", Type: "A", Name: "www.example.com", Content: "9.9.9.9"}, {ID: "r00", Type: "CNAME", Name: "blog.example.com", Content: "x.example.net"}}}}
}

// Lock and Unlock guard the exported fields while the handler is serving.
func (a *Account) Lock()   { a.mu.Lock() }
func (a *Account) Unlock() { a.mu.Unlock() }

// Handler serves the API.
func (a *Account) Handler() http.Handler { return a }

func (a *Account) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	reply := func(code int, ok bool, result any, msg string) {
		w.WriteHeader(code)
		out := map[string]any{"success": ok, "result": result}
		if !ok {
			out["errors"] = []apiErr{{Code: 1000, Message: msg}}
		}
		json.NewEncoder(w).Encode(out)
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	authed := (a.Token != "" && bearer == a.Token) || (a.Key != "" && r.Header.Get("X-Auth-Key") == a.Key)
	if !authed {
		reply(401, false, nil, "Invalid API Token")
		return
	}
	switch {
	case r.URL.Path == "/user/tokens/verify":
		reply(200, true, map[string]string{"id": "t1", "status": a.TokenStatus}, "")
	case r.URL.Path == "/user":
		reply(200, true, map[string]string{"email": a.Email}, "")
	case r.URL.Path == "/zones":
		a.ZoneCalls++
		if n := r.URL.Query().Get("name"); n != "" {
			var out []Zone
			for _, z := range a.Zones {
				if z.Name == n {
					out = append(out, z)
				}
			}
			reply(200, true, out, "")
			return
		}
		page := 1
		fmt.Sscan(r.URL.Query().Get("page"), &page)
		lo, hi := (page-1)*50, page*50
		if lo > len(a.Zones) {
			lo = len(a.Zones)
		}
		if hi > len(a.Zones) {
			hi = len(a.Zones)
		}
		reply(200, true, a.Zones[lo:hi], "")
	case strings.HasPrefix(r.URL.Path, "/zones/") && strings.HasSuffix(r.URL.Path, "/dns_records") && r.Method == http.MethodGet:
		id := strings.Split(r.URL.Path, "/")[2]
		var out []Record
		for _, rec := range a.Records[id] {
			if rec.Name == r.URL.Query().Get("name") && (r.URL.Query().Get("type") == "" || r.URL.Query().Get("type") == rec.Type) {
				out = append(out, rec)
			}
		}
		reply(200, true, out, "")
	case strings.HasPrefix(r.URL.Path, "/zones/") && strings.HasSuffix(r.URL.Path, "/dns_records") && r.Method == http.MethodPost:
		id := strings.Split(r.URL.Path, "/")[2]
		var rec Record
		json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = fmt.Sprintf("rec%d", len(a.Records[id])+1)
		a.Records[id] = append(a.Records[id], rec)
		reply(200, true, rec, "")
	case r.Method == http.MethodDelete:
		parts := strings.Split(r.URL.Path, "/")
		id, rid := parts[2], parts[4]
		kept := a.Records[id][:0]
		for _, rec := range a.Records[id] {
			if rec.ID != rid {
				kept = append(kept, rec)
			}
		}
		a.Records[id] = kept
		reply(200, true, map[string]string{"id": rid}, "")
	default:
		reply(404, false, nil, "not found")
	}
}
