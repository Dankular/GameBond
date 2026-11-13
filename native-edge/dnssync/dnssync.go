// Package dnssync keeps one Cloudflare DNS A record pointed at the exit node the client is using, so
// a name such as bond.khosa.co always reaches the client through whichever exit is active.
package dnssync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultAPI = "https://api.cloudflare.com/client/v4"

// Auth is how requests are authenticated. Set Token for a scoped API token (preferred), or Email and
// Key for a global API key. It never appears in an error or a log line.
type Auth struct {
	Token      string
	Email, Key string
}

// Client talks to the Cloudflare API.
type Client struct {
	API  string // DefaultAPI when empty
	Auth Auth
	HTTP *http.Client
	// zone caches the zone id per record name.
	zone map[string]string
}

type envelope struct {
	Success bool            `json:"success"`
	Errors  []apiError      `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Record is a DNS record as far as this package cares.
type Record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body any, out any) error {
	base := c.API
	if base == "" {
		base = DefaultAPI
	}
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case c.Auth.Token != "":
		req.Header.Set("Authorization", "Bearer "+c.Auth.Token)
	case c.Auth.Key != "":
		req.Header.Set("X-Auth-Email", c.Auth.Email)
		req.Header.Set("X-Auth-Key", c.Auth.Key)
	default:
		return errors.New("dnssync: no credentials")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		// net/http errors quote the URL only, never the headers.
		return fmt.Errorf("cloudflare %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("cloudflare %s %s: HTTP %d, unreadable reply", method, path, resp.StatusCode)
	}
	if !env.Success {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		return fmt.Errorf("cloudflare %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.Join(msgs, "; "))
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// ZoneID finds the zone that contains name by trying its parent domains, longest first.
func (c *Client) ZoneID(ctx context.Context, name string) (string, error) {
	if id, ok := c.zone[name]; ok {
		return id, nil
	}
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	var lastErr error
	for i := 0; i+1 < len(labels); i++ {
		cand := strings.Join(labels[i:], ".")
		var zones []struct {
			ID string `json:"id"`
		}
		if err := c.do(ctx, http.MethodGet, "/zones", url.Values{"name": {cand}}, nil, &zones); err != nil {
			lastErr = err
			continue
		}
		if len(zones) > 0 {
			if c.zone == nil {
				c.zone = map[string]string{}
			}
			c.zone[name] = zones[0].ID
			return zones[0].ID, nil
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no Cloudflare zone found for %s", name)
}

// Upsert makes name an unproxied A record for ip. It reports whether anything was changed.
func (c *Client) Upsert(ctx context.Context, name, ip string, ttl int) (changed bool, err error) {
	zone, err := c.ZoneID(ctx, name)
	if err != nil {
		return false, err
	}
	var have []Record
	if err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/dns_records", url.Values{"type": {"A"}, "name": {name}}, nil, &have); err != nil {
		return false, err
	}
	want := Record{Type: "A", Name: name, Content: ip, TTL: ttl, Proxied: false}
	switch {
	case len(have) == 0:
		return true, c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", nil, want, nil)
	case have[0].Content == ip && !have[0].Proxied && len(have) == 1:
		return false, nil
	}
	// Update the first record; any duplicates would make the name resolve to a stale exit.
	if err := c.do(ctx, http.MethodPut, "/zones/"+zone+"/dns_records/"+have[0].ID, nil, want, nil); err != nil {
		return false, err
	}
	for _, extra := range have[1:] {
		if err := c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+extra.ID, nil, nil, nil); err != nil {
			return true, err
		}
	}
	return true, nil
}
