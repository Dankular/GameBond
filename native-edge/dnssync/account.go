package dnssync

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Zone is a domain the credentials can manage.
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ErrExists is returned by Create when the name is already in use, so minting never overwrites a record.
var ErrExists = errors.New("a DNS record with that name already exists")

// Verify checks that the credentials work and are active. A scoped API token is checked with Cloudflare's token
// verification; a legacy global API key (Email and Key) by reading the user.
func (c *Client) Verify(ctx context.Context) error {
	if c.Auth.Token != "" {
		var res struct {
			Status string `json:"status"`
		}
		if err := c.do(ctx, http.MethodGet, "/user/tokens/verify", nil, nil, &res); err != nil {
			return err
		}
		if res.Status != "active" {
			return fmt.Errorf("the API token is %s", orUnknown(res.Status))
		}
		return nil
	}
	var user struct {
		Email string `json:"email"`
	}
	if err := c.do(ctx, http.MethodGet, "/user", nil, nil, &user); err != nil {
		return err
	}
	if c.Auth.Email != "" && user.Email != "" && !strings.EqualFold(user.Email, c.Auth.Email) {
		return errors.New("the API key belongs to a different account than that email address")
	}
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "not active"
	}
	return s
}

// Zones lists the active zones the credentials can see (up to 200).
func (c *Client) Zones(ctx context.Context) ([]Zone, error) {
	var all []Zone
	for page := 1; page <= 4; page++ {
		var zones []Zone
		q := url.Values{"per_page": {"50"}, "status": {"active"}, "page": {fmt.Sprint(page)}}
		if err := c.do(ctx, http.MethodGet, "/zones", q, nil, &zones); err != nil {
			return nil, err
		}
		all = append(all, zones...)
		if len(zones) < 50 {
			break
		}
	}
	return all, nil
}

// Create adds an unproxied A record. Unlike Upsert it refuses to touch a name that already has any record.
func (c *Client) Create(ctx context.Context, name, ip string, ttl int) error {
	zone, err := c.ZoneID(ctx, name)
	if err != nil {
		return err
	}
	var have []Record
	if err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/dns_records", url.Values{"name": {name}}, nil, &have); err != nil {
		return err
	}
	if len(have) > 0 {
		return ErrExists
	}
	return c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", nil, Record{Type: "A", Name: name, Content: ip, TTL: ttl, Proxied: false}, nil)
}

// Delete removes the A records of a name (and nothing else).
func (c *Client) Delete(ctx context.Context, name string) error {
	zone, err := c.ZoneID(ctx, name)
	if err != nil {
		return err
	}
	var have []Record
	if err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/dns_records", url.Values{"type": {"A"}, "name": {name}}, nil, &have); err != nil {
		return err
	}
	for _, r := range have {
		if err := c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+r.ID, nil, nil, nil); err != nil {
			return err
		}
	}
	return nil
}
