package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/dnssync"
)

// reverseDNSConfig is the "reverse_dns" object: keep Name pointing at the exit node in use.
// The credential is read from SecretFile (a single line; never put it in this config). With Email set it
// is a Cloudflare global API key, otherwise a scoped API token.
type reverseDNSConfig struct {
	Name       string `json:"name"`
	SecretFile string `json:"secret_file"`
	Email      string `json:"email"`
	TTL        int    `json:"ttl"` // seconds, default 60
}

const (
	reverseDNSRecheck = 15 * time.Minute // re-verify the record now and then, in case it was edited
	reverseDNSMaxWait = 5 * time.Minute
)

// reverseDNS points a DNS name at the active exit whenever the tunnel is connected and the exit changes.
type reverseDNS struct {
	cfg reverseDNSConfig
	cf  *dnssync.Client

	mu      sync.Mutex
	applied string // exit address the record last matched
	at      time.Time
	err     string
	changed time.Time
}

func newReverseDNS(root string, c reverseDNSConfig) (*reverseDNS, error) {
	if c.Name == "" {
		return nil, nil
	}
	if c.SecretFile == "" {
		return nil, fmt.Errorf("reverse_dns needs secret_file")
	}
	raw, err := os.ReadFile(resolvePath(root, c.SecretFile))
	if err != nil {
		return nil, fmt.Errorf("reverse_dns secret_file: %w", err)
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return nil, fmt.Errorf("reverse_dns secret_file is empty")
	}
	auth := dnssync.Auth{Token: secret}
	if c.Email != "" {
		auth = dnssync.Auth{Email: c.Email, Key: secret}
	}
	if c.TTL <= 0 {
		c.TTL = 60
	}
	return &reverseDNS{cfg: c, cf: &dnssync.Client{Auth: auth}}, nil
}

// run checks once a second. It acts only while at least one path is ready (the tunnel is up), so a
// name is never pointed at an exit the client cannot reach.
func (r *reverseDNS) run(ctx context.Context, snap func() client.Snapshot, log func(string)) {
	wait := time.Second
	var next time.Time
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s := snap()
			if s.Ready == 0 || !s.Exit.Active.IsValid() {
				continue
			}
			ip := s.Exit.Active.Addr().String()
			r.mu.Lock()
			current := r.applied == ip && now.Sub(r.at) < reverseDNSRecheck
			r.mu.Unlock()
			if current || now.Before(next) {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			changed, err := r.cf.Upsert(cctx, r.cfg.Name, ip, r.cfg.TTL)
			cancel()
			r.mu.Lock()
			if err != nil {
				r.err = err.Error()
				wait = min(wait*2, reverseDNSMaxWait)
				next = now.Add(wait)
				r.mu.Unlock()
				log("reverse_dns: " + err.Error())
				continue
			}
			wait, next = time.Second, time.Time{}
			prev := r.applied
			r.applied, r.at, r.err = ip, now, ""
			if changed {
				r.changed = now
			}
			r.mu.Unlock()
			if changed || prev != ip {
				log(fmt.Sprintf("reverse_dns: %s -> %s", r.cfg.Name, ip))
			}
		}
	}
}

// status is the "reverse_dns" object of the status document.
func (r *reverseDNS) status() any {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	m := map[string]any{"name": r.cfg.Name, "address": r.applied, "ok": r.err == "" && r.applied != ""}
	if r.err != "" {
		m["error"] = r.err
	}
	if !r.at.IsZero() {
		m["verified_ago_s"] = time.Since(r.at).Seconds()
	}
	if !r.changed.IsZero() {
		m["changed_ago_s"] = time.Since(r.changed).Seconds()
	}
	return m
}
