package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"gamebond.local/nativeedge/nat"
	"gamebond.local/nativeedge/omr"
	"gamebond.local/nativeedge/router"
)

// This file is the Go side of userspace.py's maintain_omr/build_router: with
// server_type "both" the GameBond tunnel gets an OMR (Glorytun UDP) tunnel
// beside it behind one router. A failing OMR leg is reported and retried every
// 30 s; it never stops the GameBond tunnel, and a refused admin login is never
// retried.

const omrRetry = 30 * time.Second

// gbUplink is what the routed uplink needs from the GameBond client.
type gbUplink interface{ Submit(bond.QueuedPacket) bool }

// routedUplink is the stackio.Uplink and the client Deliver sink. Until the
// OMR leg is up it is a pass-through.
type routedUplink struct {
	gb      gbUplink
	deliver func([]byte)
	ready   func() bool
	probe   func([]byte) bool // consumes echo replies to the SLO probe

	mu  sync.Mutex // serialises Submit so cur is the packet being routed
	cur bond.QueuedPacket
	rt  atomic.Pointer[router.Router]
}

// Send satisfies router.GameBondTransport using the queue entry of the packet
// currently being routed.
func (u *routedUplink) Send(payload []byte, replicate bool, flowID string, urgent bool) bool {
	q := u.cur
	q.Payload, q.Replicate, q.Flow = payload, replicate, flowID
	q.Priority = q.Priority || urgent
	return u.gb.Submit(q)
}

// Ready: at least one GameBond path is ready.
func (u *routedUplink) Ready() bool { return u.ready != nil && u.ready() }

// Submit routes by DSCP when the OMR leg is up.
func (u *routedUplink) Submit(q bond.QueuedPacket) bool {
	rt := u.rt.Load()
	if rt == nil {
		return u.gb.Submit(q)
	}
	dscp := 0
	if len(q.Payload) >= 2 {
		dscp = int(q.Payload[1] >> 2)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.cur = q
	return rt.Send(q.Payload, q.Replicate, q.Flow, q.Priority, dscp) > 0
}

// Deliver is the client's Deliver callback.
func (u *routedUplink) Deliver(p []byte) {
	if u.probe != nil && u.probe(p) {
		return
	}
	if rt := u.rt.Load(); rt != nil {
		rt.Receive(router.GameBond, p)
		return
	}
	u.deliver(p)
}

// omrState is what the status document reports.
type omrState struct {
	mu      sync.Mutex
	mode    string
	active  bool
	err     string
	blocked bool
}

func (s *omrState) set(active bool, err string, blocked bool) {
	s.mu.Lock()
	s.active, s.err, s.blocked = active, err, blocked
	s.mu.Unlock()
}

func (s *omrState) status() any {
	if s == nil || s.mode != "both" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var e any
	if s.err != "" {
		e = s.err
	}
	return map[string]any{"mode": "both", "active": s.active, "error": e, "blocked": s.blocked}
}

func resolvePath(root, name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(root, name)
}

// credentials is omr_credentials: the key and tunnel address from a key file,
// or from the admin API behind a pinned certificate.
func credentials(root string, s *omr.Settings) ([]byte, string, error) {
	if s.Admin == nil {
		raw, err := os.ReadFile(resolvePath(root, s.KeyFile))
		if err != nil {
			return nil, "", err
		}
		key, err := omr.ParseKey(string(raw))
		return key, s.TunnelIP, err
	}
	pw, err := os.ReadFile(resolvePath(root, s.Admin.PasswordFile))
	if err != nil {
		return nil, "", err
	}
	a, err := omr.NewAdminClient(s.Admin.Host, s.Admin.Port, s.Admin.Pin, 0)
	if err != nil {
		return nil, "", err
	}
	if err := a.Login(s.Admin.Username, strings.TrimSpace(string(pw))); err != nil { // one attempt
		return nil, "", err
	}
	cfg, err := a.GetConfig()
	if err != nil {
		return nil, "", err
	}
	info, err := omr.TunnelSettings(cfg)
	if err != nil {
		return nil, "", err
	}
	ip := s.TunnelIP
	if !s.TunnelIPSet && info.TunnelIP != "" {
		ip = info.TunnelIP
	}
	return info.Key, ip, nil
}

// omrLeg owns the retry loop.
type omrLeg struct {
	settings *omr.Settings
	root     string
	locals   []string
	indices  []int
	up       *routedUplink
	state    *omrState
	out      func(map[string]any) // JSON status line
	closers  []func()
}

func (l *omrLeg) bringUp() error {
	key, tunnelIP, err := credentials(l.root, l.settings)
	if err != nil {
		return err
	}
	avail := make([]bool, len(l.locals))
	any4 := false
	for i, ip := range l.locals {
		a, err := netip.ParseAddr(ip)
		avail[i] = err == nil && !a.IsUnspecified()
		any4 = any4 || avail[i]
	}
	if !any4 {
		return errors.New("No available uplink address for the OMR tunnel")
	}
	ext, err := netip.ParseAddr(tunnelIP)
	if err != nil {
		return fmt.Errorf("omr tunnel address %q is not usable", tunnelIP)
	}
	server, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", l.settings.ServerHost(), l.settings.ServerPort()))
	if err != nil {
		return fmt.Errorf("omr server: %w", err)
	}
	mc, err := omr.NewClient(omr.Config{Key: key, Server: server, LocalIPs: l.locals, RateMbps: l.settings.RateMbps,
		BeatMS: l.settings.BeatMS, IfaceIndices: l.indices, Available: avail})
	if err != nil {
		return err
	}
	mc.Start()
	n, err := nat.New(ext, 0, 0, 0)
	if err != nil {
		mc.Close()
		return err
	}
	rt := router.New(l.up, &omrAdapter{mc}, n, l.settings.GamebondDSCP, 0, 0)
	go func() {
		for p := range mc.Inbox() {
			rt.Receive(router.OMR, p)
		}
	}()
	go func() {
		for p := range rt.Inbox() {
			l.up.deliver(p)
		}
	}()
	l.up.rt.Store(rt)
	l.closers = append(l.closers, mc.Close)
	return nil
}

type omrAdapter struct{ c *omr.Client }

func (a *omrAdapter) Send(p []byte, urgent bool) bool { return a.c.Send(p, urgent) }
func (a *omrAdapter) Ready() bool                     { return a.c.Ready() }

// run retries until the leg is up, the login is refused, or stop closes.
func (l *omrLeg) run(stop <-chan struct{}) {
	last := ""
	for {
		err := l.bringUp()
		if err == nil {
			l.state.set(true, "", false)
			l.out(map[string]any{"status": "omr_leg_up", "server": []any{l.settings.ServerHost(), l.settings.ServerPort()}})
			return
		}
		msg := err.Error()
		blocked := errors.Is(err, omr.ErrAuth)
		if blocked {
			msg += ". Not retrying; fix the login and reconnect."
		}
		l.state.set(false, msg, blocked)
		if msg != last {
			l.out(map[string]any{"status": "omr_leg_unavailable", "error": msg})
			last = msg
		}
		if blocked {
			return
		}
		select {
		case <-stop:
			return
		case <-time.After(omrRetry):
		}
	}
}
