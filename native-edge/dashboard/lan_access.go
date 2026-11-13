package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"

	"gamebond.local/nativeedge/lan"
)

// lanAccess serves the device allow/block lists and the pending approvals. The lists are
// lan-access.json next to the status file; the running client reloads it within a second,
// so accepting a device needs no reconnect.
func (s *Server) lanAccess(w http.ResponseWriter, r *http.Request) {
	dir := filepath.Dir(s.o.StatusPath)
	accessPath, pendingPath := filepath.Join(dir, "lan-access.json"), filepath.Join(dir, "lan-pending.json")
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := readConfig(s.o.ConfigPath)
	if err != nil {
		reply(w, 500, map[string]any{"error": err.Error()})
		return
	}
	switch r.Method {
	case http.MethodGet:
		reply(w, 200, s.accessView(accessPath, pendingPath, cfg))
	case http.MethodPost:
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		var req struct {
			Action string `json:"action"`
			MAC    string `json:"mac"`
			Name   string `json:"name"`
			Mode   string `json:"mode"`
			IP     string `json:"ip"` // optional fixed address for accept; empty picks the next free one
		}
		if err != nil || json.Unmarshal(raw, &req) != nil {
			reply(w, 400, map[string]any{"error": "invalid request"})
			return
		}
		if err := s.applyAccess(accessPath, pendingPath, cfg, req.Action, req.MAC, req.Name, req.Mode, req.IP); err != nil {
			reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		reply(w, 200, s.accessView(accessPath, pendingPath, cfg))
	default:
		reply(w, 405, map[string]any{"error": "GET or POST only"})
	}
}

func (s *Server) accessView(accessPath, pendingPath string, cfg map[string]any) map[string]any {
	a := lan.LoadAccess(accessPath)
	pending := lan.LoadPending(pendingPath)
	live := pending[:0:0]
	for _, p := range pending { // the client removes decided entries within a second
		if !a.IsAccepted(p.MAC) && !a.IsBlocked(p.MAC) {
			live = append(live, p)
		}
	}
	return map[string]any{"mode": a.Mode, "accepted": a.Accepted, "blocked": a.Blocked, "pending": live}
}

func (s *Server) applyAccess(accessPath, pendingPath string, cfg map[string]any, action, mac, name, mode string, fixedIP ...string) error {
	if action == "mode" {
		if mode != lan.AccessClosed && mode != lan.AccessAsk && mode != lan.AccessAuto {
			return errors.New("mode must be closed, ask or auto")
		}
		return lan.UpdateAccess(accessPath, func(a *lan.Access) error { a.Mode = mode; return nil })
	}
	norm, err := lan.NormMAC(mac)
	if err != nil {
		return err
	}
	hostname := ""
	for _, p := range lan.LoadPending(pendingPath) {
		if p.MAC == norm {
			hostname = p.Hostname
		}
	}
	if name == "" {
		name = lan.DefaultDeviceName(hostname, norm)
	} else {
		name = lan.DefaultDeviceName(name, norm)
	}
	switch action {
	case "accept":
		clientIP, _ := cfg["client_tunnel_ip"].(string)
		client, perr := netip.ParseAddr(clientIP)
		if perr != nil {
			client = netip.MustParseAddr("10.77.0.2")
		}
		var devices []struct {
			TunnelIP string `json:"tunnel_ip"`
		}
		_ = typedValue(cfg["lan_devices"], &devices)
		var taken []string
		for _, d := range devices {
			taken = append(taken, d.TunnelIP)
		}
		return lan.UpdateAccess(accessPath, func(a *lan.Access) error {
			for _, e := range a.Accepted {
				taken = append(taken, e.IP)
			}
			ip := ""
			if i := indexOf(a.Accepted, norm); i >= 0 {
				ip = a.Accepted[i].IP
			}
			if want := ""; len(fixedIP) > 0 {
				want = strings.TrimSpace(fixedIP[0])
				if want != "" {
					if err := checkFixedIP(client, want, taken, norm, a.Accepted); err != nil {
						return err
					}
					ip = want
				}
			}
			if ip == "" {
				if ip = lan.NextFreeIP(client, taken); ip == "" {
					return errors.New("no free tunnel address left")
				}
			}
			a.Accept(lan.AccessEntry{MAC: norm, Name: name, IP: ip})
			return nil
		})
	case "decline", "block":
		return lan.UpdateAccess(accessPath, func(a *lan.Access) error { a.Block(lan.AccessEntry{MAC: norm, Name: name}); return nil })
	case "unblock":
		return lan.UpdateAccess(accessPath, func(a *lan.Access) error { a.Unblock(norm); return nil })
	case "remove":
		return lan.UpdateAccess(accessPath, func(a *lan.Access) error { a.Remove(norm); return nil })
	}
	return errors.New("unknown action")
}

func indexOf(list []lan.AccessEntry, mac string) int {
	for i, e := range list {
		if e.MAC == mac {
			return i
		}
	}
	return -1
}

// checkFixedIP vets an address an operator chose for a device: a usable host address of the tunnel subnet that no
// other device holds. The server accepts 10.77.0.3 to 10.77.0.254, so the same range is required here.
func checkFixedIP(client netip.Addr, want string, taken []string, mac string, accepted []lan.AccessEntry) error {
	ip, err := netip.ParseAddr(want)
	if err != nil || !ip.Is4() || ip.String() != want {
		return fmt.Errorf("%q is not an IPv4 address", want)
	}
	c, w := client.As4(), ip.As4()
	if c[0] != w[0] || c[1] != w[1] || c[2] != w[2] || w[3] < 3 || w[3] > 254 || ip == client {
		return fmt.Errorf("%s is not usable: pick an address from %d.%d.%d.3 to %d.%d.%d.254 other than the client's", want, c[0], c[1], c[2], c[0], c[1], c[2])
	}
	for _, e := range accepted {
		if e.IP == want && e.MAC != mac {
			return fmt.Errorf("%s is already used by %s", want, e.MAC)
		}
	}
	for _, t := range taken {
		if t == want {
			held := false
			for _, e := range accepted {
				held = held || (e.IP == want && e.MAC == mac)
			}
			if !held {
				return fmt.Errorf("%s is already used by another device", want)
			}
		}
	}
	return nil
}
