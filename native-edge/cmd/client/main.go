// client is the Go GameBond client daemon (skeleton). It reads a subset of the
// Python client config, starts the netstack helper with --proxy-stdio, and
// bridges its packets over the bonded uplinks. Not yet at Python parity: no
// traffic classification or QoS, usage caps, LAN gateways, OMR, app policy, or
// status files. See docs/go-migration-ledger.md.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"time"

	"gamebond.local/nativeedge/bond"
	"gamebond.local/nativeedge/carrier"
	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/dns"
	"gamebond.local/nativeedge/linkpolicy"
	"gamebond.local/nativeedge/omr"
	"gamebond.local/nativeedge/stackio"
	"gamebond.local/nativeedge/status"
	"gamebond.local/nativeedge/uplink"
)

// fileConfig is the subset of configs/local-client.json this daemon reads.
type fileConfig struct {
	Session        string                       `json:"session"`
	Bind           [][]any                      `json:"bind"` // [[ip, port], ...] one per uplink; port is ignored (ephemeral)
	Peer           []any                        `json:"peer"`
	MTU            int                          `json:"mtu"`
	InitialMbps    float64                      `json:"bonding_initial_rate_mbps"`
	MaxMbps        float64                      `json:"bonding_max_rate_mbps"`
	FailoverReplay bool                         `json:"failover_replay"`
	LinkPolicies   map[string]linkpolicy.Policy `json:"link_policies"` // keyed by interface index, as in Python
	GameUDPPorts   []uint16                     `json:"game_udp_ports"`
	LossTracking   bool                         `json:"loss_tracking"`
	PathMTU        bool                         `json:"path_mtu_discovery"`
	InterfaceIndex []int                        `json:"interface_indices"` // pin uplink i to this adapter index
	AdaptiveQoS    json.RawMessage              `json:"adaptive_qos"`
	ClientTunnelIP string                       `json:"client_tunnel_ip"`
	LANDevices     json.RawMessage              `json:"lan_devices"`
	DNS            json.RawMessage              `json:"dns"`
	OuterTransport json.RawMessage              `json:"outer_transport"` // stream-carrier fallback; null/absent = UDP only
}

func load(path string) (fileConfig, []uplink.Spec, netip.AddrPort, error) {
	var c fileConfig
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, nil, netip.AddrPort{}, err
	}
	if err = json.Unmarshal(raw, &c); err != nil {
		return c, nil, netip.AddrPort{}, err
	}
	if len(c.Peer) != 2 {
		return c, nil, netip.AddrPort{}, fmt.Errorf("config peer must be [host, port]")
	}
	host, _ := c.Peer[0].(string)
	port, _ := c.Peer[1].(float64)
	addr, err := netip.ParseAddr(host)
	if err != nil || port < 1 || port > 65535 {
		return c, nil, netip.AddrPort{}, fmt.Errorf("invalid peer")
	}
	var specs []uplink.Spec
	for i, b := range c.Bind {
		if len(b) < 1 {
			return c, nil, netip.AddrPort{}, fmt.Errorf("invalid bind %d", i)
		}
		s, _ := b[0].(string)
		a, err := netip.ParseAddr(s)
		if err != nil {
			return c, nil, netip.AddrPort{}, fmt.Errorf("invalid bind %d: %v", i, err)
		}
		spec := uplink.Spec{Addr: a, Buffer: 4 << 20}
		if i < len(c.InterfaceIndex) {
			spec.InterfaceIndex = c.InterfaceIndex[i]
		}
		if spec.InterfaceIndex == 0 && a.IsValid() && !a.IsUnspecified() {
			// No index configured: pin to the adapter that owns the bind address.
			if idx, _, err := uplink.InterfaceFor(a); err == nil {
				spec.InterfaceIndex = idx
			}
		}
		specs = append(specs, spec)
	}
	return c, specs, netip.AddrPortFrom(addr, uint16(port)), nil
}

// qosFromConfig is QoSSettings(**config.get('adaptive_qos', {})): defaults for
// omitted keys, unknown keys and invalid values rejected.
func qosFromConfig(raw json.RawMessage) (bond.QoSSettings, error) {
	set := bond.DefaultQoSSettings()
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return set, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&set); err != nil {
		return set, fmt.Errorf("adaptive_qos: %w", err)
	}
	if err := set.Validate(); err != nil {
		return set, fmt.Errorf("adaptive_qos: invalid settings")
	}
	return set, nil
}

// outerSettings parses outer_transport like OuterSettings(**dict): defaults for
// omitted timers, unknown keys rejected, the same validation.
func outerSettings(raw json.RawMessage) (*carrier.Settings, error) {
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	set := carrier.DefaultSettings()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&set); err != nil {
		return nil, fmt.Errorf("outer_transport: %w", err)
	}
	if err := set.Validate(); err != nil {
		return nil, fmt.Errorf("outer_transport: %w", err)
	}
	return &set, nil
}

func run() error {
	configPath := flag.String("config", "configs/local-client.json", "client config")
	keyPath := flag.String("key", "secrets/gamebond.key", "shared key file")
	stackPath := flag.String("netstack", "", "path to the netstack executable (required)")
	usagePath := flag.String("usage", ".runtime/link-usage.json", "link usage ledger shared with the Python runtime")
	statusPath := flag.String("status", ".runtime/userspace-status.json", "status file for the control tooling (empty disables)")
	flag.Parse()
	if *stackPath == "" {
		return fmt.Errorf("-netstack is required")
	}
	cfg, specs, peer, err := load(*configPath)
	if err != nil {
		return err
	}
	rawCfg, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	cfgMap, err := omr.ParseConfig(rawCfg)
	if err != nil {
		return err
	}
	serverMode, omrSettings, err := omr.LoadServerMode(cfgMap)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	session, err := hex.DecodeString(cfg.Session)
	if err != nil {
		return fmt.Errorf("invalid session: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	qosSettings, err := qosFromConfig(cfg.AdaptiveQoS)
	if err != nil {
		return err
	}
	classifier, err := bond.NewClassifier(nil, cfg.GameUDPPorts, qosSettings)
	if err != nil {
		return err
	}
	gamePorts := map[uint16]bool{}
	for _, p := range cfg.GameUDPPorts {
		gamePorts[p] = true
	}
	stack := exec.CommandContext(ctx, *stackPath, "--proxy-stdio")
	stack.Stderr = os.Stderr
	stdin, err := stack.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := stack.StdoutPipe()
	if err != nil {
		return err
	}
	bridge := &stackio.Bridge{Classifier: classifier, GamePorts: gamePorts, Out: stackio.NewWriter(stdin)}
	bridge.OnEvent = func(m map[string]any) {
		if s, ok := m["socks"].(string); ok {
			fmt.Printf("{\"status\":\"stack_ready\",\"socks\":%q}\n", s)
		}
		// Application capture is not ported: deny every request to the bulk
		// profile, exactly what the Python runtime answers without the
		// capture extension.
		if m["type"] == "app_authorization_request" {
			if id, ok := m["id"].(string); ok && len(id) == 24 {
				_ = bridge.Respond(map[string]any{"type": "app_authorization_response", "id": id, "allow": false, "profile": "bulk"})
			}
		}
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1280
	}
	outer, err := outerSettings(cfg.OuterTransport)
	if err != nil {
		return err
	}
	var lanMgr *lanManager
	if len(cfg.LANDevices) > 0 && string(cfg.LANDevices) != "null" && string(cfg.LANDevices) != "[]" {
		clientIP, perr := netip.ParseAddr(cfg.ClientTunnelIP)
		if perr != nil {
			return fmt.Errorf("lan_devices needs a valid client_tunnel_ip: %w", perr)
		}
		if lanMgr, err = newLanManager(cfg.LANDevices, clientIP, cfg.InterfaceIndex, cfg.MTU); err != nil {
			return err
		}
		dnsCfg, derr := dns.Load(cfg.DNS)
		if derr != nil {
			return derr
		}
		if dnsCfg != nil && dnsCfg.Enabled {
			lanMgr.dnsFn = dnsCfg.Override
		}
		lanMgr.outbound = bridge.Send
		lanMgr.out = func(m map[string]any) { b, _ := json.Marshal(m); fmt.Println(string(b)) }
		defer lanMgr.close()
	}
	routed := &routedUplink{deliver: func(p []byte) {
		if !lanMgr.dispatch(p) {
			bridge.Deliver(p)
		}
	}}
	c, err := client.New(client.Config{Key: key, Session: session, Server: peer, Uplinks: specs,
		MTU: mtu + bond.Overhead + 24, Discover: cfg.PathMTU, Failover: cfg.FailoverReplay,
		InitialMbps: max(cfg.InitialMbps, 1), MaxMbps: max(cfg.MaxMbps, 100), Deliver: routed.Deliver, Outer: outer, QoS: &qosSettings, LossTracking: cfg.LossTracking})
	if err != nil {
		return err
	}
	routed.gb = c
	routed.ready = func() bool { return c.Snapshot().Ready > 0 }
	bridge.Uplink = routed
	omrStatus := &omrState{mode: serverMode}
	var meter *linkpolicy.Meter
	if len(cfg.LinkPolicies) > 0 {
		keys := make([]string, len(specs))
		policies := make([]linkpolicy.Policy, len(specs))
		for i := range specs {
			keys[i] = strconv.Itoa(i) // no adapter index configured: key by uplink slot
			if i < len(cfg.InterfaceIndex) && cfg.InterfaceIndex[i] != 0 {
				keys[i] = strconv.Itoa(cfg.InterfaceIndex[i]) // as in the Python config
			}
			p, ok := cfg.LinkPolicies[keys[i]]
			if !ok {
				return fmt.Errorf("link_policies has no entry for uplink %d (key %q)", i, keys[i])
			}
			if err := p.Validate(); err != nil {
				return fmt.Errorf("link policy %q: %w", keys[i], err)
			}
			policies[i] = p
		}
		ledger, err := linkpolicy.OpenLedger(*usagePath)
		if err != nil {
			return err
		}
		meter = linkpolicy.NewMeter(ledger, keys, policies)
	}
	if err = stack.Start(); err != nil {
		return err
	}
	created := time.Now()
	errs := make(chan error, 2)
	go func() { errs <- c.Run(ctx) }()
	if lanMgr != nil {
		go func() {
			for ctx.Err() == nil {
				lanMgr.maintain(ctx)
				time.Sleep(time.Second)
			}
		}()
	}
	if serverMode == "both" {
		locals := make([]string, len(specs))
		for i, sp := range specs {
			locals[i] = sp.Addr.String()
		}
		root, _ := os.Getwd()
		leg := &omrLeg{settings: omrSettings, root: root, locals: locals, indices: cfg.InterfaceIndex, up: routed, state: omrStatus,
			out: func(m map[string]any) { b, _ := json.Marshal(m); fmt.Println(string(b)) }}
		go leg.run(ctx.Done())
	}
	go func() { errs <- bridge.Pump(stdout) }()
	go func() {
		for ctx.Err() == nil {
			time.Sleep(time.Second)
			s := c.Snapshot()
			if meter != nil {
				wire := make([][2]uint64, len(specs))
				for _, p := range s.Paths {
					if p.Local < len(wire) {
						wire[p.Local] = [2]uint64{p.WireTX, p.WireRX}
					}
				}
				if policies, changed, err := meter.Update(wire); err != nil {
					fmt.Fprintln(os.Stderr, "usage metering failed:", err)
				} else if changed {
					if err := c.SetPolicies(policies); err != nil {
						fmt.Fprintln(os.Stderr, "policy update failed:", err)
					}
				}
			}
			if *statusPath != "" {
				if err := status.WriteJSON(*statusPath, statusDocument(cfg, peer, created, s, bridge, omrStatus, lanMgr)); err != nil {
					fmt.Fprintln(os.Stderr, "status write failed:", err)
				}
			}
			fmt.Printf("{\"status\":\"running\",\"ready\":%d,\"uplinks\":%d,\"outbound\":%d,\"injected\":%d}\n", s.Ready, s.Uplinks, bridge.Outbound.Load(), bridge.Injected.Load())
		}
	}()
	err = <-errs
	stop()
	_ = stack.Wait()
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// statusDocument is the Python-compatible subset of userspace-status.json the
// control tooling reads: identity, state, peer, per-path transport and counters.
func statusDocument(cfg fileConfig, peer netip.AddrPort, created time.Time, s client.Snapshot, b *stackio.Bridge, o *omrState, l *lanManager) map[string]any {
	state := "connecting"
	if s.Ready > 0 {
		state = "running"
	}
	paths := make([]map[string]any, 0, len(s.Paths))
	for _, p := range s.Paths {
		paths = append(paths, map[string]any{"slot": p.Local, "ready": p.Ready, "healthy": p.Healthy, "suspect": p.Suspect,
			"rtt_ms": p.RTTMilliseconds, "rtt_jitter_ms": p.JitterMilliseconds, "wire_tx_bytes": p.WireTX, "wire_rx_bytes": p.WireRX,
			"policy_confirmed": p.PolicyConfirmed, "remote": p.Endpoint.String()})
	}
	return map[string]any{"pid": os.Getpid(), "created": float64(created.UnixNano()) / 1e9, "updated_at": float64(time.Now().UnixNano()) / 1e9,
		"state": state, "error": nil, "peer": []any{peer.Addr().String(), peer.Port()}, "backend": "go",
		"transport": map[string]any{"paths": paths},
		"packets":   map[string]any{"outbound": b.Outbound.Load(), "injected": b.Injected.Load(), "dropped": b.Dropped.Load(), "malformed": b.Malformed.Load()},
		"qos":       s.QoS, "link_usage": map[string]any{}, "omr": o.status(), "lan_devices": l.status(), "dns": l.dnsStatus()}
}
