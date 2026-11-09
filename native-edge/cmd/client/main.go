// client runs the userspace GameBond VPN and its optional restart supervisor.
// It bridges the netstack to one or more uplinks, classifies traffic, applies
// application/link policy, meters usage, and hosts optional OMR/LAN legs.
// Remaining migration evidence and gaps are in docs/go-migration-ledger.md.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"gamebond.local/nativeedge/launcher"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"gamebond.local/nativeedge/adapterwatch"
	"gamebond.local/nativeedge/bond"
	"gamebond.local/nativeedge/carrier"
	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/dns"
	"gamebond.local/nativeedge/linkpolicy"
	"gamebond.local/nativeedge/omr"
	"gamebond.local/nativeedge/procjob"
	"gamebond.local/nativeedge/stackio"
	"gamebond.local/nativeedge/status"
	"gamebond.local/nativeedge/ttyrelay"
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
	InterfaceIDs   []string                     `json:"interface_ids"`     // stable adapter identities across reconnects
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

var configPath = flag.String("config", "configs/local-client.json", "client config")
var keyPath = flag.String("key", "secrets/gamebond.key", "shared key file")
var stackPath = flag.String("netstack", "", "path to the netstack executable (required)")
var usagePath = flag.String("usage", ".runtime/link-usage.json", "link usage ledger shared with the Python runtime")
var ttyPath = flag.String("tty", "", "start the read-only log relay with this metadata file and publish daemon logs to it (empty disables)")
var appCaptureFlag = flag.Bool("app-capture", false, "the netstack runs with the owner-attribution capture extension: authorize and record per-application use (default: deny every request to the bulk profile)")
var historyPath = flag.String("app-history", ".runtime/app-history.json", "first-use application history (empty disables)")
var proxifyreFlag = flag.Bool("proxifyre", false, "stage and start ProxiFyre (WinDivert application capture) once the netstack is ready; verifies the attribution extension and enables app authorization when present. Diverts application traffic: never implicit")
var rootFlag = flag.String("root", ".", "project root (build/ and .runtime/ live here) for -proxifyre")
var proxifyreSource = flag.String("proxifyre-source", `C:\Program Files\ProxiFyre`, "installed ProxiFyre directory copied into .runtime/userspace-proxy")
var statusPath = flag.String("status", ".runtime/userspace-status.json", "status file for the control tooling (empty disables)")
var superviseFlag = flag.Bool("supervise", false, "run under the launcher supervisor: the log relay (-tty) owner accepts stop AND restart, relaunching the tunnel in this process; --stopped/--once as in windows_launcher.py")
var stoppedFlag = flag.Bool("stopped", false, "with -supervise: register the supervisor but wait for an authenticated restart before starting the tunnel")
var onceFlag = flag.Bool("once", false, "with -supervise: exit after one run instead of retaining the restart supervisor")

// session is one tunnel run: everything the Python launcher's app.run does.
// ready is called once the first uplink is ready. A stop requested through
// ctx is a clean end (nil), not an error.
func session(parent context.Context, ready func(), logOut, relayOnly io.Writer) error {
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
	ctx, stop := context.WithCancel(parent)
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
	stack.Stderr = logOut
	stdin, err := stack.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := stack.StdoutPipe()
	if err != nil {
		return err
	}
	bridge := &stackio.Bridge{Classifier: classifier, GamePorts: gamePorts, Profiles: &bond.FlowProfiles{}, ClientIP: cfg.ClientTunnelIP, Out: stackio.NewWriter(stdin)}
	runtimeDir, extensionDir := defaultProxifyreDirs(*rootFlag)
	proxy, err := newProxifyre(proxifyreFlags{enabled: *proxifyreFlag, root: *rootFlag, runtimeDir: runtimeDir,
		extensionDir: extensionDir, source: *proxifyreSource}, *stackPath, rawCfg, logOut)
	if err != nil {
		return err
	}
	defer proxy.close()
	stack.Env = proxy.environment(os.Environ())
	proxyFail := make(chan error, 1)
	capture, err := newAppCapture(*appCaptureFlag || proxy.attribution(), *configPath, *historyPath, rawCfg, func(m map[string]any) error { return bridge.Respond(m) })
	if err != nil {
		return err
	}
	defer capture.close()
	bridge.OnEvent = func(m map[string]any) {
		if s, ok := m["socks"].(string); ok {
			fmt.Printf("{\"status\":\"stack_ready\",\"socks\":%q}\n", s)
		}
		_ = capture.onEvent(m)
	}
	onReady := bridge.OnEvent
	bridge.OnEvent = func(m map[string]any) {
		onReady(m)
		if s, ok := m["socks"].(string); ok {
			proxy.onStackReady(ctx, s, func(e error) {
				select {
				case proxyFail <- e:
				default:
				}
			})
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
		if lanMgr, err = newLanManager(cfg.LANDevices, clientIP, cfg.InterfaceIDs, cfg.InterfaceIndex, cfg.MTU); err != nil {
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
	slots := make([]adapterwatch.Slot, len(specs))
	useInventory := false
	for i, sp := range specs {
		slots[i] = adapterwatch.Slot{Spec: sp, Pinned: i < len(cfg.InterfaceIndex) && cfg.InterfaceIndex[i] != 0}
		if runtime.GOOS == "windows" && i < len(cfg.InterfaceIDs) && cfg.InterfaceIDs[i] != "" {
			slots[i].Identity = cfg.InterfaceIDs[i]
			useInventory = true
		}
	}
	var available []bool
	if useInventory {
		rows, err := uplink.Adapters()
		if err != nil {
			return fmt.Errorf("adapter discovery: %w", err)
		}
		specs, available = adapterwatch.PlanInventory(slots, rows, uplink.InterfaceFor)
	}
	c, err := client.New(client.Config{Key: key, Session: session, Server: peer, Uplinks: specs, Available: available,
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
	// Windows: tie the netstack child to a kill-on-close job so it cannot
	// outlive a crashed daemon (process_job.py). Elsewhere the call fails and
	// CommandContext cleanup is all there is.
	if job, jerr := procjob.New(); jerr == nil {
		defer job.Close()
		if aerr := job.Add(stack.Process.Pid); aerr != nil {
			fmt.Fprintln(logOut, "netstack job assignment failed:", aerr)
		}
	}
	var readyOnce sync.Once
	created := time.Now()
	errs := make(chan error, 3)
	go func() {
		select {
		case e := <-proxyFail:
			errs <- e
		case <-ctx.Done():
		}
	}()
	go func() { errs <- c.Run(ctx) }()
	updateAdapters := func(sp []uplink.Spec, avail []bool) error {
		failed, err := c.UpdateUplinks(sp, avail)
		for _, f := range failed {
			fmt.Fprintln(logOut, "uplink rebind failed:", f)
		}
		if err == nil && len(failed) > 0 {
			return fmt.Errorf("%d uplinks could not bind; retrying", len(failed))
		}
		return err
	}
	onAdapterError := func(err error) { fmt.Fprintln(logOut, "adapter update failed:", err) }
	if useInventory {
		go adapterwatch.RunInventory(ctx, 2*time.Second, slots, uplink.Adapters, uplink.InterfaceFor, updateAdapters, onAdapterError)
	} else {
		go adapterwatch.Run(ctx, 2*time.Second, slots, uplink.InterfaceFor, updateAdapters, onAdapterError)
	}
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
			if s.Ready > 0 {
				readyOnce.Do(ready)
			}
			if meter != nil {
				wire := make([][2]uint64, len(specs))
				for _, p := range s.Paths {
					if p.Local < len(wire) {
						wire[p.Local] = [2]uint64{p.WireTX, p.WireRX}
					}
				}
				if policies, changed, err := meter.Update(wire); err != nil {
					fmt.Fprintln(logOut, "usage metering failed:", err)
				} else if changed {
					if err := c.SetPolicies(policies); err != nil {
						fmt.Fprintln(logOut, "policy update failed:", err)
					}
				}
			}
			if err := capture.flush(); err != nil {
				fmt.Fprintln(logOut, "application history write failed:", err)
			}
			if *statusPath != "" {
				if err := status.WriteJSON(*statusPath, statusDocument(cfg, peer, created, s, bridge, omrStatus, lanMgr, capture, c.DFEnforced())); err != nil {
					fmt.Fprintln(logOut, "status write failed:", err)
				}
			}
			line := fmt.Sprintf("{\"status\":\"running\",\"ready\":%d,\"uplinks\":%d,\"outbound\":%d,\"injected\":%d}\n", s.Ready, s.Uplinks, bridge.Outbound.Load(), bridge.Injected.Load())
			fmt.Print(line)
			if *ttyPath != "" {
				io.WriteString(relayOnly, line)
			}
		}
	}()
	err = <-errs
	stop()
	_ = stack.Wait()
	if parent.Err() != nil {
		return nil // stopped on request
	}
	return err
}

func run() error {
	flag.Parse()
	if *stackPath == "" {
		return fmt.Errorf("-netstack is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var logOut, relayOnly io.Writer = os.Stderr, io.Discard
	if *ttyPath != "" {
		configIdentity, err := filepath.Abs(*configPath)
		if err != nil {
			return err
		}
		relay, err := ttyrelay.Start(ttyrelay.Options{Metadata: *ttyPath, ConfigPath: configIdentity})
		if err != nil {
			return fmt.Errorf("log relay: %w", err)
		}
		defer relay.Close()
		logOut, relayOnly = io.MultiWriter(os.Stderr, relay), relay
	}
	if *superviseFlag {
		if *ttyPath == "" {
			return fmt.Errorf("-supervise needs -tty (the relay is how stop and restart arrive)")
		}
		owner := launcher.NewOwner()
		defer owner.Close()
		go ttyrelay.ServeSupervisor(ctx, *ttyPath, owner, nil)
		status := launcher.Supervise(ctx, owner, func(c context.Context, ready func()) error {
			return session(c, ready, logOut, relayOnly)
		}, launcher.Options{Once: *onceFlag, InitiallyStopped: *stoppedFlag, Log: func(m string) { fmt.Fprintln(logOut, m) }})
		if status != 0 {
			return fmt.Errorf("the tunnel failed (see the log)")
		}
		return nil
	}
	if *ttyPath != "" {
		// Register as the control owner so `ttyrelay control stop` ends the daemon.
		// Restart needs -supervise, which relaunches the tunnel.
		go func() {
			err := ttyrelay.ServeOwner(ctx, *ttyPath, func(command string) (string, error) {
				if command == "stop" {
					stop()
					return "stopping", nil
				}
				return "running", fmt.Errorf("%s needs -supervise: without it the daemon has no supervisor to relaunch it", command)
			})
			if err != nil && ctx.Err() == nil {
				fmt.Fprintln(logOut, "log relay owner ended:", err)
			}
		}()
	}
	return session(ctx, func() {}, logOut, relayOnly)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// statusDocument is the Python-compatible subset of userspace-status.json the
// control tooling reads: identity, state, peer, per-path transport and counters.
func statusDocument(cfg fileConfig, peer netip.AddrPort, created time.Time, s client.Snapshot, b *stackio.Bridge, o *omrState, l *lanManager, capture *appCapture, df []bool) map[string]any {
	state := "connecting"
	if s.Ready > 0 {
		state = "running"
	}
	paths := make([]map[string]any, 0, len(s.Paths))
	for _, p := range s.Paths {
		paths = append(paths, map[string]any{"slot": p.Local, "ready": p.Ready, "healthy": p.Healthy, "suspect": p.Suspect,
			"rtt_ms": p.RTTMilliseconds, "rtt_jitter_ms": p.JitterMilliseconds, "wire_tx_bytes": p.WireTX, "wire_rx_bytes": p.WireRX,
			"policy_confirmed": p.PolicyConfirmed, "remote": p.Endpoint.String(), "mtu": mtuStatus(p, df)})
	}
	doc := map[string]any{"pid": os.Getpid(), "created": float64(created.UnixNano()) / 1e9, "updated_at": float64(time.Now().UnixNano()) / 1e9,
		"state": state, "error": nil, "peer": []any{peer.Addr().String(), peer.Port()}, "backend": "go",
		"transport": map[string]any{"paths": paths},
		"packets":   map[string]any{"outbound": b.Outbound.Load(), "injected": b.Injected.Load(), "dropped": b.Dropped.Load(), "malformed": b.Malformed.Load()},
		"qos":       s.QoS, "link_usage": map[string]any{}, "omr": o.status(), "lan_devices": l.status(), "dns": l.dnsStatus()}
	if capture != nil {
		capture.status(doc)
	}
	return doc
}

// mtuStatus is a path's `mtu` entry (nil without discovery): the prober's
// stats plus skips and whether the socket enforces don't-fragment.
func mtuStatus(p bond.PathSnapshot, df []bool) any {
	if p.MTU == nil {
		return nil
	}
	failed := append([]int{}, p.MTU.FailedSizes...)
	sort.Ints(failed)
	enforced := p.Local >= 0 && p.Local < len(df) && df[p.Local]
	return map[string]any{"path_mtu": p.MTU.PathMTU, "ceiling": p.MTU.Ceiling, "confirmed": p.MTU.Confirmed, "capable": p.MTU.Capable,
		"rounds": p.MTU.Rounds, "acks": p.MTU.Acks, "failed_sizes": failed, "skips": p.MTUSkips, "df_enforced": enforced}
}
