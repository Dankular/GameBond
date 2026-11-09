// client is the Go GameBond client daemon (skeleton). It reads a subset of the
// Python client config, starts the netstack helper with --proxy-stdio, and
// bridges its packets over the bonded uplinks. Not yet at Python parity: no
// traffic classification or QoS, usage caps, LAN gateways, OMR, app policy, or
// status files. See docs/go-migration-ledger.md.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"gamebond.local/nativeedge/bond"
	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/stackio"
	"gamebond.local/nativeedge/uplink"
)

// fileConfig is the subset of configs/local-client.json this daemon reads.
type fileConfig struct {
	Session        string  `json:"session"`
	Bind           [][]any `json:"bind"` // [[ip, port], ...] one per uplink; port is ignored (ephemeral)
	Peer           []any   `json:"peer"`
	MTU            int     `json:"mtu"`
	InitialMbps    float64 `json:"bonding_initial_rate_mbps"`
	MaxMbps        float64 `json:"bonding_max_rate_mbps"`
	FailoverReplay bool    `json:"failover_replay"`
	PathMTU        bool    `json:"path_mtu_discovery"`
	InterfaceIndex []int   `json:"interface_indices"` // pin uplink i to this adapter index
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
		specs = append(specs, spec)
	}
	return c, specs, netip.AddrPortFrom(addr, uint16(port)), nil
}

func run() error {
	configPath := flag.String("config", "configs/local-client.json", "client config")
	keyPath := flag.String("key", "secrets/gamebond.key", "shared key file")
	stackPath := flag.String("netstack", "", "path to the netstack executable (required)")
	flag.Parse()
	if *stackPath == "" {
		return fmt.Errorf("-netstack is required")
	}
	cfg, specs, peer, err := load(*configPath)
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
	bridge := &stackio.Bridge{Out: stackio.NewWriter(stdin), OnEvent: func(m map[string]any) {
		if s, ok := m["socks"].(string); ok {
			fmt.Printf("{\"status\":\"stack_ready\",\"socks\":%q}\n", s)
		}
	}}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1280
	}
	c, err := client.New(client.Config{Key: key, Session: session, Server: peer, Uplinks: specs,
		MTU: mtu + bond.Overhead + 24, Discover: cfg.PathMTU, Failover: cfg.FailoverReplay,
		InitialMbps: max(cfg.InitialMbps, 1), MaxMbps: max(cfg.MaxMbps, 100), Deliver: bridge.Deliver})
	if err != nil {
		return err
	}
	bridge.Uplink = c
	if err = stack.Start(); err != nil {
		return err
	}
	errs := make(chan error, 2)
	go func() { errs <- c.Run(ctx) }()
	go func() { errs <- bridge.Pump(stdout) }()
	go func() {
		for ctx.Err() == nil {
			time.Sleep(time.Second)
			s := c.Snapshot()
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
