package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"gamebond.local/nativeedge/lan"
)

const localNetworkRetry = 5 * time.Second

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

type localNetworkManager struct {
	config  lan.LocalConfig
	router  *lan.LocalRouter
	mtu     int
	open    func(lan.NetworkConfig) (lan.FrameIO, error)
	mu      sync.Mutex
	errors  map[string]string
	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newLocalNetworkManager(networksRaw, routesRaw json.RawMessage, uplinkIDs, deviceAdapters []string, uplinkIndices, deviceIndices []int, mtu int) (*localNetworkManager, error) {
	config, err := lan.LoadLocalConfig(networksRaw, routesRaw, uplinkIDs, deviceAdapters, uplinkIndices, deviceIndices)
	if err != nil {
		return nil, err
	}
	if len(config.Networks) == 0 {
		return nil, nil
	}
	ports := make([]lan.FramePort, 0, len(config.Networks))
	for _, network := range config.Networks {
		ports = append(ports, lan.FramePort{Network: network})
	}
	router, err := lan.NewLocalRouter(config, ports, nil, nil, time.Now)
	if err != nil {
		return nil, err
	}
	if mtu <= 0 {
		mtu = lan.DefaultTunnelM
	}
	router.SetTunnelMTU(mtu)
	return &localNetworkManager{config: config, router: router, mtu: mtu, open: openLocalNetworkFrameIO, errors: map[string]string{}}, nil
}

func (m *localNetworkManager) useLeaseTable(path string) {
	if m == nil || path == "" {
		return
	}
	// Rebuild before start so every per-network DHCP server shares this table.
	ports := make([]lan.FramePort, 0, len(m.config.Networks))
	for _, network := range m.config.Networks {
		ports = append(ports, lan.FramePort{Network: network})
	}
	router, err := lan.NewLocalRouter(m.config, ports, lan.OpenPoolLeaseTable(path), nil, time.Now)
	if err == nil {
		router.SetTunnelMTU(m.mtu)
		m.router = router
	}
}

func (m *localNetworkManager) start(parent context.Context) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel, m.started = cancel, true
	m.mu.Unlock()
	for _, network := range m.config.Networks {
		m.wg.Add(1)
		go m.runNetwork(ctx, network)
	}
}

func (m *localNetworkManager) runNetwork(ctx context.Context, network lan.NetworkConfig) {
	defer m.wg.Done()
	for ctx.Err() == nil {
		io, err := m.open(network)
		if err != nil {
			m.setError(network.Name, err)
			if !waitContext(ctx, localNetworkRetry) {
				return
			}
			continue
		}
		if err := m.router.SetPort(network.Name, io); err != nil {
			_ = io.Close()
			m.setError(network.Name, err)
			if !waitContext(ctx, localNetworkRetry) {
				return
			}
			continue
		}
		m.setError(network.Name, nil)
		for ctx.Err() == nil {
			frame, readErr := io.Read(250 * time.Millisecond)
			if readErr != nil {
				if ctx.Err() != nil {
					break
				}
				m.setError(network.Name, readErr)
				break
			}
			if len(frame) != 0 {
				m.router.HandleFrame(localIdentity(network), frame)
			}
		}
		_ = io.Close()
		_ = m.router.SetPort(network.Name, nil)
		if ctx.Err() != nil {
			return
		}
		if !waitContext(ctx, localNetworkRetry) {
			return
		}
	}
}

func localIdentity(network lan.NetworkConfig) string {
	return network.Identity()
}

func (m *localNetworkManager) setError(name string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		delete(m.errors, name)
		return
	}
	m.errors[name] = err.Error()
}

func (m *localNetworkManager) dispatchTunnel(packet []byte) bool {
	return m != nil && m.router != nil && m.router.ForwardFromTunnel(packet)
}

func (m *localNetworkManager) status() any {
	if m == nil {
		return []any{}
	}
	state := m.router.Status()
	rows, _ := state["networks"].([]map[string]any)
	m.mu.Lock()
	for _, row := range rows {
		if message := m.errors[row["name"].(string)]; message != "" {
			row["error"] = message
		}
	}
	m.mu.Unlock()
	return state
}

func (m *localNetworkManager) close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
}

func localDeviceAdapterKeys(raw json.RawMessage, client netip.Addr, uplinkIDs []string, uplinkIndices []int) ([]string, []int, error) {
	devices, err := lan.LoadDevices(raw, client, uplinkIDs, uplinkIndices)
	if err != nil {
		return nil, nil, err
	}
	var adapters []string
	var indices []int
	for _, device := range devices {
		if device.InterfaceID != "" {
			adapters = append(adapters, device.InterfaceID)
		} else if device.InterfaceName != "" {
			adapters = append(adapters, "name:"+device.InterfaceName)
		}
		if device.InterfaceIndex > 0 {
			indices = append(indices, device.InterfaceIndex)
		}
	}
	return adapters, indices, nil
}

func localClientAddress(raw string) (netip.Addr, error) {
	address, err := netip.ParseAddr(raw)
	if err != nil || !address.Is4() {
		return netip.Addr{}, errors.New("local networks need a valid client_tunnel_ip")
	}
	return address, nil
}

func localConfigError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("local networks: %w", err)
}
