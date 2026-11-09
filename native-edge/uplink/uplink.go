// Package uplink opens the per-uplink UDP sockets of the Go client. Each uplink
// is pinned to one physical adapter so bonded traffic really leaves on distinct
// links: bound to the adapter's local address and, where the OS supports it,
// forced out of that adapter regardless of the routing table.
package uplink

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// Spec identifies one uplink. Addr is the adapter's local IPv4 address (the
// zero address binds the wildcard). Interface is the OS interface name or empty;
// when set it selects the egress adapter (IP_UNICAST_IF on Windows,
// SO_BINDTODEVICE on Linux).
type Spec struct {
	Addr      netip.Addr
	Interface string
	// Buffer is the socket send and receive buffer in bytes (0 keeps the default).
	Buffer int
}

var ErrUnsupported = errors.New("uplink: adapter pinning is not supported on this platform")

// Open returns a UDP socket for the uplink on an ephemeral port.
func Open(s Spec) (*net.UDPConn, error) {
	if s.Addr.IsValid() && !s.Addr.Is4() {
		return nil, fmt.Errorf("uplink: only IPv4 addresses are supported")
	}
	var index int
	if s.Interface != "" {
		ifc, err := net.InterfaceByName(s.Interface)
		if err != nil {
			return nil, fmt.Errorf("uplink: interface %q: %w", s.Interface, err)
		}
		index = ifc.Index
	}
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var inner error
		if err := c.Control(func(fd uintptr) {
			if index != 0 {
				inner = pin(fd, index, s.Interface)
			}
			if inner == nil && s.Buffer > 0 {
				inner = setBuffers(fd, s.Buffer)
			}
		}); err != nil {
			return err
		}
		return inner
	}}
	addr := "0.0.0.0:0"
	if s.Addr.IsValid() {
		addr = netip.AddrPortFrom(s.Addr, 0).String()
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
