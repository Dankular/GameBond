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
	// InterfaceIndex selects the egress adapter by OS index instead of name
	// (what the Python config calls interface_indices). Zero means unset.
	InterfaceIndex int
	// Buffer is the socket send and receive buffer in bytes (0 keeps the default).
	Buffer int
	// DontFragment sets the don't-fragment option (path MTU discovery), best
	// effort like Python's _enable_df: a platform that refuses it still opens;
	// DFEnforced reports whether it took effect.
	DontFragment bool
}

var ErrUnsupported = errors.New("uplink: adapter pinning is not supported on this platform")

// Open returns a UDP socket for the uplink on an ephemeral port.
func Open(s Spec) (*net.UDPConn, error) {
	if s.Addr.IsValid() && !s.Addr.Is4() {
		return nil, fmt.Errorf("uplink: only IPv4 addresses are supported")
	}
	index := s.InterfaceIndex
	if s.Interface != "" && index == 0 {
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
			if inner == nil && s.DontFragment {
				_ = setDF(fd)
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

// Control returns a socket Control function that pins a (TCP) socket to the
// uplink's adapter, for the stream-carrier fallback. It returns nil when the
// spec names no adapter.
func Control(s Spec) func(network, address string, c syscall.RawConn) error {
	index := s.InterfaceIndex
	if s.Interface != "" && index == 0 {
		if ifc, err := net.InterfaceByName(s.Interface); err == nil {
			index = ifc.Index
		}
	}
	if index == 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var inner error
		if err := c.Control(func(fd uintptr) { inner = pin(fd, index, s.Interface) }); err != nil {
			return err
		}
		return inner
	}
}

// DFEnforced reports whether the socket has the don't-fragment option set.
func DFEnforced(c *net.UDPConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	on := false
	if raw.Control(func(fd uintptr) { on = getDF(fd) }) != nil {
		return false
	}
	return on
}
