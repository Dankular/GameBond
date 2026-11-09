//go:build linux

package lan

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// LinuxIO is an AF_PACKET raw socket bound to one interface (needs CAP_NET_RAW).
type LinuxIO struct {
	fd  int
	mac [6]byte
	mu  sync.Mutex
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// OpenLinux opens raw frame access on the named interface.
func OpenLinux(name string) (*LinuxIO, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("cannot open raw socket on %s: %w", name, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("cannot open raw socket on %s: %w", name, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("cannot open raw socket on %s: %w", name, err)
	}
	l := &LinuxIO{fd: fd}
	if len(ifc.HardwareAddr) != 6 {
		unix.Close(fd)
		return nil, errors.New("adapter MAC address must be six bytes")
	}
	copy(l.mac[:], ifc.HardwareAddr)
	return l, nil
}

func (l *LinuxIO) MAC() [6]byte { return l.mac }

func (l *LinuxIO) Read(timeout time.Duration) ([]byte, error) {
	timeout = min(max(timeout, time.Millisecond), 250*time.Millisecond)
	tv := unix.NsecToTimeval(int64(timeout))
	if err := unix.SetsockoptTimeval(l.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, ErrClosed
	}
	buf := make([]byte, 65535)
	n, from, err := unix.Recvfrom(l.fd, buf, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return nil, nil
		}
		return nil, err
	}
	if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
		return nil, nil // our own transmission echoed back
	}
	return buf[:n], nil
}

func (l *LinuxIO) Write(frame []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return unix.Send(l.fd, frame, 0)
}

func (l *LinuxIO) Close() error { return unix.Close(l.fd) }
