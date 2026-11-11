package main

import (
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/lan"
)

// sharedAdapters lets several lan_devices share one physical adapter (for
// example a PS5 and a laptop behind an access point). The adapter is opened
// once; a reader fans frames out to per-device views by source MAC. Devices
// sharing an adapter must each set device_mac. A device without device_mac
// receives every frame (the single-device behaviour).
type sharedAdapters struct {
	open func(lan.DeviceConfig) (lan.FrameIO, error)
	mu   sync.Mutex
	m    map[string]*sharedAdapter
}

func newSharedAdapters(open func(lan.DeviceConfig) (lan.FrameIO, error)) *sharedAdapters {
	return &sharedAdapters{open: open, m: map[string]*sharedAdapter{}}
}

type sharedAdapter struct {
	owner *sharedAdapters
	key   string
	io    lan.FrameIO
	cfg   lan.DeviceConfig
	wmu   sync.Mutex
	mu    sync.Mutex
	views map[*adapterView]struct{}
	dead  error
}

type adapterView struct {
	sa      *sharedAdapter
	pin     *[6]byte
	ip      [4]byte // this device's tunnel IP; its frames identify an auto-claimed MAC
	claimed *[6]byte
	order   int
	in      chan []byte
	cl      chan struct{}
	one     sync.Once
}

func (s *sharedAdapters) Open(d lan.DeviceConfig) (lan.FrameIO, error) {
	key := strings.ToLower(d.InterfaceID)
	s.mu.Lock()
	defer s.mu.Unlock()
	sa := s.m[key]
	if sa == nil {
		io, err := s.open(d)
		if err != nil {
			return nil, err
		}
		sa = &sharedAdapter{owner: s, key: key, io: io, cfg: d, views: map[*adapterView]struct{}{}}
		s.m[key] = sa
		go sa.pump()
	}
	v := &adapterView{sa: sa, in: make(chan []byte, 256), cl: make(chan struct{}), ip: d.TunnelIP.As4()}
	if d.DeviceMAC != "" {
		mac, err := lan.ParseMAC(d.DeviceMAC)
		if err != nil {
			return nil, err
		}
		v.pin = &mac
	}
	sa.mu.Lock()
	v.order = len(sa.views)
	sa.views[v] = struct{}{}
	sa.mu.Unlock()
	return v, nil
}

func (sa *sharedAdapter) pump() {
	last := time.Now()
	for {
		sa.wmu.Lock()
		io := sa.io
		sa.wmu.Unlock()
		f, err := io.Read(250 * time.Millisecond)
		if err == nil && f == nil && time.Since(last) > 15*time.Second {
			// Nothing has arrived for a while (cable or link flap leaves the
			// driver handle stale): take a fresh handle for every view.
			io.Close() // release the stale handle first: closing it later would undo the new one's tunnel mode
			if nio, oerr := sa.owner.open(sa.cfg); oerr == nil {
				sa.wmu.Lock()
				sa.io = nio
				sa.wmu.Unlock()
			} else {
				sa.mu.Lock()
				sa.dead = oerr
				sa.mu.Unlock()
				sa.owner.mu.Lock()
				if sa.owner.m[sa.key] == sa {
					delete(sa.owner.m, sa.key)
				}
				sa.owner.mu.Unlock()
				return
			}
			last = time.Now()
			continue
		}
		if f != nil {
			last = time.Now()
		}
		sa.mu.Lock()
		if len(sa.views) == 0 && sa.dead == nil {
			sa.mu.Unlock()
			continue
		}
		if f != nil && len(f) >= 14 {
			sa.fanout(f)
		}
		sa.mu.Unlock()
	}
}

func (v *adapterView) MAC() [6]byte {
	v.sa.wmu.Lock()
	defer v.sa.wmu.Unlock()
	return v.sa.io.MAC()
}

func (v *adapterView) Write(f []byte) error {
	v.sa.wmu.Lock()
	defer v.sa.wmu.Unlock()
	return v.sa.io.Write(f)
}

func (v *adapterView) Read(timeout time.Duration) ([]byte, error) {
	select {
	case f := <-v.in:
		return f, nil
	case <-v.cl:
		return nil, lan.ErrClosed
	case <-time.After(timeout):
		v.sa.mu.Lock()
		err := v.sa.dead
		v.sa.mu.Unlock()
		return nil, err
	}
}

func (v *adapterView) Close() error {
	v.one.Do(func() {
		close(v.cl)
		sa := v.sa
		sa.mu.Lock()
		delete(sa.views, v)
		last := len(sa.views) == 0
		sa.mu.Unlock()
		if last {
			sa.owner.mu.Lock()
			if sa.owner.m[sa.key] == sa {
				delete(sa.owner.m, sa.key)
			}
			sa.owner.mu.Unlock()
			sa.io.Close()
		}
	})
	return nil
}

// fanout hands a frame to the view that owns its source MAC. Pinned views own
// their pin. Unpinned views on a shared adapter claim the first unowned device
// that sends a DHCP request, or an IPv4 packet from the view's tunnel IP, so a
// PS5 and a laptop behind one access point each find their own address
// without configuring MACs. A lone view receives everything. sa.mu is held.
func (sa *sharedAdapter) fanout(f []byte) {
	var src [6]byte
	copy(src[:], f[6:12])
	if len(sa.views) == 1 {
		for v := range sa.views {
			if v.pin == nil || *v.pin == src {
				v.push(f)
			}
		}
		return
	}
	for v := range sa.views {
		if v.owns(src) {
			v.push(f)
			return
		}
	}
	ip := ipv4Src(f)
	if !isDHCPRequest(f) && !sa.isViewIP(ip) {
		return
	}
	var pick *adapterView
	for v := range sa.views {
		if v.pin != nil || v.claimed != nil {
			continue
		}
		if ip != [4]byte{} && ip == v.ip {
			pick = v
			break
		}
		if isDHCPRequest(f) && (pick == nil || v.order < pick.order) {
			pick = v
		}
	}
	if pick != nil {
		pick.claimed = &src
		pick.push(f)
	}
}

func (v *adapterView) owns(src [6]byte) bool {
	if v.pin != nil {
		return *v.pin == src
	}
	return v.claimed != nil && *v.claimed == src
}

func (v *adapterView) push(f []byte) {
	select {
	case v.in <- f:
	default: // slow consumer: drop like a congested NIC
	}
}

// isDHCPRequest reports a UDP packet to port 67 (a DHCP client talking).
func isDHCPRequest(f []byte) bool {
	if len(f) < 14+20+8 || f[12] != 0x08 || f[13] != 0x00 || f[14]>>4 != 4 || f[23] != 17 {
		return false
	}
	ihl := int(f[14]&0x0f) * 4
	return len(f) >= 14+ihl+4 && int(f[14+ihl+2])<<8|int(f[14+ihl+3]) == 67
}

func (sa *sharedAdapter) isViewIP(ip [4]byte) bool {
	if ip == [4]byte{} {
		return false
	}
	for v := range sa.views {
		if v.ip == ip {
			return true
		}
	}
	return false
}

func ipv4Src(f []byte) (a [4]byte) {
	if len(f) >= 30 && f[12] == 0x08 && f[13] == 0x00 {
		copy(a[:], f[26:30])
	}
	return
}
