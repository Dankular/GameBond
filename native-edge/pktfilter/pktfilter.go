// Package pktfilter is windows_packet_filter.py: raw Ethernet frame I/O on
// Windows through the Windows Packet Filter (NDISRD) driver. This file holds
// the portable part (structure layouts, IOCTL numbering and the call
// sequence) so it can be tested against a fake driver on any OS; the real
// device access is driver_windows.go.
//
// Layouts and the call sequence follow wiresock/ndisapi as the Python module
// did. Like the Python module, the real-driver path has not been exercised
// against hardware by this repository.
package pktfilter

import (
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	FileDeviceNDISRD  = 0x8300
	IoctlIndex        = 0x830
	AdapterListSize   = 32
	AdapterNameSize   = 256
	EtherAddrLength   = 6
	MaxFrameBuffer    = 9014
	MstcpSentTunnel   = 0x1
	MstcpRecvTunnel   = 0x2
	TunnelMode        = MstcpSentTunnel | MstcpRecvTunnel
	PacketFlagOnSend  = 0x1
	PacketFlagOnRecv  = 0x2
	DevicePath        = `\\.\NDISRD`
	PresenceCheck     = time.Second
	bufferHeaderBytes = 52 // link 16 + five u32 + reserved 4*u32
)

// CtlCode is CTL_CODE(FILE_DEVICE_NDISRD, NDISRD_IOCTL_INDEX+offset, METHOD_BUFFERED, FILE_ANY_ACCESS).
func CtlCode(offset uint32) uint32 { return FileDeviceNDISRD<<16 | (IoctlIndex+offset)<<2 }

var (
	IoctlGetTCPIPInterfaces = CtlCode(1)
	IoctlSendPacket         = CtlCode(2)
	IoctlReadPacket         = CtlCode(4)
	IoctlSetAdapterMode     = CtlCode(5)
	IoctlFlushQueue         = CtlCode(6)
	IoctlSetEvent           = CtlCode(7)
)

// Packed structure sizes (the driver structures are #pragma pack(1)).
const (
	AdapterListBytes = 4 + AdapterNameSize*AdapterListSize + 8*AdapterListSize + 4*AdapterListSize +
		EtherAddrLength*AdapterListSize + 2*AdapterListSize
	BufferBytes = bufferHeaderBytes + MaxFrameBuffer
)

// Row is one TCP/IP adapter the driver lists.
type Row struct {
	Name   string
	Handle uint64
	MAC    [6]byte
	MTU    uint16
}

// ParseAdapterList is adapter_rows over the raw reply buffer.
func ParseAdapterList(b []byte) []Row {
	if len(b) < AdapterListBytes {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(b))
	if count > AdapterListSize {
		count = AdapterListSize
	}
	names := 4
	handles := names + AdapterNameSize*AdapterListSize
	mediums := handles + 8*AdapterListSize
	addrs := mediums + 4*AdapterListSize
	mtus := addrs + EtherAddrLength*AdapterListSize
	rows := make([]Row, 0, count)
	for i := 0; i < count; i++ {
		raw := b[names+i*AdapterNameSize : names+(i+1)*AdapterNameSize]
		if z := indexZero(raw); z >= 0 {
			raw = raw[:z]
		}
		name := make([]rune, len(raw))
		for j, c := range raw {
			if c < 0x80 {
				name[j] = rune(c)
			} else {
				name[j] = '�' // Python decodes ascii with errors="replace"
			}
		}
		var mac [6]byte
		copy(mac[:], b[addrs+i*EtherAddrLength:])
		rows = append(rows, Row{Name: string(name), Handle: binary.LittleEndian.Uint64(b[handles+i*8:]),
			MAC: mac, MTU: binary.LittleEndian.Uint16(b[mtus+i*2:])})
	}
	return rows
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// MatchAdapter is match_adapter: driver names are \DEVICE\<adapter GUID>.
func MatchAdapter(rows []Row, interfaceID string) *Row {
	want := foldASCII(`\device\` + interfaceID)
	for i := range rows {
		if foldASCII(rows[i].Name) == want {
			return &rows[i]
		}
	}
	return nil
}

// foldASCII approximates str.casefold for the ASCII names the driver returns
// (non-ASCII bytes were already replaced).
func foldASCII(s string) string { return strings.ToLower(s) }

// Driver is the device the Adapter talks to.
type Driver interface {
	// Ioctl is a synchronous IOCTL; out may alias in. It returns success and the bytes returned.
	Ioctl(code uint32, in, out []byte) (bool, int)
	CreateEvent() (uintptr, error)
	Wait(event uintptr, d time.Duration) (bool, error)
	ResetEvent(event uintptr)
	CloseEvent(event uintptr)
	Close() error
}

// ErrClosed is returned by a closed adapter.
var ErrClosed = errors.New("adapter closed")

// Adapter is frame I/O for one adapter, identified by its Windows adapter GUID.
type Adapter struct {
	driver     Driver
	ownsDriver bool
	id         string
	handle     uint64
	mac        [6]byte
	mtu        uint16
	event      uintptr
	hasEvent   bool
	closed     bool
	nextCheck  time.Time
	pool       sync.Pool
	mu         sync.Mutex
}

// Open puts the adapter in tunnel mode: frames from the wire go to GameBond
// instead of Windows, and anything Windows tries to send out it is discarded.
func Open(interfaceID string, driver Driver) (*Adapter, error) {
	if interfaceID == "" {
		return nil, errors.New("LAN devices on Windows need interface_id (the adapter GUID)")
	}
	a := &Adapter{driver: driver, id: interfaceID}
	a.pool.New = func() any { return make([]byte, BufferBytes) }
	var err error
	defer func() {
		if err != nil {
			a.Close()
		}
	}()
	var row *Row
	if row, err = a.findAdapter(); err != nil {
		return nil, err
	}
	if row == nil {
		err = errors.New("Adapter " + interfaceID + " is not bound to TCP/IP or is not visible to the packet driver")
		return nil, err
	}
	a.handle, a.mac, a.mtu = row.Handle, row.MAC, row.MTU
	if err = a.setMode(TunnelMode); err != nil {
		return nil, err
	}
	if a.event, err = driver.CreateEvent(); err != nil {
		return nil, err
	}
	a.hasEvent = true
	req := make([]byte, 16)
	binary.LittleEndian.PutUint64(req, a.handle)
	binary.LittleEndian.PutUint64(req[8:], uint64(a.event))
	if ok, _ := driver.Ioctl(IoctlSetEvent, req, nil); !ok {
		err = errors.New("Packet driver rejected the packet-event registration")
		return nil, err
	}
	a.flush()
	a.nextCheck = time.Now().Add(PresenceCheck)
	return a, nil
}

// MAC is the adapter's hardware address.
func (a *Adapter) MAC() [6]byte { return a.mac }

// MTU is the adapter's MTU as reported by the driver.
func (a *Adapter) MTU() int { return int(a.mtu) }

func (a *Adapter) findAdapter() (*Row, error) {
	list := make([]byte, AdapterListBytes)
	ok, n := a.driver.Ioctl(IoctlGetTCPIPInterfaces, list, list)
	if !ok || n != AdapterListBytes {
		return nil, errors.New("Packet driver could not list TCP/IP adapters")
	}
	return MatchAdapter(ParseAdapterList(list), a.id), nil
}

func (a *Adapter) setMode(flags uint32) error {
	req := make([]byte, 12)
	binary.LittleEndian.PutUint64(req, a.handle)
	binary.LittleEndian.PutUint32(req[8:], flags)
	if ok, _ := a.driver.Ioctl(IoctlSetAdapterMode, req, nil); !ok {
		return errors.New("Packet driver rejected the adapter mode change")
	}
	return nil
}

func (a *Adapter) flush() {
	req := make([]byte, 8)
	binary.LittleEndian.PutUint64(req, a.handle)
	a.driver.Ioctl(IoctlFlushQueue, req, nil)
}

// readOne is one queued wire frame, or nil when the queue is empty. Frames the
// host itself sent toward the adapter are isolated, never returned.
func (a *Adapter) readOne() []byte {
	buf := a.pool.Get().([]byte)
	defer a.pool.Put(buf)
	for {
		for i := 0; i < bufferHeaderBytes; i++ {
			buf[i] = 0
		}
		req := make([]byte, 16)
		binary.LittleEndian.PutUint64(req, a.handle)
		binary.LittleEndian.PutUint64(req[8:], bufferAddress(buf))
		ok, n := a.driver.Ioctl(IoctlReadPacket, req, req)
		if !ok || n != 16 {
			return nil
		}
		if binary.LittleEndian.Uint32(buf[16:])&PacketFlagOnSend != 0 {
			continue
		}
		length := int(binary.LittleEndian.Uint32(buf[20:]))
		if length >= 14 && length <= MaxFrameBuffer {
			return append([]byte(nil), buf[bufferHeaderBytes:bufferHeaderBytes+length]...)
		}
	}
}

// Read returns one frame from the wire, or (nil, nil) after the timeout.
func (a *Adapter) Read(timeout time.Duration) ([]byte, error) {
	if a.closed {
		return nil, ErrClosed
	}
	if f := a.readOne(); f != nil {
		return f, nil
	}
	ms := timeout
	if ms < time.Millisecond {
		ms = time.Millisecond
	}
	ok, err := a.driver.Wait(a.event, ms)
	if err != nil {
		return nil, err
	}
	if ok {
		a.driver.ResetEvent(a.event) // reset before draining so a later arrival re-signals
		return a.readOne(), nil
	}
	if now := time.Now(); !now.Before(a.nextCheck) {
		a.nextCheck = now.Add(PresenceCheck)
		row, err := a.findAdapter()
		if err != nil {
			return nil, err
		}
		if row == nil || row.Handle != a.handle {
			return nil, errors.New("Adapter was removed or is no longer bound to TCP/IP")
		}
	}
	return nil, nil
}

// Write sends one Ethernet frame out the adapter.
func (a *Adapter) Write(frame []byte) error {
	if a.closed {
		return ErrClosed
	}
	if len(frame) < 14 || len(frame) > MaxFrameBuffer {
		return errors.New("invalid Ethernet frame size")
	}
	buf := a.pool.Get().([]byte)
	defer a.pool.Put(buf)
	for i := 0; i < bufferHeaderBytes; i++ {
		buf[i] = 0
	}
	binary.LittleEndian.PutUint32(buf[20:], uint32(len(frame)))
	copy(buf[bufferHeaderBytes:], frame)
	req := make([]byte, 16)
	binary.LittleEndian.PutUint64(req, a.handle)
	binary.LittleEndian.PutUint64(req[8:], bufferAddress(buf))
	if ok, _ := a.driver.Ioctl(IoctlSendPacket, req, nil); !ok {
		return errors.New("Packet driver refused the frame")
	}
	return nil
}

// Close restores pass-through, drops anything still queued and releases the event.
func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	if a.handle != 0 {
		_ = a.setMode(0)
		a.flush()
	}
	if a.hasEvent {
		a.driver.CloseEvent(a.event)
		a.hasEvent = false
	}
	if a.ownsDriver {
		return a.driver.Close()
	}
	return nil
}

// OwnDriver makes Close also close the driver.
func (a *Adapter) OwnDriver() *Adapter { a.ownsDriver = true; return a }

// bufferAddress is the address handed to the driver for a frame buffer. The Go
// heap does not move objects, and callers keep the buffer referenced for the
// duration of the IOCTL. Tests replace it to map addresses to buffers.
var bufferAddress = func(b []byte) uint64 { return addressOf(b) }
