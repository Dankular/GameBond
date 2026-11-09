package pktfilter

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"
)

type vectorFile struct {
	Constants map[string]uint32 `json:"constants"`
	Sizes     map[string]int    `json:"sizes"`
	Cases     []struct {
		List   string `json:"list"`
		Wanted string `json:"wanted"`
		Rows   []struct {
			Name   string `json:"name"`
			Handle uint64 `json:"handle"`
			MAC    string `json:"mac"`
			MTU    uint16 `json:"mtu"`
		} `json:"rows"`
		Match *int `json:"match"`
	} `json:"cases"`
}

func loadVectors(t *testing.T) vectorFile {
	f, err := os.Open("testdata/vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.NewDecoder(z).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestConstantsAndLayoutsMatchPython(t *testing.T) {
	v := loadVectors(t)
	for name, got := range map[string]uint32{
		"IOCTL_GET_TCPIP_INTERFACES": IoctlGetTCPIPInterfaces, "IOCTL_SEND_PACKET_TO_ADAPTER": IoctlSendPacket,
		"IOCTL_READ_PACKET": IoctlReadPacket, "IOCTL_SET_ADAPTER_MODE": IoctlSetAdapterMode,
		"IOCTL_FLUSH_ADAPTER_QUEUE": IoctlFlushQueue, "IOCTL_SET_EVENT": IoctlSetEvent, "TUNNEL_MODE": TunnelMode,
		"MAX_FRAME_BUFFER": MaxFrameBuffer} {
		if v.Constants[name] != got {
			t.Errorf("%s = %#x, Python %#x", name, got, v.Constants[name])
		}
	}
	for name, got := range map[string]int{"adapter_list": AdapterListBytes, "buffer": BufferBytes, "buffer_data_offset": bufferHeaderBytes,
		"device_flags_offset": 16, "length_offset": 20, "eth_request": 16, "adapter_mode": 12, "adapter_event": 16} {
		if v.Sizes[name] != got {
			t.Errorf("%s = %d, Python %d", name, got, v.Sizes[name])
		}
	}
}

func TestAdapterListAndMatchReplayPython(t *testing.T) {
	for i, c := range loadVectors(t).Cases {
		raw, _ := hex.DecodeString(c.List)
		rows := ParseAdapterList(raw)
		if len(rows) != len(c.Rows) {
			t.Fatalf("case %d: %d rows, Python %d", i, len(rows), len(c.Rows))
		}
		for j, r := range rows {
			w := c.Rows[j]
			if r.Name != w.Name || r.Handle != w.Handle || hex.EncodeToString(r.MAC[:]) != w.MAC || r.MTU != w.MTU {
				t.Fatalf("case %d row %d: %+v, Python %+v", i, j, r, w)
			}
		}
		m := MatchAdapter(rows, c.Wanted)
		switch {
		case m == nil && c.Match != nil, m != nil && c.Match == nil:
			t.Fatalf("case %d: match %v, Python %v", i, m, c.Match)
		case m != nil && m.Handle != rows[*c.Match].Handle:
			// duplicate names can legitimately map to an earlier row: compare the first match
			t.Fatalf("case %d: match handle differs", i)
		}
	}
}

// fakeDriver implements the documented NDISRD semantics.
type fakeDriver struct {
	mu        sync.Mutex
	handle    uint64
	name      string
	mode      uint32
	queue     [][]byte
	queueFlag []uint32
	sent      [][]byte
	flushes   int
	event     chan struct{}
	removed   bool
	refuse    map[uint32]bool
	buffers   map[uint64][]byte
	closedEv  bool
}

func newFake(name string) *fakeDriver {
	f := &fakeDriver{handle: 0x1122334455, name: name, event: make(chan struct{}, 1), refuse: map[uint32]bool{}, buffers: map[uint64][]byte{}}
	bufferAddress = func(b []byte) uint64 {
		a := addressOf(b)
		f.mu.Lock()
		f.buffers[a] = b
		f.mu.Unlock()
		return a
	}
	return f
}

func (f *fakeDriver) Ioctl(code uint32, in, out []byte) (bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse[code] {
		return false, 0
	}
	switch code {
	case IoctlGetTCPIPInterfaces:
		for i := range out {
			out[i] = 0
		}
		if !f.removed {
			binary.LittleEndian.PutUint32(out, 1)
			copy(out[4:], f.name)
			binary.LittleEndian.PutUint64(out[4+AdapterNameSize*AdapterListSize:], f.handle)
			mac := 4 + AdapterNameSize*AdapterListSize + 8*AdapterListSize + 4*AdapterListSize
			copy(out[mac:], []byte{2, 0, 0, 0, 0, 1})
			binary.LittleEndian.PutUint16(out[mac+6*AdapterListSize:], 1500)
		}
		return true, len(out)
	case IoctlSetAdapterMode:
		f.mode = binary.LittleEndian.Uint32(in[8:])
		return true, 0
	case IoctlSetEvent:
		return true, 0
	case IoctlFlushQueue:
		f.flushes++
		f.queue, f.queueFlag = nil, nil
		return true, 0
	case IoctlReadPacket:
		if len(f.queue) == 0 {
			return false, 0
		}
		buf := f.buffers[binary.LittleEndian.Uint64(in[8:])]
		frame := f.queue[0]
		binary.LittleEndian.PutUint32(buf[16:], f.queueFlag[0])
		binary.LittleEndian.PutUint32(buf[20:], uint32(len(frame)))
		copy(buf[bufferHeaderBytes:], frame)
		f.queue, f.queueFlag = f.queue[1:], f.queueFlag[1:]
		copy(out, in)
		return true, 16
	case IoctlSendPacket:
		buf := f.buffers[binary.LittleEndian.Uint64(in[8:])]
		n := binary.LittleEndian.Uint32(buf[20:])
		f.sent = append(f.sent, append([]byte(nil), buf[bufferHeaderBytes:bufferHeaderBytes+int(n)]...))
		return true, 0
	}
	return false, 0
}
func (f *fakeDriver) CreateEvent() (uintptr, error) { return 7, nil }
func (f *fakeDriver) Wait(_ uintptr, d time.Duration) (bool, error) {
	select {
	case <-f.event:
		return true, nil
	case <-time.After(d):
		return false, nil
	}
}
func (f *fakeDriver) ResetEvent(uintptr) {}
func (f *fakeDriver) CloseEvent(uintptr) { f.closedEv = true }
func (f *fakeDriver) Close() error       { return nil }

func (f *fakeDriver) arrive(frame []byte, flags uint32) {
	f.mu.Lock()
	f.queue, f.queueFlag = append(f.queue, frame), append(f.queueFlag, flags)
	f.mu.Unlock()
	select {
	case f.event <- struct{}{}:
	default:
	}
}

const guid = `{d1729bf1-b1fa-422e-98c9-3089d2ba82ed}`

func frame(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

func TestOpenSetsTunnelModeAndCloseRestores(t *testing.T) {
	f := newFake(`\DEVICE\{D1729BF1-B1FA-422E-98C9-3089D2BA82ED}`)
	a, err := Open(guid, f)
	if err != nil {
		t.Fatal(err)
	}
	if f.mode != TunnelMode || a.MTU() != 1500 || a.MAC() != [6]byte{2, 0, 0, 0, 0, 1} || f.flushes != 1 {
		t.Fatalf("mode %#x mtu %d mac %v flushes %d", f.mode, a.MTU(), a.MAC(), f.flushes)
	}
	a.Close()
	if f.mode != 0 || f.flushes != 2 || !f.closedEv {
		t.Fatalf("close left mode %#x flushes %d eventClosed %v", f.mode, f.flushes, f.closedEv)
	}
	if _, err := a.Read(time.Millisecond); err != ErrClosed {
		t.Fatalf("read after close: %v", err)
	}
}

func TestOpenFailures(t *testing.T) {
	if _, err := Open("", newFake("x")); err == nil {
		t.Fatal("empty interface id accepted")
	}
	if _, err := Open(guid, newFake(`\DEVICE\other`)); err == nil {
		t.Fatal("unbound adapter accepted")
	}
	for _, code := range []uint32{IoctlGetTCPIPInterfaces, IoctlSetAdapterMode, IoctlSetEvent} {
		f := newFake(`\DEVICE\` + guid)
		f.refuse[code] = true
		if _, err := Open(guid, f); err == nil {
			t.Fatalf("open succeeded although %#x is refused", code)
		}
		if code != IoctlGetTCPIPInterfaces && f.mode != 0 {
			t.Fatalf("failed open left mode %#x", f.mode)
		}
	}
}

func TestReadSkipsHostTransmissionsAndBadFrames(t *testing.T) {
	f := newFake(`\DEVICE\` + guid)
	a, _ := Open(guid, f)
	defer a.Close()
	f.arrive(frame(60, 1), PacketFlagOnSend)   // Windows' own DHCP: isolated
	f.arrive(frame(13, 2), PacketFlagOnRecv)   // runt
	f.arrive(frame(9015, 3), PacketFlagOnRecv) // oversize
	f.arrive(frame(60, 4), PacketFlagOnRecv)   // the one wire frame
	got, err := a.Read(50 * time.Millisecond)
	if err != nil || !bytes.Equal(got, frame(60, 4)) {
		t.Fatalf("got %d bytes %v err %v", len(got), got[:1], err)
	}
	if got, _ := a.Read(20 * time.Millisecond); got != nil {
		t.Fatal("expected a timeout")
	}
}

func TestReadWaitsForArrival(t *testing.T) {
	f := newFake(`\DEVICE\` + guid)
	a, _ := Open(guid, f)
	defer a.Close()
	go func() { time.Sleep(30 * time.Millisecond); f.arrive(frame(64, 9), PacketFlagOnRecv) }()
	if got, err := a.Read(2 * time.Second); err != nil || len(got) != 64 {
		t.Fatalf("got %d err %v", len(got), err)
	}
}

func TestWriteFramesAndLimits(t *testing.T) {
	f := newFake(`\DEVICE\` + guid)
	a, _ := Open(guid, f)
	defer a.Close()
	if err := a.Write(frame(100, 5)); err != nil || len(f.sent) != 1 || !bytes.Equal(f.sent[0], frame(100, 5)) {
		t.Fatalf("send: %v %d", err, len(f.sent))
	}
	for _, n := range []int{13, 9015} {
		if err := a.Write(frame(n, 1)); err == nil {
			t.Fatalf("size %d accepted", n)
		}
	}
	f.refuse[IoctlSendPacket] = true
	if err := a.Write(frame(60, 1)); err == nil {
		t.Fatal("driver refusal not reported")
	}
}

func TestAdapterRemovalDetectedOnIdleRead(t *testing.T) {
	f := newFake(`\DEVICE\` + guid)
	a, _ := Open(guid, f)
	defer a.Close()
	a.nextCheck = time.Now()
	f.mu.Lock()
	f.removed = true
	f.mu.Unlock()
	if _, err := a.Read(5 * time.Millisecond); err == nil {
		t.Fatal("removed adapter not reported")
	}
}

func TestAdapterRebindDetectedOnIdleRead(t *testing.T) {
	f := newFake(`\DEVICE\` + guid)
	a, _ := Open(guid, f)
	defer a.Close()
	a.nextCheck = time.Now()
	f.mu.Lock()
	f.handle++
	f.mu.Unlock()
	if _, err := a.Read(5 * time.Millisecond); err == nil {
		t.Fatal("re-bound adapter (new handle) not reported")
	}
}
