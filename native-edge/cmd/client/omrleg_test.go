package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"gamebond.local/nativeedge/nat"
	"gamebond.local/nativeedge/omr"
	"gamebond.local/nativeedge/router"
)

type fakeGB struct{ got []bond.QueuedPacket }

func (f *fakeGB) Submit(q bond.QueuedPacket) bool { f.got = append(f.got, q); return true }

type fakeOMR struct{ got [][]byte }

func (f *fakeOMR) Send(p []byte, u bool) bool { f.got = append(f.got, p); return true }
func (f *fakeOMR) Ready() bool                { return true }

func ipv4UDP(dscp byte) []byte {
	p := make([]byte, 28)
	p[0], p[1], p[8], p[9] = 0x45, dscp<<2, 64, 17
	p[2], p[3] = 0, 28
	copy(p[12:16], []byte{10, 0, 0, 2})
	copy(p[16:20], []byte{8, 8, 8, 8})
	p[20], p[21], p[22], p[23] = 0x30, 0x39, 0, 53
	p[25] = 8
	return p
}

func TestRoutedUplinkPassThroughThenRouted(t *testing.T) {
	gb := &fakeGB{}
	var delivered [][]byte
	u := &routedUplink{gb: gb, deliver: func(p []byte) { delivered = append(delivered, p) }, ready: func() bool { return true }}
	q := bond.QueuedPacket{Payload: ipv4UDP(0), Flow: "f", Tag: 7, ClassCapacity: 5, Expires: time.Now().Add(time.Second)}
	if !u.Submit(q) || len(gb.got) != 1 {
		t.Fatal("pass-through failed")
	}
	u.Deliver([]byte{1})
	if len(delivered) != 1 {
		t.Fatal("deliver pass-through")
	}
	o := &fakeOMR{}
	n, _ := newTestNat()
	u.rt.Store(router.New(u, o, n, nil, 0, 0))
	// DSCP 46 stays on GameBond with the queue metadata intact.
	g := bond.QueuedPacket{Payload: ipv4UDP(46), Flow: "g", Tag: 9, ClassCapacity: 3, Expires: q.Expires}
	if !u.Submit(g) || len(gb.got) != 2 || gb.got[1].Tag != 9 || gb.got[1].ClassCapacity != 3 || gb.got[1].Flow != "g" {
		t.Fatalf("gamebond route lost metadata: %+v", gb.got)
	}
	// Best effort goes to OMR through the NAT.
	if !u.Submit(q) || len(o.got) != 1 || len(gb.got) != 2 {
		t.Fatal("bulk should use OMR")
	}
	if string(o.got[0][12:16]) == string([]byte{10, 0, 0, 2}) {
		t.Fatal("source address was not translated")
	}
}

func TestCredentialsFromKeyFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "k"), []byte(strings.Repeat("cd", 32)+"\n"), 0o600)
	s := &omr.Settings{KeyFile: "k", TunnelIP: "10.1.2.3"}
	key, ip, err := credentials(dir, s)
	if err != nil || len(key) != 32 || key[0] != 0xcd || ip != "10.1.2.3" {
		t.Fatalf("%v %v %v", key, ip, err)
	}
	if _, _, err := credentials(dir, &omr.Settings{KeyFile: "missing"}); err == nil {
		t.Fatal("missing key accepted")
	}
}

func TestOMRLegBlocksAfterRefusedLoginOnly(t *testing.T) {
	st := &omrState{mode: "both"}
	var lines []map[string]any
	l := &omrLeg{settings: &omr.Settings{Server: [2]any{"127.0.0.1", 1}, KeyFile: "missing"}, root: t.TempDir(), locals: []string{"127.0.0.1"},
		up: &routedUplink{}, state: st, out: func(m map[string]any) { lines = append(lines, m) }}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { l.run(stop); close(done) }()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	<-done // a non-auth failure keeps retrying until stopped
	if len(lines) != 1 || lines[0]["status"] != "omr_leg_unavailable" {
		t.Fatalf("%v", lines)
	}
	if s := st.status().(map[string]any); s["blocked"] != false || s["active"] != false {
		t.Fatalf("%v", s)
	}
	if (&omrState{mode: "gamebond"}).status() != nil {
		t.Fatal("status for non-both mode must be nil")
	}
}

func newTestNat() (*nat.Nat, error) { return nat.New(netip.MustParseAddr("10.255.254.7"), 0, 0, 0) }

func TestOuterSettings(t *testing.T) {
	if s, err := outerSettings(nil); s != nil || err != nil {
		t.Fatal("absent must disable the carrier")
	}
	if s, err := outerSettings([]byte("null")); s != nil || err != nil {
		t.Fatal("null must disable the carrier")
	}
	s, err := outerSettings([]byte(`{"endpoints":[{"mode":"tcp","port":443}]}`))
	if err != nil || s.FallbackAfter != 1.5 || s.RecoveryInterval != 5 || s.QueuePackets != 32 {
		t.Fatalf("%+v %v", s, err)
	}
	for _, bad := range []string{`{}`, `{"endpoints":[{"mode":"tcp","port":443}],"bogus":1}`, `{"endpoints":[{"mode":"tls","port":443}]}`,
		`{"endpoints":[{"mode":"tcp","port":443}],"fallback_after":0}`, `[]`} {
		if _, err := outerSettings([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestQoSFromConfig(t *testing.T) {
	d, err := qosFromConfig(nil)
	if err != nil || d.GameDeadlineMS != 20 || !d.Enabled {
		t.Fatalf("%+v %v", d, err)
	}
	s, err := qosFromConfig([]byte(`{"game_deadline_ms":30,"enabled":false}`))
	if err != nil || s.GameDeadlineMS != 30 || s.Enabled || s.CallDeadlineMS != 60 {
		t.Fatalf("%+v %v", s, err)
	}
	for _, bad := range []string{`{"bogus":1}`, `{"loss_threshold":0}`, `{"loss_threshold":2}`, `{"game_deadline_ms":5000}`, `{"enabled":"yes"}`, `[]`} {
		if _, err := qosFromConfig([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
