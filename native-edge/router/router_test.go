package router

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"gamebond.local/nativeedge/nat"
)

type gb struct {
	healthy, accept bool
	sent            []string
}

func (g *gb) Ready() bool { return g.healthy }
func (g *gb) Send(p []byte, _ bool, _ string, _ bool) bool {
	g.sent = append(g.sent, hex.EncodeToString(p))
	return g.accept
}

type omr struct {
	ready, accept bool
	sent          [][2]any
}

func (o *omr) Ready() bool { return o.ready }
func (o *omr) Send(p []byte, urgent bool) bool {
	o.sent = append(o.sent, [2]any{hex.EncodeToString(p), urgent})
	return o.accept
}

func TestPythonVectors(t *testing.T) {
	f, err := os.Open("testdata/router-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, _ := gzip.NewReader(f)
	var scs []struct {
		DSCP     []int   `json:"dscp"`
		FlowTTL  float64 `json:"flow_ttl"`
		ReadyTTL float64 `json:"ready_ttl"`
		Steps    []struct {
			Op        string
			T         float64
			GB, OMR   json.RawMessage
			Flow      *string
			DSCP      int
			Packet    string
			Urgent    bool
			Result    int
			Which     string
			Delivered *string
		}
		Counts map[string]uint64
		Flows  int
		NAT    map[string]int
	}
	if err := json.NewDecoder(z).Decode(&scs); err != nil {
		t.Fatal(err)
	}
	epoch := time.Unix(10, 0)
	dur := func(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }
	for si, sc := range scs {
		var now time.Time
		n, _ := nat.New(netip.MustParseAddr("10.255.254.2"), 0, 0, 0)
		n.Now = func() time.Time { return now }
		n.Intn = func(int) int { return 0 }
		g, o := &gb{healthy: true, accept: true}, &omr{ready: true, accept: true}
		r := New(g, o, n, sc.DSCP, dur(sc.FlowTTL), dur(sc.ReadyTTL))
		if sc.ReadyTTL == 0 {
			r.readyTTL = 0 // New treats 0 as "default"; Python 0.0 means never cached
		}
		r.Now = func() time.Time { return now }
		for i, st := range sc.Steps {
			now = epoch.Add(dur(st.T - 10))
			switch st.Op {
			case "ready":
				json.Unmarshal(st.GB, &g.healthy)
				json.Unmarshal(st.OMR, &o.ready)
			case "accept":
				json.Unmarshal(st.GB, &g.accept)
				json.Unmarshal(st.OMR, &o.accept)
			case "send":
				p, _ := hex.DecodeString(st.Packet)
				flow := ""
				if st.Flow != nil {
					flow = *st.Flow
				}
				g.sent, o.sent = nil, nil
				got := r.Send(p, true, flow, st.Urgent, st.DSCP)
				if got != st.Result {
					t.Fatalf("scenario %d step %d: result %d want %d (g=%v o=%v)", si, i, got, st.Result, g.sent, o.sent)
				}
				var wantG []string
				var wantO [][2]any
				json.Unmarshal(st.GB, &wantG)
				var rawO [][]any
				json.Unmarshal(st.OMR, &rawO)
				for _, x := range rawO {
					wantO = append(wantO, [2]any{x[0], x[1]})
				}
				if !(len(g.sent) == 0 && len(wantG) == 0) && !reflect.DeepEqual(g.sent, wantG) {
					t.Fatalf("scenario %d step %d gamebond sent %v want %v", si, i, g.sent, wantG)
				}
				if len(o.sent) != len(wantO) || (len(o.sent) > 0 && (o.sent[0][0] != wantO[0][0] || o.sent[0][1] != wantO[0][1])) {
					t.Fatalf("scenario %d step %d omr sent %v want %v", si, i, o.sent, wantO)
				}
			case "recv":
				p, _ := hex.DecodeString(st.Packet)
				r.Receive(st.Which, p)
				select {
				case got := <-r.Inbox():
					if st.Delivered == nil || hex.EncodeToString(got) != *st.Delivered {
						t.Fatalf("scenario %d step %d: delivered %x want %v", si, i, got, st.Delivered)
					}
				default:
					if st.Delivered != nil {
						t.Fatalf("scenario %d step %d: nothing delivered, want %s", si, i, *st.Delivered)
					}
				}
			}
		}
		c, flows := r.Stats()
		got := map[string]uint64{"sent_gamebond": c.SentGameBond, "sent_omr": c.SentOMR, "fallbacks": c.Fallbacks, "nat_dropped": c.NATDropped,
			"send_failed": c.SendFailed, "recv_gamebond": c.RecvGameBond, "recv_omr": c.RecvOMR, "recv_nat_dropped": c.RecvNATDropped, "inbox_full": c.InboxFull}
		for k, w := range sc.Counts {
			if got[k] != w {
				t.Errorf("scenario %d counter %s = %d want %d", si, k, got[k], w)
			}
		}
		if flows != sc.Flows {
			t.Errorf("scenario %d flows %d want %d", si, flows, sc.Flows)
		}
		ns := n.Stats()
		if int(ns.Out) != sc.NAT["out"] || int(ns.In) != sc.NAT["inn"] || int(ns.Created) != sc.NAT["created"] {
			t.Errorf("scenario %d nat %+v want %v", si, ns, sc.NAT)
		}
	}
}
