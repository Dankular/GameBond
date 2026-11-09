package omr

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"testing"
)

type mudVectors struct {
	Primitives struct {
		Seals []struct {
			Key, Plain, Wire, Bad string
			BadOK                 bool `json:"bad_ok"`
		} `json:"seals"`
		Hashes []struct {
			Parts []string
			Out   string
		} `json:"hashes"`
		Msgs []struct {
			Hex    string
			Fields struct {
				SentTime int64    `json:"sent_time"`
				Aes      byte     `json:"aes"`
				PKey     string   `json:"pkey"`
				Tx       [2]int64 `json:"tx"`
				Rx       [2]int64 `json:"rx"`
				Fw       [2]int64 `json:"fw"`
				MaxRate  int64    `json:"max_rate"`
				Beat     int64    `json:"beat"`
				MTU      int64    `json:"mtu"`
				Pref     byte     `json:"pref"`
				Loss     byte     `json:"loss"`
				Fixed    byte     `json:"fixed_rate"`
				LossLim  byte     `json:"loss_limit"`
				Addr     [2]any   `json:"addr"`
			} `json:"fields"`
		} `json:"msgs"`
		Stats []struct {
			Values []int64
			Trace  [][2]int64
		} `json:"stats"`
		MTUs []struct {
			Ops   []int64
			Trace [][4]int64
		} `json:"mtus"`
	} `json:"primitives"`
	Scenarios []struct {
		Init struct {
			IPs      []string `json:"ips"`
			Roles    []string `json:"roles"`
			Prefs    []int    `json:"prefs"`
			Rate     float64  `json:"rate_mbps"`
			Beat     int      `json:"beat_ms"`
			Jitter   float64  `json:"jitter"`
			Demote   float64  `json:"demote_after"`
			Recovery float64  `json:"recovery"`
			Enabled  []bool   `json:"enabled"`
			HasSock  []bool   `json:"has_sock"`
			T        int64    `json:"t"`
			URandom  []string `json:"urandom"`
		} `json:"init"`
		Steps []struct {
			Op struct {
				Kind   string    `json:"kind"`
				T      int64     `json:"t"`
				Slot   int       `json:"slot"`
				Addr   []any     `json:"addr"`
				Packet string    `json:"packet"`
				Urgent bool      `json:"urgent"`
				Roles  []string  `json:"roles"`
				Up     []float64 `json:"up"`
				Down   []float64 `json:"down"`
			} `json:"op"`
			Ret   any             `json:"ret"`
			Out   [][]any         `json:"out"`
			Inbox []string        `json:"inbox"`
			Snap  json.RawMessage `json:"snap"`
		} `json:"steps"`
	} `json:"scenarios"`
}

func loadMud(t *testing.T) *mudVectors {
	f, err := os.Open("testdata/mud-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	var v mudVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMudPrimitivesMatchPython(t *testing.T) {
	v := loadMud(t)
	for i, s := range v.Primitives.Seals {
		key, plain, wire := unhex(t, s.Key), unhex(t, s.Plain), unhex(t, s.Wire)
		got := Seal(key, wire[:TimeSize], plain)
		if !bytes.Equal(got, wire) {
			t.Fatalf("seal %d differs:\n go %x\n py %x", i, got, wire)
		}
		if back := Unseal(key, wire); !bytes.Equal(back, plain) {
			t.Fatalf("unseal %d", i)
		}
		if (Unseal(key, unhex(t, s.Bad)) != nil) != s.BadOK {
			t.Fatalf("tamper %d accepted", i)
		}
	}
	for i, h := range v.Primitives.Hashes {
		if got := hashKey(unhex(t, h.Parts[0]), unhex(t, h.Parts[1]), unhex(t, h.Parts[2]), unhex(t, h.Parts[3])); hex.EncodeToString(got) != h.Out {
			t.Fatalf("hash %d", i)
		}
	}
	for i, m := range v.Primitives.Msgs {
		f := m.Fields
		ap := netip.MustParseAddrPort(fmt.Sprintf("%s:%d", f.Addr[0], int(f.Addr[1].(float64))))
		msg := Msg{SentTime: f.SentTime, Aes: f.Aes, PKey: unhex(t, f.PKey), TxBytes: f.Tx[0], TxTotal: f.Tx[1], RxBytes: f.Rx[0], RxTotal: f.Rx[1], FwBytes: f.Fw[0], FwTotal: f.Fw[1],
			MaxRate: f.MaxRate, Beat: f.Beat, MTU: f.MTU, Pref: f.Pref, Loss: f.Loss, FixedRate: f.Fixed, LossLimit: f.LossLim, Addr: ap}
		if hex.EncodeToString(msg.Pack()) != m.Hex {
			t.Fatalf("pack %d differs", i)
		}
		back, err := UnpackMsg(unhex(t, m.Hex))
		if err != nil || !reflect.DeepEqual(*back, msg) {
			t.Fatalf("unpack %d: %v\n%+v\n%+v", i, err, back, msg)
		}
	}
	for i, s := range v.Primitives.Stats {
		var st stat
		for j, val := range s.Values {
			st.update(val)
			if st.val != s.Trace[j][0] || st.vr != s.Trace[j][1] {
				t.Fatalf("stat %d step %d", i, j)
			}
		}
	}
	for i, m := range v.Primitives.MTUs {
		var p path
		for j, op := range m.Ops {
			p.updateMTU(op)
			if got := [4]int64{p.mtuMin, p.mtuMax, p.mtuProbe, p.mtuLast}; got != m.Trace[j] {
				t.Fatalf("mtu %d step %d: %v vs %v", i, j, got, m.Trace[j])
			}
		}
	}
	if _, err := ParseKey("zz"); err == nil {
		t.Fatal("bad key accepted")
	}
	if k, err := ParseKey(" 00" + "11" + string(bytes.Repeat([]byte("ff"), 30)) + "\n"); err != nil || k[1] != 0x11 {
		t.Fatalf("%v %v", k, err)
	}
}

func goSnapshot(c *Client) []any {
	paths := []any{}
	f := func(v int64) any { return float64(v) }
	b := func(v bool) any {
		if v {
			return float64(1)
		}
		return float64(0)
	}
	for _, p := range c.paths {
		base := -1.0
		if p.baseRTTSet {
			base = p.baseRTT
		}
		paths = append(paths, []any{f(int64(p.status)), f(int64(p.pref)), b(p.demoted), b(p.bad), p.reason, f(p.mtuOK), f(p.mtuLast), f(p.mtuProbe), f(p.mtuMin), f(p.mtuMax), b(p.rtt.setup), f(p.rtt.val), f(p.rtt.vr),
			f(p.tx.total), f(p.tx.bytes), f(p.tx.rate), f(p.tx.loss), f(p.tx.time), f(p.rx.total), f(p.rx.bytes), f(p.rx.loss), f(p.rx.time), f(p.msg.sent), f(p.msg.time), f(p.msg.txTime), f(p.msg.rxTime),
			f(p.msg.txBytes), f(p.msg.rxBytes), f(p.msg.txTotal), f(p.msg.rxTotal), f(p.msg.txAcc), f(p.msg.rxAcc), b(p.msg.set), f(p.dataTx), f(p.idle),
			base, p.badSince, p.goodSince, b(p.enabled), f(p.rxMaxRate), f(p.txMaxRate), f(int64(p.pref)), f(int64(p.basePref)), p.role})
	}
	// pref/basePref ordering: python lists p.pref again before base_pref; fix below.
	errs := map[string]any{}
	for k, v := range c.errors {
		errs[k] = float64(v)
	}
	return []any{f(int64(c.pref)), f(c.rate), f(c.mtu), f(c.window), f(c.windowTime), f(c.lastRecv), errs, b(c.kx.useNext), hex.EncodeToString(c.kx.remote), f(c.kx.time), paths}
}

func TestMudClientMatchesPython(t *testing.T) {
	v := loadMud(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	server := netip.MustParseAddrPort("203.0.113.7:65001")
	total := 0
	for si, sc := range v.Scenarios {
		var now int64 = sc.Init.T
		urand := 0
		cfg := Config{Key: key, Server: server, LocalIPs: sc.Init.IPs, Roles: sc.Init.Roles, Prefs: sc.Init.Prefs, RateMbps: sc.Init.Rate, BeatMS: sc.Init.Beat,
			JitterThresholdMS: sc.Init.Jitter, DemoteAfter: sc.Init.Demote, RecoverySeconds: sc.Init.Recovery,
			Now: func() int64 { return now }, Mono: func() float64 { return float64(now) / 1e6 },
			Random: func(n int) []byte { b := unhex(t, sc.Init.URandom[urand]); urand++; return b }}
		c, err := NewClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		type sent struct {
			slot int
			wire []byte
			to   netip.AddrPort
		}
		var out []sent
		for i, p := range c.paths {
			if sc.Init.Enabled[i] != p.enabled {
				t.Fatalf("scenario %d path %d enabled %v vs %v", si, i, p.enabled, sc.Init.Enabled[i])
			}
			if sc.Init.HasSock[i] {
				slot := i
				p.hasSock = true
				p.write = func(w []byte) error {
					out = append(out, sent{slot, append([]byte(nil), w...), c.cfg.Server})
					return nil
				}
			}
		}
		for stepNo, st := range sc.Steps {
			out = out[:0]
			now = st.Op.T
			var ret any
			switch st.Op.Kind {
			case "start":
				c.kx.rotateIfDue(c.clockNow(), KxTimeout)
			case "tick":
				c.update()
			case "in":
				ip := st.Op.Addr[0].(string)
				addr := netip.MustParseAddrPort(fmt.Sprintf("%s:%d", ip, int(st.Op.Addr[1].(float64))))
				c.onPacket(c.paths[st.Op.Slot], addr, unhex(t, st.Op.Packet))
			case "send":
				ret = c.send(unhex(t, st.Op.Packet), st.Op.Urgent)
			case "roles":
				if err := c.SetRoles(st.Op.Roles); err == nil {
					ret = "ok"
				} else {
					ret = "error"
				}
			case "rates":
				if err := c.SetRates(st.Op.Up, st.Op.Down); err == nil {
					ret = "ok"
				} else {
					ret = "error"
				}
			default:
				t.Fatalf("op %q", st.Op.Kind)
			}
			where := fmt.Sprintf("scenario %d step %d (%s)", si, stepNo, st.Op.Kind)
			if st.Ret != nil && !reflect.DeepEqual(st.Ret, ret) {
				t.Fatalf("%s: return %v vs %v", where, ret, st.Ret)
			}
			if len(out) != len(st.Out) {
				t.Fatalf("%s: %d datagrams vs python %d", where, len(out), len(st.Out))
			}
			for i, o := range out {
				w := st.Out[i]
				sum := sha256.Sum256(o.wire)
				if int(w[0].(float64)) != o.slot || w[1].(string) != hex.EncodeToString(sum[:]) || int(w[2].(float64)) != len(o.wire) {
					t.Fatalf("%s: datagram %d differs (slot %v/%d, len %v/%d)", where, i, w[0], o.slot, w[2], len(o.wire))
				}
			}
			var inbox []string
		drain:
			for {
				select {
				case p := <-c.inbox:
					sum := sha256.Sum256(p)
					inbox = append(inbox, hex.EncodeToString(sum[:]))
				default:
					break drain
				}
			}
			if !reflect.DeepEqual(append([]string{}, inbox...), append([]string{}, st.Inbox...)) {
				t.Fatalf("%s: inbox %v vs %v", where, inbox, st.Inbox)
			}
			if st.Op.Kind == "send" {
				var s struct {
					Window float64 `json:"window"`
				}
				json.Unmarshal(st.Snap, &s)
				if float64(c.window) != s.Window {
					t.Fatalf("%s: window %d vs %v", where, c.window, s.Window)
				}
				total++
				continue
			}
			compareSnapshot(t, where, st.Snap, c)
			total++
		}
		c.Close()
	}
	t.Logf("%d steps compared", total)
}

func compareSnapshot(t *testing.T, where string, raw json.RawMessage, c *Client) {
	t.Helper()
	var py struct {
		Pref, Rate, MTU, Window, WindowTime, LastRecv int64
		Errors                                        map[string]int
		UseNext                                       int     `json:"use_next"`
		Remote                                        string  `json:"remote"`
		KTime                                         int64   `json:"ktime"`
		Paths                                         [][]any `json:"paths"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Field names in the document are snake_case.
	var m map[string]json.RawMessage
	json.Unmarshal(raw, &m)
	_ = dec
	num := func(key string) int64 {
		var v int64
		json.Unmarshal(m[key], &v)
		return v
	}
	py.Pref, py.Rate, py.MTU, py.Window, py.WindowTime, py.LastRecv = num("pref"), num("rate"), num("mtu"), num("window"), num("window_time"), num("last_recv")
	json.Unmarshal(m["errors"], &py.Errors)
	json.Unmarshal(m["use_next"], &py.UseNext)
	json.Unmarshal(m["remote"], &py.Remote)
	json.Unmarshal(m["ktime"], &py.KTime)
	json.Unmarshal(m["paths"], &py.Paths)
	if int64(c.pref) != py.Pref || c.rate != py.Rate || c.mtu != py.MTU || c.window != py.Window || c.windowTime != py.WindowTime || c.lastRecv != py.LastRecv || c.kx.time != py.KTime ||
		hex.EncodeToString(c.kx.remote) != py.Remote || (map[bool]int{true: 1, false: 0})[c.kx.useNext] != py.UseNext {
		t.Fatalf("%s: client state differs\n go: pref=%d rate=%d mtu=%d window=%d wt=%d last=%d ktime=%d remote=%x useNext=%v\n py: %+v", where, c.pref, c.rate, c.mtu, c.window, c.windowTime, c.lastRecv, c.kx.time, c.kx.remote, c.kx.useNext, py)
	}
	if !reflect.DeepEqual(c.errors, py.Errors) {
		t.Fatalf("%s: errors %v vs %v", where, c.errors, py.Errors)
	}
	goPaths := goSnapshot(c)[10].([]any)
	if len(goPaths) != len(py.Paths) {
		t.Fatalf("%s: path count", where)
	}
	names := []string{"status", "pref", "demoted", "bad", "reason", "mtu_ok", "mtu_last", "mtu_probe", "mtu_min", "mtu_max", "rtt.setup", "rtt.val", "rtt.var", "tx.total", "tx.bytes", "tx.rate", "tx.loss", "tx.time", "rx.total", "rx.bytes", "rx.loss", "rx.time",
		"msg.sent", "msg.time", "msg.tx_time", "msg.rx_time", "msg.tx_bytes", "msg.rx_bytes", "msg.tx_total", "msg.rx_total", "msg.tx_acc", "msg.rx_acc", "msg.set", "data_tx", "idle", "base_rtt", "bad_since", "good_since", "enabled", "rx_max_rate", "tx_max_rate", "pref2", "base_pref", "role"}
	for i := range goPaths {
		g := goPaths[i].([]any)
		for j := range py.Paths[i] {
			if false {
				continue
			}
			if !reflect.DeepEqual(g[j], py.Paths[i][j]) {
				t.Fatalf("%s: path %d field %s: go %v python %v", where, i, names[j], g[j], py.Paths[i][j])
			}
		}
	}
}
