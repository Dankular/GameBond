package dns

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"
)

type vectorFile struct {
	Bad   []json.RawMessage `json:"bad"`
	Cases []struct {
		Config json.RawMessage `json:"config"`
		Rows   []struct {
			Packet   string  `json:"packet"`
			TCP      bool    `json:"tcp"`
			Answer   string  `json:"answer"`
			Override *string `json:"override"`
		} `json:"rows"`
		Stats struct {
			Queries   uint64 `json:"queries"`
			Overrides uint64 `json:"overrides"`
			Malformed uint64 `json:"malformed"`
		} `json:"stats"`
	} `json:"cases"`
}

func loadVectors(t *testing.T) vectorFile {
	f, err := os.Open("testdata/dns-vectors.json.gz")
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

func TestPythonVectors(t *testing.T) {
	v := loadVectors(t)
	for i, raw := range v.Bad {
		if _, err := Load(raw); err == nil {
			t.Errorf("bad config %d accepted: %s", i, raw)
		}
	}
	rows := 0
	for ci, c := range v.Cases {
		cfg, err := Load(c.Config)
		if err != nil {
			t.Fatalf("case %d: %v", ci, err)
		}
		r := NewResponder(cfg)
		for ri, row := range c.Rows {
			p, _ := hex.DecodeString(row.Packet)
			got := hex.EncodeToString(r.Answer(p, row.TCP))
			if got != row.Answer {
				t.Fatalf("case %d row %d answer mismatch\npacket %s\n got %s\nwant %s", ci, ri, row.Packet, got, row.Answer)
			}
			ov := cfg.Override(p)
			switch {
			case row.Override == nil && ov != nil:
				t.Fatalf("case %d row %d: unexpected override %x", ci, ri, ov)
			case row.Override != nil && hex.EncodeToString(ov) != *row.Override:
				t.Fatalf("case %d row %d override mismatch\n got %x\nwant %s", ci, ri, ov, *row.Override)
			}
			rows++
		}
		s := r.Stats()
		if s.Queries != c.Stats.Queries || s.Overrides != c.Stats.Overrides || s.Malformed != c.Stats.Malformed {
			t.Errorf("case %d stats %+v want %+v", ci, s, c.Stats)
		}
	}
	t.Logf("%d rows over %d configs", rows, len(v.Cases))
}

func TestLoopbackUDPAndTCP(t *testing.T) {
	cfg, err := Load([]byte(`{"records":{"game.test":{"A":["10.1.2.3"]}},"bind":["127.0.0.1",0]}`))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	q := []byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 'g', 'a', 'm', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	u, err := net.Dial("udp4", r.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	_ = u.SetDeadline(time.Now().Add(2 * time.Second))
	u.Write(q)
	buf := make([]byte, 512)
	n, err := u.Read(buf)
	if err != nil || !bytes.HasSuffix(buf[:n], []byte{10, 1, 2, 3}) {
		t.Fatalf("udp reply %x err %v", buf[:n], err)
	}
	c, err := net.Dial("tcp4", r.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	n, err = c.Read(buf)
	if err != nil || n < 14 || !bytes.HasSuffix(buf[2:n], []byte{10, 1, 2, 3}) {
		t.Fatalf("tcp reply %x err %v", buf[:n], err)
	}
}
