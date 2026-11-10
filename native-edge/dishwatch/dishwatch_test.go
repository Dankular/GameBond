package dishwatch

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func pbBytes(num uint64, data []byte) []byte {
	out := binary.AppendUvarint(nil, num<<3|2)
	out = binary.AppendUvarint(out, uint64(len(data)))
	return append(out, data...)
}

func pbFloats(num uint64, v []float64) []byte {
	b := make([]byte, 0, len(v)*4)
	for _, f := range v {
		b = binary.LittleEndian.AppendUint32(b, math.Float32bits(float32(f)))
	}
	return pbBytes(num, b)
}

// response builds a history with `write` as the next slot to be written.
func response(write int, drop, lat func(i int) float64) []byte {
	d, l := make([]float64, ringSize), make([]float64, ringSize)
	for i := range d {
		d[i], l[i] = drop(i), lat(i)
	}
	inner := binary.AppendUvarint(nil, fieldCurrent<<3)
	inner = binary.AppendUvarint(inner, uint64(write))
	inner = append(inner, pbFloats(fieldDrop, d)...)
	inner = append(inner, pbFloats(fieldLatency, l)...)
	msg := pbBytes(responseField, inner)
	frame := append([]byte{0}, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(frame[1:], uint32(len(msg)))
	frame = append(frame, msg...)
	trailer := []byte("grpc-status:0\r\n")
	tf := append([]byte{0x80, 0, 0, 0, byte(len(trailer))}, trailer...)
	return []byte(base64.StdEncoding.EncodeToString(append(frame, tf...)))
}

func TestHealthyDish(t *testing.T) {
	body := response(500, func(int) float64 { return 0 }, func(int) float64 { return 30 })
	s, err := Decode(body, time.Now())
	if err != nil || !s.OK || s.Degraded || s.BaseMS != 30 {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestRecentLossBurstIsDegradedAndOldOneIsNot(t *testing.T) {
	// slot 499 is the newest second; slot 200 is long ago.
	recent := response(500, func(i int) float64 {
		if i == 498 {
			return .5
		}
		return 0
	}, func(int) float64 { return 30 })
	s, _ := Decode(recent, time.Now())
	if !s.Degraded || s.Reason != "packet_loss" {
		t.Fatalf("recent burst: %+v", s)
	}
	old := response(500, func(i int) float64 {
		if i == 200 {
			return .5
		}
		return 0
	}, func(int) float64 { return 30 })
	if s, _ := Decode(old, time.Now()); s.Degraded {
		t.Fatalf("old burst must not count: %+v", s)
	}
}

func TestRingWrap(t *testing.T) {
	// write index 1 means the newest sample is slot 0 and the one before is 899.
	body := response(1, func(i int) float64 {
		if i == 899 {
			return .3
		}
		return 0
	}, func(int) float64 { return 30 })
	if s, _ := Decode(body, time.Now()); !s.Degraded {
		t.Fatalf("wrapped ring missed the newest-but-one second: %+v", s)
	}
}

func TestLatencySpike(t *testing.T) {
	body := response(500, func(int) float64 { return 0 }, func(i int) float64 {
		if i == 499 {
			return 120
		}
		return 30
	})
	s, _ := Decode(body, time.Now())
	if !s.Degraded || s.Reason != "latency" {
		t.Fatalf("%+v", s)
	}
}

func TestGarbageIsRejected(t *testing.T) {
	for _, b := range []string{"", "!!!", base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0, 9, 1})} {
		if _, err := Decode([]byte(b), time.Now()); err == nil {
			t.Fatalf("accepted %q", b)
		}
	}
}

func TestRunPollsAndReportsFailure(t *testing.T) {
	good := response(500, func(int) float64 { return 0 }, func(int) float64 { return 30 })
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("content-type") != "application/grpc-web-text" {
			t.Errorf("content-type %q", r.Header.Get("content-type"))
		}
		if calls == 1 {
			http.Error(w, "no", 500)
			return
		}
		w.Write(good)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var got []bool
	go Run(ctx, Config{URL: srv.URL, Interval: 10 * time.Millisecond}, func(s Sample) {
		got = append(got, s.OK)
		if len(got) == 3 {
			cancel()
		}
	})
	<-ctx.Done()
	time.Sleep(20 * time.Millisecond)
	if len(got) < 3 || got[0] || !got[1] || !got[2] {
		t.Fatalf("%v", got)
	}
}
