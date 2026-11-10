// Package dishwatch reads a Starlink dish's own per-second history over its
// local gRPC-web interface so the bond can treat the dish's line as degraded a
// second or two before its own loss detection would. Field numbers follow the
// community schema (starlink-grpc-tools); they were checked against live
// firmware responses, not against an official specification.
package dishwatch

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	requestHistory = 1007 // Request.get_history
	responseField  = 2006 // Response.dish_get_history
	fieldCurrent   = 1
	fieldDrop      = 1001 // pop_ping_drop_rate, one float per second
	fieldLatency   = 1002 // pop_ping_latency_ms, one float per second
	ringSize       = 900
)

// Config selects the dish and the uplink it serves.
type Config struct {
	URL      string        // e.g. http://192.168.100.1:9201
	Interval time.Duration // default 1s
	Client   *http.Client  // optional
}

// Sample is the dish's recent state.
type Sample struct {
	OK        bool
	At        time.Time
	DropMax3s float64 // worst ping drop rate (0..1) in the last 3 s
	LatencyMS float64 // latest pop ping latency
	BaseMS    float64 // median latency over the last minute
	Degraded  bool
	Reason    string
}

// Thresholds: a 10% loss second, or latency 30 ms over the minute's median.
const (
	dropThreshold   = 0.10
	latencyExcessMS = 30.0
	recentSeconds   = 3
	baselineSeconds = 60
)

var ErrFormat = errors.New("dishwatch: unexpected response")

func uvarint(b []byte, i int) (uint64, int, error) {
	var x uint64
	for s := uint(0); i < len(b) && s < 70; s += 7 {
		c := b[i]
		i++
		x |= uint64(c&0x7f) << s
		if c < 0x80 {
			return x, i, nil
		}
	}
	return 0, i, ErrFormat
}

type field struct {
	num  uint64
	wire uint64
	val  uint64
	data []byte
}

func parse(b []byte) ([]field, error) {
	var out []field
	for i := 0; i < len(b); {
		key, n, err := uvarint(b, i)
		if err != nil {
			return nil, err
		}
		i = n
		f := field{num: key >> 3, wire: key & 7}
		switch f.wire {
		case 0:
			if f.val, i, err = uvarint(b, i); err != nil {
				return nil, err
			}
		case 1:
			if i+8 > len(b) {
				return nil, ErrFormat
			}
			i += 8
		case 5:
			if i+4 > len(b) {
				return nil, ErrFormat
			}
			i += 4
		case 2:
			l, n, err := uvarint(b, i)
			if err != nil || l > uint64(len(b)-n) {
				return nil, ErrFormat
			}
			f.data = b[n : n+int(l)]
			i = n + int(l)
		default:
			return nil, ErrFormat
		}
		out = append(out, f)
	}
	return out, nil
}

func floats(b []byte) []float64 {
	if len(b)%4 != 0 {
		return nil
	}
	out := make([]float64, len(b)/4)
	for i := range out {
		out[i] = float64(math.Float32frombits(binary.LittleEndian.Uint32(b[i*4:])))
	}
	return out
}

// requestBody is the base64 gRPC-web frame asking for the history.
func requestBody() string {
	msg := binary.AppendUvarint(nil, requestHistory<<3|2)
	msg = append(msg, 0)
	frame := append([]byte{0, 0, 0, 0, byte(len(msg))}, msg...)
	return base64.StdEncoding.EncodeToString(frame)
}

// Decode turns a gRPC-web text response into a Sample.
func Decode(body []byte, now time.Time) (Sample, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		// grpc-web-text may concatenate several base64 groups.
		raw = nil
		for _, part := range strings.Split(strings.TrimSpace(string(body)), "=") {
			if part == "" {
				continue
			}
			for len(part)%4 != 0 {
				part += "="
			}
			chunk, e := base64.StdEncoding.DecodeString(part)
			if e != nil {
				return Sample{}, ErrFormat
			}
			raw = append(raw, chunk...)
		}
	}
	for len(raw) >= 5 {
		flag, size := raw[0], int(binary.BigEndian.Uint32(raw[1:5]))
		if size < 0 || 5+size > len(raw) {
			return Sample{}, ErrFormat
		}
		payload := raw[5 : 5+size]
		raw = raw[5+size:]
		if flag&0x80 != 0 {
			continue // trailers
		}
		return decodeMessage(payload, now)
	}
	return Sample{}, ErrFormat
}

func decodeMessage(msg []byte, now time.Time) (Sample, error) {
	top, err := parse(msg)
	if err != nil {
		return Sample{}, err
	}
	var inner []byte
	for _, f := range top {
		if f.num == responseField && f.wire == 2 {
			inner = f.data
		}
	}
	if inner == nil {
		return Sample{}, ErrFormat
	}
	fields, err := parse(inner)
	if err != nil {
		return Sample{}, err
	}
	var current uint64
	var drop, lat []float64
	for _, f := range fields {
		switch {
		case f.num == fieldCurrent && f.wire == 0:
			current = f.val
		case f.num == fieldDrop && f.wire == 2:
			drop = floats(f.data)
		case f.num == fieldLatency && f.wire == 2:
			lat = floats(f.data)
		}
	}
	if len(drop) != ringSize || len(lat) != ringSize {
		return Sample{}, ErrFormat
	}
	return summarise(drop, lat, int(current%ringSize), now), nil
}

// summarise reads the ring buffer: the oldest sample sits at the write index.
func summarise(drop, lat []float64, write int, now time.Time) Sample {
	at := func(a []float64, back int) float64 { return a[((write-1-back)%ringSize+ringSize)%ringSize] }
	s := Sample{OK: true, At: now}
	for i := 0; i < recentSeconds; i++ {
		if d := at(drop, i); d > s.DropMax3s && d <= 1 {
			s.DropMax3s = d
		}
	}
	s.LatencyMS = at(lat, 0)
	var window []float64
	for i := 0; i < baselineSeconds; i++ {
		if v := at(lat, i); v > 0 {
			window = append(window, v)
		}
	}
	if len(window) > 0 {
		sort.Float64s(window)
		s.BaseMS = window[len(window)/2]
	}
	switch {
	case s.DropMax3s >= dropThreshold:
		s.Degraded, s.Reason = true, "packet_loss"
	case s.BaseMS > 0 && (at(lat, 0) > s.BaseMS+latencyExcessMS || at(lat, 1) > s.BaseMS+latencyExcessMS):
		s.Degraded, s.Reason = true, "latency"
	}
	return s
}

// Run polls until ctx ends, calling onSample after every attempt (OK false on
// failure). A dish that cannot be reached is simply not a signal.
func Run(ctx context.Context, cfg Config, onSample func(Sample)) {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	url := strings.TrimRight(cfg.URL, "/") + "/SpaceX.API.Device.Device/Handle"
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		onSample(fetch(ctx, client, url))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func fetch(ctx context.Context, client *http.Client, url string) Sample {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(requestBody())))
	if err != nil {
		return Sample{}
	}
	req.Header.Set("content-type", "application/grpc-web-text")
	req.Header.Set("x-grpc-web", "1")
	req.Header.Set("accept", "application/grpc-web-text")
	resp, err := client.Do(req)
	if err != nil {
		return Sample{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Sample{}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Sample{}
	}
	s, err := Decode(body, time.Now())
	if err != nil {
		return Sample{}
	}
	return s
}
