// leg-probe measures one leg of the path in isolation: the raw UDP socket
// between two points, with no GB03 protocol on top. Compare its numbers with the
// bonded Go-to-Go numbers to see how much the protocol layer costs.
//
//	leg-probe loopback [-size 1113] [-seconds 2]      self-contained, both ends local
//	leg-probe serve    [-addr 0.0.0.0:7000]           echo + counter; run on the far host
//	leg-probe measure  -target host:7000 [...]        RTT/jitter/loss then throughput
//
// "serve" and "measure" against a remote host send real traffic to that host:
// run them only against hosts you control, and they are never started by tests.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"time"
)

const (
	tagPing  = 1
	tagBlast = 2
	tagEnd   = 3
	tagStat  = 4
)

func serve(conn *net.UDPConn, stop <-chan struct{}) {
	buf := make([]byte, 65536)
	var count, bytes uint64
	var first, last time.Time
	for {
		select {
		case <-stop:
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			continue
		}
		if n < 9 {
			continue
		}
		switch buf[0] {
		case tagPing:
			conn.WriteToUDPAddrPort(buf[:n], from)
		case tagBlast:
			if count == 0 {
				first = time.Now()
			}
			last = time.Now()
			count++
			bytes += uint64(n)
		case tagEnd:
			reply := make([]byte, 33)
			reply[0] = tagStat
			binary.BigEndian.PutUint64(reply[1:], count)
			binary.BigEndian.PutUint64(reply[9:], bytes)
			binary.BigEndian.PutUint64(reply[17:], uint64(last.Sub(first)))
			conn.WriteToUDPAddrPort(reply, from)
			count, bytes = 0, 0
		}
	}
}

type result struct {
	Target                       string  `json:"target"`
	Size                         int     `json:"size"`
	RTTSamples                   int     `json:"rtt_samples"`
	RTTLossPercent               float64 `json:"rtt_loss_percent"`
	RTTP50Ms, RTTP99Ms, RTTMaxMs float64
	JitterMs                     float64 `json:"jitter_ms"`
	Sent, Received               uint64
	LossPercent                  float64 `json:"loss_percent"`
	Mbit                         float64 `json:"mbit_per_s"`
	SendMbit                     float64 `json:"send_mbit_per_s"`
}

func measure(target string, size int, seconds float64) (result, error) {
	addr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return result{}, err
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return result{}, err
	}
	defer conn.Close()
	conn.SetReadBuffer(8 << 20)
	conn.SetWriteBuffer(8 << 20)
	r := result{Target: target, Size: size}
	buf := make([]byte, 65536)
	var rtts []float64
	lost := 0
	for i := 0; i < 200; i++ {
		ping := make([]byte, 16)
		ping[0] = tagPing
		binary.BigEndian.PutUint64(ping[1:], uint64(i))
		t0 := time.Now()
		conn.Write(ping)
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := conn.Read(buf); err != nil {
			lost++
		} else {
			rtts = append(rtts, float64(time.Since(t0).Microseconds())/1000)
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.RTTSamples, r.RTTLossPercent = len(rtts), float64(lost)/2
	if len(rtts) > 0 {
		sorted := append([]float64(nil), rtts...)
		sort.Float64s(sorted)
		r.RTTP50Ms, r.RTTP99Ms, r.RTTMaxMs = sorted[len(sorted)/2], sorted[len(sorted)*99/100], sorted[len(sorted)-1]
		var sum float64
		for i := 1; i < len(rtts); i++ {
			d := rtts[i] - rtts[i-1]
			if d < 0 {
				d = -d
			}
			sum += d
		}
		if len(rtts) > 1 {
			r.JitterMs = sum / float64(len(rtts)-1)
		}
	}
	packet := make([]byte, size)
	packet[0] = tagBlast
	start := time.Now()
	for time.Since(start) < time.Duration(seconds*float64(time.Second)) {
		binary.BigEndian.PutUint64(packet[1:], r.Sent)
		if _, err := conn.Write(packet); err == nil {
			r.Sent++
		}
	}
	sendSeconds := time.Since(start).Seconds()
	time.Sleep(200 * time.Millisecond)
	end := []byte{tagEnd, 0, 0, 0, 0, 0, 0, 0, 0}
	for attempt := 0; attempt < 5; attempt++ {
		conn.Write(end)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err == nil && n == 33 && buf[0] == tagStat {
			r.Received = binary.BigEndian.Uint64(buf[1:])
			bytes := binary.BigEndian.Uint64(buf[9:])
			span := time.Duration(binary.BigEndian.Uint64(buf[17:])).Seconds()
			if span > 0 {
				r.Mbit = float64(bytes) * 8 / span / 1e6
			}
			break
		}
	}
	if r.Sent > 0 {
		r.LossPercent = 100 * float64(r.Sent-min(r.Sent, r.Received)) / float64(r.Sent)
		r.SendMbit = float64(r.Sent) * float64(size) * 8 / sendSeconds / 1e6
	}
	return r, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: leg-probe loopback|serve|measure")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	size := fs.Int("size", 1113, "datagram size in bytes (default matches a 1000-byte payload plus GB03 overhead)")
	seconds := fs.Float64("seconds", 2, "throughput phase length")
	addr := fs.String("addr", "127.0.0.1:0", "serve listen address")
	target := fs.String("target", "", "measure target host:port")
	fs.Parse(os.Args[2:])
	if *size < 16 || *size > 1472 {
		fmt.Fprintln(os.Stderr, "size must be 16..1472")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "loopback":
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		conn.SetReadBuffer(8 << 20)
		stop := make(chan struct{})
		go serve(conn, stop)
		r, err := measure(conn.LocalAddr().String(), *size, *seconds)
		close(stop)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(r)
	case "serve":
		a, err := net.ResolveUDPAddr("udp4", *addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		conn, err := net.ListenUDP("udp4", a)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		conn.SetReadBuffer(8 << 20)
		fmt.Println(conn.LocalAddr())
		serve(conn, make(chan struct{}))
	case "measure":
		if *target == "" {
			fmt.Fprintln(os.Stderr, "-target required")
			os.Exit(2)
		}
		r, err := measure(*target, *size, *seconds)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(r)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(2)
	}
}
