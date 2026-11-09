// client-probe is a loopback-only interoperability harness for the Go client
// role, not a client daemon. It binds one UDP socket per simulated uplink,
// handshakes each against a server (normally the Python Node), then sends a
// numbered payload stream striped across the uplinks and counts what comes back.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime/pprof"
	"time"

	"gamebond.local/nativeedge/bond"
)

type config struct {
	Key, Session string
	Server       string
	Paths        int
	Send         int     // payloads to send once every uplink is ready
	MTU          bool    // enable per-path MTU discovery
	Rate         float64 // sender initial and maximum Mbit/s per uplink (default 10/20)
	PolicyMbps   float64 // upload/download policy per uplink when Policy is set (default 50)
	Profile      string  // write a CPU profile here (diagnostics)
	AsyncWrite   bool    // hand frames to a per-uplink writer goroutine instead of writing inline
	Spin         bool    // busy-poll instead of sleeping on a ticker (timer-granularity experiment)
	Policy       bool    // send a primary link policy on every uplink (50 Mbit/s each way)
}

type datagram struct {
	local    int
	frame    []byte
	endpoint netip.AddrPort
}

func payload(n int) []byte {
	p := make([]byte, 1000)
	binary.BigEndian.PutUint64(p, uint64(n))
	for i := 8; i < len(p); i++ {
		p[i] = byte(n % 251)
	}
	return p
}

func run() error {
	input := bufio.NewReader(io.LimitReader(os.Stdin, 4096))
	line, err := input.ReadBytes('\n')
	if err != nil {
		return err
	}
	var c config
	if err = json.Unmarshal(line, &c); err != nil || c.Paths < 1 || c.Paths > 8 {
		return fmt.Errorf("invalid test configuration")
	}
	if c.Profile != "" {
		f, err := os.Create(c.Profile)
		if err != nil {
			return err
		}
		pprof.StartCPUProfile(f)
		defer func() { pprof.StopCPUProfile(); f.Close() }()
	}
	key, err := hex.DecodeString(c.Key)
	if err != nil {
		return fmt.Errorf("invalid test key")
	}
	session, err := hex.DecodeString(c.Session)
	if err != nil {
		return fmt.Errorf("invalid test session")
	}
	server, err := netip.ParseAddrPort(c.Server)
	if err != nil || !server.Addr().IsLoopback() {
		return fmt.Errorf("server must be a loopback address")
	}
	codec, err := bond.NewCodec(key, session, "client")
	if err != nil {
		return err
	}
	receiver, err := bond.NewReceiver(codec, 1400)
	if err != nil {
		return err
	}
	if err = receiver.SetPathMTUDiscovery(c.MTU); err != nil {
		return err
	}
	sender, err := bond.NewSender(receiver, max(10, c.Rate/4), max(20, c.Rate))
	_ = sender
	if err != nil {
		return err
	}
	outbound, err := bond.NewTransmitQueue(sender, 40000, 64*1024*1024)
	if err != nil {
		return err
	}
	conns := make([]*net.UDPConn, c.Paths)
	incoming := make(chan datagram, 1024)
	for i := range conns {
		conns[i], err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return err
		}
		defer conns[i].Close()
		if err = receiver.AddClientPath(i, server, time.Now()); err != nil {
			return err
		}
		go func(i int) {
			buffer := make([]byte, 65536)
			for {
				n, from, err := conns[i].ReadFromUDPAddrPort(buffer)
				if err != nil {
					return
				}
				incoming <- datagram{i, append([]byte(nil), buffer[:n]...), from}
			}
		}(i)
	}
	writers := make([]chan bond.Datagram, len(conns))
	for i := range writers {
		writers[i] = make(chan bond.Datagram, 8192)
		go func(i int) {
			for d := range writers[i] {
				conns[i].WriteToUDPAddrPort(d.Frame, d.Endpoint)
			}
		}(i)
	}
	writer := func(d bond.Datagram) error {
		if d.Local < 0 || d.Local >= len(conns) {
			return fmt.Errorf("datagram for unknown local socket %d", d.Local)
		}
		if c.AsyncWrite {
			select {
			case writers[d.Local] <- d:
				return nil
			default:
				return fmt.Errorf("uplink %d writer queue full", d.Local)
			}
		}
		_, err := conns[d.Local].WriteToUDPAddrPort(d.Frame, d.Endpoint)
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	if err = encoder.Encode(map[string]any{"status": "started", "paths": c.Paths, "scope": "loopback client interoperability only"}); err != nil {
		return err
	}
	if c.Policy {
		policies := make([]bond.PathPolicy, c.Paths)
		for i := range policies {
			policies[i] = bond.PathPolicy{Role: bond.Primary, UploadMbps: max(1, c.PolicyMbps), DownloadMbps: max(1, c.PolicyMbps)}
		}
		if err = receiver.SetClientLinkPolicies(policies, time.Now()); err != nil {
			return err
		}
	}
	quit := make(chan struct{})
	go func() { input.ReadByte(); close(quit) }()

	delivered := map[int]int{}
	corrupt := 0
	handle := func(result bond.ReceiveResult) {
		now := time.Now()
		sender.Controls(result, now, writer)
		for _, p := range result.Deliver {
			if len(p) != 1000 {
				corrupt++
				continue
			}
			n := int(binary.BigEndian.Uint64(p))
			if string(p) != string(payload(n)) {
				corrupt++
				continue
			}
			delivered[n]++
		}
	}
	sent, firstReady, firstSend := false, time.Time{}, time.Now()
	end := time.Now().Add(30 * time.Second)
	tick := time.NewTicker(100 * time.Microsecond)
	defer tick.Stop()
	tickC := tick.C
	if c.Spin { // a closed channel is always ready: the loop never sleeps
		ready := make(chan time.Time)
		close(ready)
		tickC = ready
	}
	nextBulk := time.Now()
loop:
	for time.Now().Before(end) {
		select {
		case <-quit:
			break loop
		case d := <-incoming:
			result, err := receiver.ReceiveOn(d.local, d.frame, d.endpoint, time.Now())
			if err != nil {
				return err
			}
			handle(result)
		case <-tickC:
		}
		now := time.Now()
		result, err := receiver.Tick(now)
		if err != nil {
			return err
		}
		handle(result)
		if err = sender.Maintenance(now, writer); err != nil {
			return err
		}
		if !sent && receiver.ReadyPaths(now) == c.Paths {
			if firstReady.IsZero() {
				firstReady = now
			}
			// Let every uplink get an RTT sample so striping has real inputs.
			if now.Sub(firstReady) > 400*time.Millisecond {
				for n := 0; n < c.Send; n++ {
					if !outbound.Enqueue(bond.QueuedPacket{Payload: payload(n), Flow: "client-probe", Expires: now.Add(10 * time.Second)}) {
						return fmt.Errorf("bounded send queue full at %d", n)
					}
				}
				sent = true
				firstSend = now
			}
		}
		if outbound.Stats().QueuedPackets > 0 && !time.Now().Before(nextBulk) {
			if nextBulk, err = outbound.Pump(time.Now(), writer); err != nil {
				return err
			}
		}
	}
	drained := time.Since(firstSend)
	unique := len(delivered)
	duplicates := 0
	for _, count := range delivered {
		duplicates += count - 1
	}
	return encoder.Encode(map[string]any{"receiver": receiver.Stats(), "sender": sender.Stats(), "paths": sender.Paths(time.Now()),
		"transmit_queue": outbound.Stats(), "ready_paths": receiver.ReadyPaths(time.Now()),
		"delivered_unique": unique, "delivered_duplicates": duplicates, "corrupt": corrupt, "sent_enqueued": sent, "seconds_to_drain": drained.Seconds()})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
