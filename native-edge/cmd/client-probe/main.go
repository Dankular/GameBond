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
	"time"

	"gamebond.local/nativeedge/bond"
)

type config struct {
	Key, Session string
	Server       string
	Paths        int
	Send         int // payloads to send once every uplink is ready
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
	sender, err := bond.NewSender(receiver, 10, 20)
	if err != nil {
		return err
	}
	outbound, err := bond.NewTransmitQueue(sender, 1024, 4*1024*1024)
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
	writer := func(d bond.Datagram) error {
		if d.Local < 0 || d.Local >= len(conns) {
			return fmt.Errorf("datagram for unknown local socket %d", d.Local)
		}
		_, err := conns[d.Local].WriteToUDPAddrPort(d.Frame, d.Endpoint)
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	if err = encoder.Encode(map[string]any{"status": "started", "paths": c.Paths, "scope": "loopback client interoperability only"}); err != nil {
		return err
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
	sent, firstReady := false, time.Time{}
	end := time.Now().Add(30 * time.Second)
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
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
		case <-tick.C:
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
			}
		}
		if outbound.Stats().QueuedPackets > 0 && !time.Now().Before(nextBulk) {
			if nextBulk, err = outbound.Pump(time.Now(), writer); err != nil {
				return err
			}
		}
	}
	unique := len(delivered)
	duplicates := 0
	for _, count := range delivered {
		duplicates += count - 1
	}
	return encoder.Encode(map[string]any{"receiver": receiver.Stats(), "sender": sender.Stats(), "paths": sender.Paths(time.Now()),
		"transmit_queue": outbound.Stats(), "ready_paths": receiver.ReadyPaths(time.Now()),
		"delivered_unique": unique, "delivered_duplicates": duplicates, "corrupt": corrupt, "sent_enqueued": sent})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
