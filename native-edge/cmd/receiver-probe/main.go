// receiver-probe is a loopback-only interoperability harness, not an edge daemon.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"gamebond.local/nativeedge/bond"
	"gamebond.local/nativeedge/hrclock"
)

type config struct {
	Key, Session string
	Bonded       bool
	Sink         bool    // count payloads, do not echo them
	Rate         float64 // bonded sender ceiling Mbit/s per uplink (default 10/20)
}

func run() error {
	input := bufio.NewReader(io.LimitReader(os.Stdin, 4096))
	line, err := input.ReadBytes('\n')
	if err != nil {
		return err
	}
	var c config
	if err = json.Unmarshal(line, &c); err != nil {
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
	codec, err := bond.NewCodec(key, session, "server")
	if err != nil {
		return err
	}
	receiver, err := bond.NewReceiver(codec, 1400)
	if err != nil {
		return err
	}
	var sender *bond.Sender
	var outbound *bond.TransmitQueue
	if c.Bonded {
		sender, err = bond.NewSender(receiver, max(10, c.Rate/4), max(20, c.Rate))
		if err != nil {
			return err
		}
		outbound, err = bond.NewTransmitQueue(sender, 1024, 1024*1024)
		if err != nil {
			return err
		}
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer conn.Close()
	encoder := json.NewEncoder(os.Stdout)
	if err = encoder.Encode(map[string]any{"address": conn.LocalAddr().String(), "scope": "loopback receive interoperability only"}); err != nil {
		return err
	}
	go func() { input.ReadByte(); conn.Close() }()
	var destination netip.AddrPort
	writer := func(d bond.Datagram) error { _, err := conn.WriteToUDPAddrPort(d.Frame, d.Endpoint); return err }
	var firstPayload, lastPayload time.Time
	var seenPayloads uint64
	output := func(result bond.ReceiveResult) error {
		if n := receiver.Stats().PayloadPackets; n != seenPayloads {
			seenPayloads = n
			if firstPayload.IsZero() {
				firstPayload = hrclock.Now()
			}
			lastPayload = hrclock.Now()
		}
		if c.Sink {
			if sender != nil {
				sender.Controls(result, hrclock.Now(), writer)
			} else {
				for _, d := range result.Send {
					_, err := conn.WriteToUDPAddrPort(d.Frame, d.Endpoint)
					receiver.Sent(d, err)
				}
			}
			return nil
		}
		if sender != nil {
			now := hrclock.Now()
			sender.Controls(result, now, writer)
			for _, payload := range result.Deliver {
				if !outbound.Enqueue(bond.QueuedPacket{Payload: payload, Flow: "probe-echo", Expires: now.Add(200 * time.Millisecond)}) {
					return fmt.Errorf("bounded echo queue full")
				}
			}
			return nil
		}
		for _, d := range result.Send {
			if !destination.IsValid() && d.Frame[36] == bond.Ready {
				destination = d.Endpoint
			}
			_, err := conn.WriteToUDPAddrPort(d.Frame, d.Endpoint)
			receiver.Sent(d, err)
			if err != nil {
				return err
			}
		}
		for _, payload := range result.Deliver {
			if !destination.IsValid() {
				return fmt.Errorf("no echo destination")
			}
			frame, err := codec.Encode(bond.Data, payload)
			if err != nil {
				return err
			}
			d := bond.Datagram{Endpoint: destination, Frame: frame}
			_, err = conn.WriteToUDPAddrPort(frame, destination)
			receiver.Sent(d, err)
			if err != nil {
				return err
			}
		}
		return nil
	}
	buffer := make([]byte, 65536)
	end := hrclock.Now().Add(30 * time.Second)
	nextTick := hrclock.Now()
	nextBulk := nextTick
	for hrclock.Now().Before(end) {
		deadline := hrclock.Now().Add(2 * time.Millisecond)
		if outbound != nil && outbound.Stats().QueuedPackets > 0 && nextBulk.Before(deadline) {
			deadline = nextBulk
		}
		conn.SetReadDeadline(deadline)
		n, endpoint, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				break
			}
		} else {
			result, err := receiver.Receive(buffer[:n], endpoint, hrclock.Now())
			if err != nil {
				return err
			}
			if err = output(result); err != nil {
				return err
			}
		}
		if now := hrclock.Now(); !now.Before(nextTick) {
			result, err := receiver.Tick(now)
			if err != nil {
				return err
			}
			if err = output(result); err != nil {
				return err
			}
			nextTick = now.Add(2 * time.Millisecond)
			if sender != nil {
				if err := sender.Maintenance(hrclock.Now(), writer); err != nil {
					return err
				}
			}
		}
		if outbound != nil && outbound.Stats().QueuedPackets > 0 {
			nextBulk, err = outbound.Pump(hrclock.Now(), writer)
			if err != nil {
				return err
			}
		}
	}
	report := map[string]any{"receiver": receiver.Stats(), "reorder": receiver.ReorderStats(), "payload_seconds": lastPayload.Sub(firstPayload).Seconds()}
	if sender != nil {
		report["sender"] = sender.Stats()
		report["paths"] = sender.Paths(hrclock.Now())
		report["transmit_queue"] = outbound.Stats()
	}
	return encoder.Encode(report)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
