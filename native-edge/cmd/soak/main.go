// Command soak runs the GameBond client for hours against real servers over emulated links, injects
// faults (pull a link, throttle, burst loss, latency, total outage, loss of an exit server) and
// reports the loss and failover times it measured.
//
// The links are emulated on loopback: each uplink binds its own 127.0.0.N address and talks to a local
// proxy, which forwards over a UDP socket of its own to the real server and impairs each direction.
// Nothing here touches the PC's real adapters or the live tunnel. Traffic is ICMP echo through the
// tunnel to the server's tunnel address, so a probe that does not come back was lost on the real
// path: client, emulated link, internet, server TUN and back.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/slo"
	"gamebond.local/nativeedge/store"
	"gamebond.local/nativeedge/uplink"
)

var (
	serverFlag  = flag.String("server", "195.154.119.136:4447", "primary exit server host:port")
	backupFlag  = flag.String("backup", "195.154.119.136:4448", "backup exit server host:port (empty: no exit faults)")
	keyFlag     = flag.String("key", ".runtime/soak/soak.key", "32-byte key file")
	sessionFlag = flag.String("session", "", "session id, 32 hex characters")
	durFlag     = flag.Duration("duration", 24*time.Hour, "how long to run")
	outFlag     = flag.String("out", "", "output directory (default .runtime/soak/run-<time>)")
	linksFlag   = flag.Int("links", 2, "emulated links")
	quickFlag   = flag.Bool("quick", false, "short faults and gaps, for a smoke test")
	onlyFlag    = flag.String("only", "", "comma-separated fault classes to run (default: all)")
	seedFlag    = flag.Int64("seed", 1, "random seed")
	afterFlag   = flag.Duration("exit-failover", 700*time.Millisecond, "client exit_failover_ms")
	gameEvery   = flag.Duration("game-every", 20*time.Millisecond, "game probe interval (100 B, priority, duplicated)")
	bulkEvery   = flag.Duration("bulk-every", 50*time.Millisecond, "bulk probe interval (1200 B, best effort)")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "soak:", err)
		os.Exit(1)
	}
}

func run() error {
	key, err := os.ReadFile(*keyFlag)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("key file: need 32 bytes (%v)", err)
	}
	session, err := hex.DecodeString(*sessionFlag)
	if err != nil || len(session) != 16 {
		return fmt.Errorf("session: need 32 hex characters")
	}
	out := *outFlag
	if out == "" {
		out = filepath.Join(".runtime", "soak", "run-"+time.Now().Format("20060102-150405"))
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	started := time.Now()
	ctx, cancel := context.WithDeadline(ctx, started.Add(*durFlag))
	defer cancel()

	servers := []string{*serverFlag}
	if *backupFlag != "" {
		servers = append(servers, *backupFlag)
	}
	net, err := newEmuNet(*linksFlag, servers, *seedFlag, ctx.Done())
	if err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(out, "slo.db"), []string{slo.Schema})
	if err != nil {
		return err
	}
	defer db.Close()
	tracker := slo.NewTracker(db)
	st := newStats(*gameEvery)
	src, dst := netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.1")
	game := slo.NewProber(slo.ProbeConfig{Src: src, Dst: dst, ID: 0x7a01, Size: 100, Timeout: time.Second}, stream{s: st, name: "game", also: tracker, track: true})
	bulk := slo.NewProber(slo.ProbeConfig{Src: src, Dst: dst, ID: 0x7a02, Size: 1200, Timeout: time.Second}, stream{s: st, name: "bulk"})

	specs := make([]uplink.Spec, *linksFlag)
	for i := range specs {
		specs[i] = uplink.Spec{Addr: linkIP(i)}
	}
	qos := bond.DefaultQoSSettings()
	cfg := client.Config{Key: key, Session: session, Server: net.addr(0), FailoverAfter: *afterFlag, Uplinks: specs,
		Failover: true, FlowPinning: true, CoDel: true, LossTracking: true, DelayControl: true, InitialMbps: 10, MaxMbps: 300,
		MTU: 1280 + bond.Overhead + 24, QoS: &qos,
		Deliver: func(p []byte) {
			now := time.Now()
			if !game.Handle(p, now) {
				bulk.Handle(p, now)
			}
		}}
	if len(servers) > 1 {
		cfg.Backups = []netip.AddrPort{net.addr(1)}
	}
	var evMu sync.Mutex
	evFile, err := os.OpenFile(filepath.Join(out, "events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer evFile.Close()
	logEv := func(m map[string]any) {
		m["at"] = time.Now().Format(time.RFC3339Nano)
		b, _ := json.Marshal(m)
		evMu.Lock()
		evFile.Write(append(b, '\n'))
		evMu.Unlock()
		fmt.Println(string(b))
	}
	cfg.OnSwitch = func(from, to netip.AddrPort, reason string) {
		logEv(map[string]any{"event": "exit-switch", "from": from.String(), "to": to.String(), "reason": reason})
		tracker.Event(time.Now(), "exit-switch", reason, 0)
	}
	c, err := client.New(cfg)
	if err != nil {
		return err
	}
	go c.Run(ctx)

	// probe senders
	send := func(p *slo.Prober, every time.Duration, prio, repl bool, flow string) {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				c.Submit(bond.QueuedPacket{Payload: p.Build(now), Flow: flow, Priority: prio, Replicate: repl, Expires: now.Add(time.Second)})
			}
		}
	}
	go send(game, *gameEvery, true, true, "soak-game")
	go send(bulk, *bulkEvery, false, false, "soak-bulk")
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				game.Expire(now)
				bulk.Expire(now)
				_ = tracker.Flush(now, 3*time.Second)
			}
		}
	}()

	rep := &reporter{out: out, started: started, st: st, db: db, c: c, links: *linksFlag, servers: servers, seed: *seedFlag, planned: *durFlag}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rep.write(false)
			}
		}
	}()
	logEv(map[string]any{"event": "start", "servers": servers, "links": *linksFlag, "duration": durFlag.String(), "quick": *quickFlag, "out": out})

	// let the session come up and the standby warm before the first fault
	waitUp := time.Now().Add(60 * time.Second)
	for c.Snapshot().Ready < *linksFlag && time.Now().Before(waitUp) {
		time.Sleep(200 * time.Millisecond)
	}
	if c.Snapshot().Ready == 0 {
		return fmt.Errorf("the client never became ready against %s: is the soak server up and the session right?", *serverFlag)
	}
	time.Sleep(10 * time.Second)

	sched := &scheduler{ctx: ctx, net: net, c: c, st: st, links: *linksFlag, backup: len(servers) > 1, quick: *quickFlag, only: *onlyFlag, rng: rand.New(rand.NewSource(*seedFlag)), log: logEv}
	sched.run()
	cancel()
	time.Sleep(2 * time.Second)
	_ = tracker.Flush(time.Now().Add(time.Hour), 0)
	rep.write(true)
	logEv(map[string]any{"event": "done"})
	return nil
}
