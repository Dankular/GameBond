package main

import (
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestSOCKSVerifiedIdentityIsDeniedBeforeDialAndAnnouncedOnlyAfterSuccess(t *testing.T) {
	t.Setenv("GAMEBOND_CAPTURE_TOKEN", "test-token")
	t.Setenv("GAMEBOND_APP_AUTHORIZATION", "1")
	a, client, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, server, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	pump := func(from, to tun.Device) {
		buffer := make([]byte, 65535)
		sizes := make([]int, 1)
		for {
			n, err := from.Read([][]byte{buffer}, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				if _, err = to.Write([][]byte{buffer[:sizes[0]]}, 0); err != nil {
					return
				}
			}
		}
	}
	go pump(a, b)
	go pump(b, a)
	listener, err := server.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:8080"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 2)
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	activity := make(chan string, 2)
	profiles := make(chan string, 2)
	oldActivity, oldFlow, oldAuthorize := emitAppActivity, emitAppFlow, emitAuthorizationRequest
	defer func() { emitAppActivity = oldActivity; emitAppFlow = oldFlow; emitAuthorizationRequest = oldAuthorize }()
	emitAppActivity = func(identity *appIdentity, protocol, target, proof string) {
		if identity == nil || identity.PID != 42 {
			t.Error("native owner identity lost")
		}
		activity <- proof
	}
	emitAppFlow = func(identity *appIdentity, protocol, source, target, profile string) { profiles <- profile }
	for _, allow := range []bool{false, true} {
		emitAuthorizationRequest = func(request map[string]any) error {
			if request["pid"] != uint32(42) {
				t.Error("authorization lost owner PID")
			}
			response, _ := json.Marshal(map[string]any{"type": "app_authorization_response", "id": request["id"], "allow": allow, "profile": "call"})
			handleAppAuthorizationFrame(response)
			return nil
		}
		host, proxy := net.Pipe()
		host.SetDeadline(time.Now().Add(2 * time.Second))
		done := make(chan error, 1)
		go func() { defer proxy.Close(); done <- serveSOCKS(proxy, client, false) }()
		host.Write([]byte{5, 1, 2})
		reply := make([]byte, 2)
		if _, err = io.ReadFull(host, reply); err != nil || reply[1] != 2 {
			t.Fatal("capture auth missing")
		}
		username := "gamebond-owner-v1|42|134000000000000000"
		auth := append([]byte{1, byte(len(username))}, []byte(username)...)
		auth = append(auth, 10)
		auth = append(auth, []byte("test-token")...)
		host.Write(auth)
		if _, err = io.ReadFull(host, reply); err != nil || reply[1] != 0 {
			t.Fatal("capture auth failed")
		}
		host.Write([]byte{5, 1, 0, 1, 10, 77, 0, 1, 0x1f, 0x90})
		response := make([]byte, 10)
		if _, err = io.ReadFull(host, response); err != nil {
			t.Fatal(err)
		}
		if !allow {
			if response[1] != 2 {
				t.Fatal("application block did not reject SOCKS CONNECT")
			}
			select {
			case <-accepted:
				t.Fatal("denied app reached the remote listener")
			default:
			}
			select {
			case <-activity:
				t.Fatal("denied app generated a tunnel-use toast")
			default:
			}
		} else {
			if response[1] != 0 {
				t.Fatal("allowed app did not connect")
			}
			select {
			case <-accepted:
			case <-time.After(time.Second):
				t.Fatal("allowed app did not reach server")
			}
			select {
			case proof := <-activity:
				if proof != "tcp_connect" {
					t.Fatal("wrong usage proof")
				}
			case <-time.After(time.Second):
				t.Fatal("successful app was not announced")
			}
			select {
			case profile := <-profiles:
				if profile != "call" {
					t.Fatal("profile was lost")
				}
			case <-time.After(time.Second):
				t.Fatal("flow profile was not propagated")
			}
			payload := []byte("owned application payload")
			host.Write(payload)
			echo := make([]byte, len(payload))
			if _, err = io.ReadFull(host, echo); err != nil {
				t.Fatal(err)
			}
		}
		host.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("SOCKS handler did not close")
		}
	}
}
