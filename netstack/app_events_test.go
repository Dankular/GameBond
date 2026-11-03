package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func authenticateForTest(t *testing.T, token, password, username string) (*appIdentity, error) {
	t.Helper()
	t.Setenv("GAMEBOND_CAPTURE_TOKEN", token)
	host, proxy := net.Pipe()
	defer host.Close()
	defer proxy.Close()
	host.SetDeadline(time.Now().Add(time.Second))
	proxy.SetDeadline(time.Now().Add(time.Second))
	type result struct {
		identity *appIdentity
		err      error
	}
	done := make(chan result, 1)
	go func() { identity, err := authenticateCapture(proxy, []byte{2}, false); done <- result{identity, err} }()
	selected := make([]byte, 2)
	if _, err := io.ReadFull(host, selected); err != nil {
		t.Fatal(err)
	}
	if selected[1] != 2 {
		t.Fatal("username auth not selected")
	}
	request := append([]byte{1, byte(len(username))}, []byte(username)...)
	request = append(request, byte(len(password)))
	request = append(request, []byte(password)...)
	if _, err := host.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(host, reply); err != nil {
		t.Fatal(err)
	}
	output := <-done
	return output.identity, output.err
}

func TestCaptureAuthenticationRequiresRuntimeTokenAndPreservesBirthTime(t *testing.T) {
	identity, err := authenticateForTest(t, "private-runtime-token", "private-runtime-token", "gamebond-owner-v1|42|134000000000000000")
	if err != nil || identity == nil || identity.PID != 42 || identity.CreatedFiletime != "134000000000000000" {
		t.Fatalf("identity=%v err=%v", identity, err)
	}
	identity, err = authenticateForTest(t, "private-runtime-token", "wrong", "gamebond-owner-v1|42|134000000000000000")
	if err == nil || identity != nil {
		t.Fatal("invalid capture password was accepted")
	}
	identity, err = authenticateForTest(t, "private-runtime-token", "private-runtime-token", "gamebond-owner-v1|0|0")
	if err != nil || identity != nil {
		t.Fatal("unknown native process must remain unattributed")
	}
}
