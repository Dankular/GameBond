package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestApplicationAuthorizationMatchesBoundedRequestAndDefaultsInvalidProfileToDeny(t *testing.T) {
	t.Setenv("GAMEBOND_APP_AUTHORIZATION", "1")
	original := emitAuthorizationRequest
	defer func() { emitAuthorizationRequest = original }()
	requests := make(chan map[string]any, 1)
	emitAuthorizationRequest = func(request map[string]any) error { requests <- request; return nil }
	result := make(chan appAuthorization, 1)
	go func() { result <- authorizeApplication(&appIdentity{42, "134000000000000000"}, "tcp", "1.1.1.1:443") }()
	request := <-requests
	packet, _ := json.Marshal(map[string]any{"type": "app_authorization_response", "id": request["id"], "allow": true, "profile": "game"})
	handleAppAuthorizationFrame(packet)
	if decision := <-result; !decision.Allow || decision.Profile != "game" {
		t.Fatalf("decision=%v", decision)
	}
	appAuthorizationWaiters.Lock()
	pending := len(appAuthorizationWaiters.pending)
	appAuthorizationWaiters.Unlock()
	if pending != 0 {
		t.Fatal("authorization waiter leaked")
	}
	go func() { result <- authorizeApplication(nil, "udp", "1.1.1.1:443") }()
	request = <-requests
	packet, _ = json.Marshal(map[string]any{"type": "app_authorization_response", "id": request["id"], "allow": true, "profile": "execute-command"})
	handleAppAuthorizationFrame(packet)
	if decision := <-result; decision.Allow {
		t.Fatal("invalid fixed profile must fail closed")
	}
}

func TestApplicationAuthorizationTimesOutAndReleasesWaiter(t *testing.T) {
	t.Setenv("GAMEBOND_APP_AUTHORIZATION", "1")
	original := emitAuthorizationRequest
	defer func() { emitAuthorizationRequest = original }()
	emitAuthorizationRequest = func(request map[string]any) error { return nil }
	started := time.Now()
	decision := authorizeApplication(nil, "tcp", "1.1.1.1:443")
	if decision.Allow || time.Since(started) > 3*time.Second {
		t.Fatal("missing policy reply must fail closed within bounded time")
	}
	appAuthorizationWaiters.Lock()
	defer appAuthorizationWaiters.Unlock()
	if len(appAuthorizationWaiters.pending) != 0 {
		t.Fatal("timed-out waiter leaked")
	}
}
