package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

type appAuthorization struct {
	Allow   bool   `json:"allow"`
	Profile string `json:"profile"`
}

var appAuthorizationWaiters = struct {
	sync.Mutex
	pending map[string]chan appAuthorization
}{pending: make(map[string]chan appAuthorization)}

var emitAuthorizationRequest = func(request map[string]any) error {
	packet, err := json.Marshal(request)
	if err != nil {
		return err
	}
	return writeFrame(2, packet)
}

func authorizeApplication(identity *appIdentity, protocol, destination string) appAuthorization {
	if os.Getenv("GAMEBOND_APP_AUTHORIZATION") != "1" {
		return appAuthorization{true, "bulk"}
	}
	denied := appAuthorization{false, "bulk"}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return denied
	}
	id := hex.EncodeToString(nonce)
	reply := make(chan appAuthorization, 1)
	appAuthorizationWaiters.Lock()
	if len(appAuthorizationWaiters.pending) >= 128 {
		appAuthorizationWaiters.Unlock()
		return denied
	}
	appAuthorizationWaiters.pending[id] = reply
	appAuthorizationWaiters.Unlock()
	defer func() {
		appAuthorizationWaiters.Lock()
		delete(appAuthorizationWaiters.pending, id)
		appAuthorizationWaiters.Unlock()
	}()
	request := map[string]any{"type": "app_authorization_request", "id": id, "protocol": protocol, "destination": destination, "pid": uint32(0), "created_filetime": "0"}
	if identity != nil {
		request["pid"] = identity.PID
		request["created_filetime"] = identity.CreatedFiletime
	}
	if emitAuthorizationRequest(request) != nil {
		return denied
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case result := <-reply:
		return result
	case <-timer.C:
		return denied
	}
}

func handleAppAuthorizationFrame(packet []byte) {
	var response struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		Allow   bool   `json:"allow"`
		Profile string `json:"profile"`
	}
	if json.Unmarshal(packet, &response) != nil || response.Type != "app_authorization_response" || len(response.ID) != 24 {
		return
	}
	switch response.Profile {
	case "automatic", "bulk", "game", "call", "stream":
	default:
		response.Allow = false
		response.Profile = "bulk"
	}
	appAuthorizationWaiters.Lock()
	reply := appAuthorizationWaiters.pending[response.ID]
	appAuthorizationWaiters.Unlock()
	if reply != nil {
		select {
		case reply <- appAuthorization{response.Allow, response.Profile}:
		default:
		}
	}
}
