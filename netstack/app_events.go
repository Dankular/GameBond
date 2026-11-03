package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

type appIdentity struct {
	PID             uint32
	CreatedFiletime string
}

// Only our per-runtime authenticated capture engine can supply an identity.
// Unextended engines can still proxy, but do not produce attributed app events.
func authenticateCapture(conn net.Conn, methods []byte, restricted bool) (*appIdentity, error) {
	token := os.Getenv("GAMEBOND_CAPTURE_TOKEN")
	if restricted || token == "" {
		if !strings.ContainsRune(string(methods), 0) {
			conn.Write([]byte{5, 255})
			return nil, fmt.Errorf("SOCKS no-auth method required")
		}
		_, err := conn.Write([]byte{5, 0})
		return nil, err
	}
	if !strings.ContainsRune(string(methods), 2) {
		conn.Write([]byte{5, 255})
		return nil, fmt.Errorf("capture authentication required")
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return nil, err
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 1 || header[1] == 0 {
		return nil, fmt.Errorf("invalid SOCKS authentication")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return nil, err
	}
	length := make([]byte, 1)
	if _, err := io.ReadFull(conn, length); err != nil {
		return nil, err
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(password, []byte(token)) != 1 {
		conn.Write([]byte{1, 1})
		return nil, fmt.Errorf("capture authentication rejected")
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return nil, err
	}
	fields := strings.Split(string(username), "|")
	if len(fields) != 3 || fields[0] != "gamebond-owner-v1" {
		return nil, nil
	}
	pid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil || pid == 0 {
		return nil, nil
	}
	birth, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil || birth <= 116444736000000000 {
		return nil, nil
	}
	return &appIdentity{uint32(pid), strconv.FormatUint(birth, 10)}, nil
}

var emitAppActivity = func(identity *appIdentity, protocol, destination, proof string) {
	if identity == nil {
		return
	}
	packet, err := json.Marshal(map[string]any{"type": "app_activity", "pid": identity.PID, "created_filetime": identity.CreatedFiletime,
		"protocol": protocol, "destination": destination, "proof": proof})
	if err == nil {
		writeFrame(2, packet)
	}
}

var emitAppFlow = func(identity *appIdentity, protocol, source, destination, profile string) {
	if identity == nil {
		return
	}
	packet, err := json.Marshal(map[string]any{"type": "app_flow_profile", "pid": identity.PID, "created_filetime": identity.CreatedFiletime,
		"protocol": protocol, "source": source, "destination": destination, "profile": profile})
	if err == nil {
		writeFrame(2, packet)
	}
}
