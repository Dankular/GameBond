package desktopruntime

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"gamebond.local/nativeedge/atomicio"
	"gamebond.local/nativeedge/ttyrelay"
)

type Manager struct {
	Plan         Plan
	ProfileError error
	mu           sync.Mutex
	// Spawn is injectable for integration tests; production launches only the
	// workspace's Go client with a fixed argument list, never a shell.
	Spawn func(Plan) (int, error)
}

func hasOwner(msg map[string]any) bool {
	pid, _ := msg["owner_pid"].(float64)
	state, _ := msg["state"].(string)
	return msg["ok"] == true && pid > 0 && state != "" && state != "unavailable"
}

// A failed IPC call is not proof of a stopped VPN. Check the known executable
// identity too; a stale PID reused by an unrelated process is not an owner.
func (m *Manager) ownerAbsent() bool {
	rec, err := ttyrelay.ReadMetadata(m.Plan.Metadata)
	if err == nil {
		if rec.PID <= 0 || clientProcessAlive(rec.PID, m.Plan.Client) {
			return false
		}
	} else if !os.IsNotExist(err) {
		return false
	}
	var status struct {
		PID     int     `json:"pid"`
		State   string  `json:"state"`
		Updated float64 `json:"updated_at"`
	}
	if atomicio.ReadJSONShared(m.Plan.Status, 4<<20, &status) == nil && status.State == "running" && float64(time.Now().UnixNano())/1e9-status.Updated < 15 && clientProcessAlive(status.PID, m.Plan.Client) {
		return false
	}
	return true
}

func (m *Manager) owner() (map[string]any, error) {
	return ttyrelay.Control(m.Plan.Metadata, "status", 2*time.Second, io.Discard)
}

func (m *Manager) profileMatch() error {
	rec, err := ttyrelay.ReadMetadata(m.Plan.Metadata)
	if err != nil {
		return err
	}
	a, b := Resolve(m.Plan.Root, rec.ConfigPath), Resolve(m.Plan.Root, m.Plan.Config)
	match := a == b
	if runtime.GOOS == "windows" {
		match = strings.EqualFold(a, b)
	}
	if rec.ConfigPath != "" && m.Plan.Config != "" && !match {
		return errors.New("the supervisor is using a different client config; reopen the widget with its config")
	}
	return nil
}

// Status is passive. A configured desktop can offer Connect when no relay
// exists, without confusing absence with a connected or failed tunnel.
func (m *Manager) Status() (map[string]any, error) {
	msg, err := m.owner()
	if err == nil && hasOwner(msg) {
		if err := m.profileMatch(); err != nil {
			return nil, err
		}
		return msg, nil
	}
	if err == nil {
		return nil, errors.New("the log relay has no registered supervisor")
	}
	if !m.ownerAbsent() {
		return nil, errors.New("the supervisor process is present but its control connection is unavailable")
	}
	if m.ProfileError != nil {
		return nil, fmt.Errorf("no supervisor; desktop launch profile: %w", m.ProfileError)
	}
	if err := m.Plan.Validate(); err != nil {
		return nil, err
	}
	return map[string]any{"state": "stopped", "supervisor_available": false}, nil
}

func (m *Manager) Control(command string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if command != "stop" && command != "restart" {
		return nil, errors.New("choose stop or restart")
	}
	if command == "stop" {
		if _, err := m.owner(); err != nil {
			if !m.ownerAbsent() {
				return nil, errors.New("could not contact the existing supervisor; stop was not confirmed")
			}
			return map[string]any{"state": "stopped", "ok": true}, nil
		}
	}
	if _, err := m.ensureOwner(); err != nil {
		return nil, err
	}
	result, err := ttyrelay.Control(m.Plan.Metadata, command, 60*time.Second, io.Discard)
	if err != nil {
		return result, err
	}
	if result["ok"] != true {
		message, _ := result["error"].(string)
		if message == "" {
			message = "VPN control operation failed"
		}
		return result, errors.New(message)
	}
	return result, nil
}

// Ensure starts only a stopped supervisor. It never sends restart.
func (m *Manager) Ensure() (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureOwner()
}

func (m *Manager) ensureOwner() (map[string]any, error) {
	msg, err := m.owner()
	if err == nil {
		if !hasOwner(msg) {
			return nil, errors.New("the log relay has no registered supervisor; refusing to replace a live relay")
		}
		if err := m.profileMatch(); err != nil {
			return nil, err
		}
		return msg, nil
	}
	if !m.ownerAbsent() {
		return nil, errors.New("the supervisor process is present but unreachable; refusing to launch a duplicate")
	}
	if m.ProfileError != nil {
		return nil, fmt.Errorf("desktop launch profile: %w", m.ProfileError)
	}
	if err := m.Plan.Validate(); err != nil {
		return nil, err
	}
	spawn := m.Spawn
	if spawn == nil {
		spawn = spawnSupervisor
	}
	pid, err := spawn(m.Plan)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rec, readErr := ttyrelay.ReadMetadata(m.Plan.Metadata)
		if readErr == nil && rec.PID == pid {
			if state, e := m.owner(); e == nil && hasOwner(state) && state["owner_pid"] == float64(pid) && state["state"] == "stopped" {
				if err := m.profileMatch(); err != nil {
					return nil, err
				}
				return state, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, errors.New("supervisor startup timed out; inspect .runtime/supervisor.log")
}
