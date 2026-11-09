package main

import (
	"encoding/json"
	"fmt"

	"gamebond.local/nativeedge/appauth"
	"gamebond.local/nativeedge/appevents"
)

// appCapture is the daemon side of application attribution: authorization
// requests from the netstack, first-use events and per-app traffic.
//
// It is only active when the netstack runs with the owner-attribution
// capture extension (`-app-capture`); Go does not stage or verify that
// extension yet, so the flag is an assertion by whoever launched the process.
// Without it every request is denied to the bulk profile, as Python does when
// its manifest check fails.
type appCapture struct {
	enabled    bool
	auth       *appauth.Authorizer
	events     *appevents.Store
	historyErr string
}

func newAppCapture(enabled bool, configPath, historyPath string, rawConfig []byte, respond func(map[string]any) error) (*appCapture, error) {
	var config any
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, err
	}
	c := &appCapture{enabled: enabled}
	if historyPath != "" {
		store, err := appevents.New(historyPath, appevents.Options{Resolver: appauth.ResolveProcess})
		if err != nil {
			c.historyErr = err.Error() // Python keeps running without history
		} else {
			c.events = store
		}
	}
	a := &appauth.Authorizer{Enabled: enabled, ConfigPath: configPath, Resolve: appauth.ResolveProcess, Respond: respond}
	if c.events != nil {
		a.Events = c.events
	}
	if err := a.Init(config); err != nil {
		return nil, fmt.Errorf("application policy: %w", err)
	}
	c.auth = a
	return c, nil
}

// onEvent handles one stack control record and reports whether it was one of
// ours.
func (c *appCapture) onEvent(m map[string]any) bool {
	switch m["type"] {
	case "app_authorization_request":
		c.auth.Handle(m)
	case "app_activity":
		if c.enabled && c.events != nil {
			c.events.Observe(m)
		}
	case "app_metrics":
		if c.enabled && c.events != nil {
			c.events.RecordUsage(m)
		}
	default:
		return false
	}
	return true
}

func (c *appCapture) flush() error {
	if c == nil || c.events == nil {
		return nil
	}
	return c.events.Flush()
}

func (c *appCapture) close() {
	if c != nil {
		c.auth.Close()
	}
}

// status adds the application sections of the Python status document.
func (c *appCapture) status(doc map[string]any) {
	var source any
	if c.enabled {
		source = "native_capture_owner_and_tunnel_success"
	}
	var histErr any
	if c.historyErr != "" {
		histErr = c.historyErr
	}
	doc["app_attribution"] = map[string]any{"available": c.enabled, "history_error": histErr, "source": source}
	doc["app_authorization"] = c.auth.Snapshot()
	doc["application_policy"] = c.auth.PolicyState()
	if c.events == nil {
		doc["app_events"], doc["applications"], doc["application_traffic"] = nil, []any{}, nil
		return
	}
	doc["app_events"] = c.events.Snapshot(0, 32)
	traffic := c.events.TrafficSnapshot(128)
	rest := map[string]any{}
	for k, v := range traffic {
		if k != "rows" {
			rest[k] = v
		}
	}
	doc["applications"], doc["application_traffic"] = traffic["rows"], rest
}
