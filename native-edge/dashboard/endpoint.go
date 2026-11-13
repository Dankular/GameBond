package dashboard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"gamebond.local/nativeedge/endpointwatch"
)

// This PC: process-level alerts from SentinelWire. The dashboard only reads the alert files the two programs write
// (see package endpointwatch) and keeps its own small setting, "endpoint_watch", in the client config. Nothing
// here starts, stops or changes SentinelWire.

const endpointPollEvery = time.Second

type endpointState struct {
	mu     sync.Mutex
	w      *endpointwatch.Watcher
	cfg    endpointwatch.Config
	polled time.Time
}

func (s *Server) endpointConfig() (endpointwatch.Config, error) {
	cfg, err := readConfig(s.o.ConfigPath)
	if err != nil {
		return endpointwatch.Config{}, err
	}
	var c endpointwatch.Config
	if cfg["endpoint_watch"] != nil {
		if err := typedValue(cfg["endpoint_watch"], &c); err != nil {
			return endpointwatch.Config{}, err
		}
	}
	return c, nil
}

// endpointAPI: GET returns the setting and the current alerts; POST saves the setting.
func (s *Server) endpointAPI(w http.ResponseWriter, r *http.Request) {
	st := &s.endpoint
	st.mu.Lock()
	defer st.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		c, err := s.endpointConfig()
		if err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		if st.w == nil {
			st.w, st.cfg = endpointwatch.New(c), c
		} else if st.cfg != c {
			st.w.SetConfig(c)
			st.cfg, st.polled = c, time.Time{}
		}
		if time.Since(st.polled) >= endpointPollEvery {
			st.w.Poll()
			st.polled = time.Now()
		}
		reply(w, 200, map[string]any{"config": c, "snapshot": st.w.Snapshot()})
	case http.MethodPost:
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		var c endpointwatch.Config
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			reply(w, 400, map[string]any{"error": "invalid request"})
			return
		}
		if err := c.Validate(); err != nil {
			reply(w, 422, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		s.mu.Lock()
		cfg, err := readConfig(s.o.ConfigPath)
		if err == nil {
			cfg["endpoint_watch"] = c
			err = writeConfig(s.o.ConfigPath, cfg)
		}
		s.mu.Unlock()
		if err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		st.polled = time.Time{}
		reply(w, 200, map[string]any{"ok": true})
	default:
		reply(w, 405, map[string]any{"error": "GET or POST only"})
	}
}
