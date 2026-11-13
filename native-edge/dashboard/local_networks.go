package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"

	"gamebond.local/nativeedge/lan"
)

// localNetworks exposes the client's isolated LAN router configuration. The
// same parser used by the daemon validates edits before the config is replaced.
func (s *Server) localNetworks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		reply(w, 405, map[string]any{"error": "GET or PUT only"})
		return
	}
	discover := s.o.Adapters
	if discover == nil {
		discover = discoverAdapters
	}
	adapters, err := discover()
	if err != nil {
		reply(w, 503, map[string]any{"error": err.Error()})
		return
	}
	s.configSectionWithConfig(w, r, func(cfg map[string]any) map[string]any {
		return map[string]any{"adapters": adapters, "local_networks": cfg["local_networks"], "static_routes": cfg["static_routes"], "status": localNetworkSnapshot(s.o.Snapshot)}
	}, func(cfg map[string]any, raw []byte) (map[string]any, error) {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			return nil, errors.New("local network settings must be an object")
		}
		for key := range fields {
			if key != "local_networks" && key != "static_routes" {
				return nil, errors.New("unknown local network settings field: " + key)
			}
		}
		var request struct {
			Networks json.RawMessage `json:"local_networks"`
			Routes   json.RawMessage `json:"static_routes"`
		}
		if err := json.Unmarshal(raw, &request); err != nil || len(request.Networks) == 0 || len(request.Routes) == 0 {
			return nil, errors.New("local_networks and static_routes are required")
		}
		uplinkIDs, uplinkIndices := stringValues(cfg["interface_ids"]), intValues(cfg["interface_indices"])
		var legacy []struct {
			ID          string `json:"interface_id"`
			Name        string `json:"interface_name"`
			Index       int    `json:"interface_index"`
			RedundantID string `json:"redundant_interface_id"`
			Redundant   string `json:"redundant_interface_name"`
		}
		legacyRaw, _ := json.Marshal(cfg["lan_devices"])
		if len(legacyRaw) > 0 && string(legacyRaw) != "null" {
			if err := json.Unmarshal(legacyRaw, &legacy); err != nil {
				return nil, errors.New("existing LAN device configuration is invalid")
			}
		}
		var deviceIDs []string
		var deviceIndices []int
		for _, device := range legacy {
			if device.ID != "" {
				deviceIDs = append(deviceIDs, device.ID)
			}
			if device.Name != "" {
				deviceIDs = append(deviceIDs, "name:"+device.Name)
			}
			if device.RedundantID != "" {
				deviceIDs = append(deviceIDs, device.RedundantID)
			}
			if device.Redundant != "" {
				deviceIDs = append(deviceIDs, "name:"+device.Redundant)
			}
			if device.Index > 0 {
				deviceIndices = append(deviceIndices, device.Index)
			}
		}
		_, err := lan.LoadLocalConfig(request.Networks, request.Routes, uplinkIDs, deviceIDs, uplinkIndices, deviceIndices)
		if err != nil {
			return nil, err
		}
		return map[string]any{"local_networks": request.Networks, "static_routes": request.Routes}, nil
	})
}

func stringValues(value any) []string {
	var out []string
	_ = typedValue(value, &out)
	return out
}

func intValues(value any) []int {
	var out []int
	_ = typedValue(value, &out)
	return out
}

func localNetworkSnapshot(snapshot func() map[string]any) any {
	if snapshot == nil {
		return nil
	}
	return snapshot()["local_networks"]
}
