package dashboard

import (
	"encoding/json"
	"errors"
	"gamebond.local/nativeedge/uplink"
	"net"
	"strings"
)

// Adapter is a read-only OS snapshot. Selection never alters system routes.
type Adapter = uplink.Adapter

func discoverAdapters() ([]Adapter, error) { return uplink.Adapters() }

func stableID(id string) bool {
	return len(id) == 38 && strings.HasPrefix(id, "{") && strings.HasSuffix(id, "}")
}

func selectAdapters(raw []byte, adapters []Adapter) (map[string]any, error) {
	var indices []int
	if err := json.Unmarshal(raw, &indices); err != nil || len(indices) < 1 || len(indices) > 8 {
		return nil, errors.New("choose 1 to 8 different adapters")
	}
	bind, ids, names, gateways := []any{}, []string{}, []string{}, []string{}
	seen, seenIDs, sources := map[int]bool{}, map[string]bool{}, map[string]bool{}
	allStable, needStable := true, false
	for _, index := range indices {
		if index <= 0 || index >= 1<<24 || seen[index] {
			return nil, errors.New("choose distinct positive interface indices")
		}
		seen[index] = true
		var row *Adapter
		for i := range adapters {
			if adapters[i].Index == index {
				row = &adapters[i]
				break
			}
		}
		if row == nil {
			return nil, errors.New("selected adapter disappeared; refresh the networks")
		}
		id := strings.ToLower(row.ID)
		if id != "" && seenIDs[id] {
			return nil, errors.New("choose different physical adapters")
		}
		seenIDs[id] = true
		allStable = allStable && stableID(id)
		address := "0.0.0.0"
		if row.Up && len(row.Addresses) > 0 && row.Gateway != "" {
			address = row.Addresses[0]
			ip, gw := net.ParseIP(address), net.ParseIP(row.Gateway)
			if ip == nil || ip.To4() == nil || ip.IsUnspecified() || gw == nil || gw.To4() == nil || gw.IsUnspecified() {
				return nil, errors.New("invalid discovered IPv4 address or gateway")
			}
			needStable = needStable || sources[address]
			sources[address] = true
		} else {
			needStable = true
		}
		bind = append(bind, []any{address, 0})
		ids = append(ids, row.ID)
		names = append(names, row.Name)
		gateways = append(gateways, row.Gateway)
	}
	if needStable && !allStable {
		return nil, errors.New("offline adapters or matching addresses require distinct stable Windows adapter identifiers")
	}
	return map[string]any{"bind": bind, "interface_indices": indices, "interface_ids": ids, "interface_names": names, "gateways": gateways}, nil
}
