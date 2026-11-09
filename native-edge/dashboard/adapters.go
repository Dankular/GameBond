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

// Keep unplugged selected adapters in the editor. Their stable identities let
// the daemon park them safely instead of substituting a different adapter.
func withSavedAdapters(cfg map[string]any, rows []Adapter) []Adapter {
	out := append([]Adapter(nil), rows...)
	var ids, names []string
	var indices []int
	_ = typedValue(cfg["interface_ids"], &ids)
	_ = typedValue(cfg["interface_names"], &names)
	_ = typedValue(cfg["interface_indices"], &indices)
	for i, id := range ids {
		if !stableID(id) || i >= len(indices) {
			continue
		}
		found := false
		for _, row := range out {
			if strings.EqualFold(row.ID, id) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		name := "Saved adapter"
		if i < len(names) && names[i] != "" {
			name = names[i]
		}
		out = append(out, Adapter{Index: indices[i], ID: id, Name: name, Addresses: []string{}})
	}
	return out
}

func selectAdapters(raw []byte, adapters []Adapter) (map[string]any, error) {
	var requested []json.RawMessage
	if err := json.Unmarshal(raw, &requested); err != nil || len(requested) < 1 || len(requested) > 8 {
		return nil, errors.New("choose 1 to 8 different adapters")
	}
	bind, ids, names, gateways := []any{}, []string{}, []string{}, []string{}
	indices := []int{}
	seen, seenIDs, sources := map[int]bool{}, map[string]bool{}, map[string]bool{}
	allStable, needStable := true, false
	for _, selection := range requested {
		var index int
		identity := ""
		if json.Unmarshal(selection, &index) != nil {
			var object map[string]json.RawMessage
			if json.Unmarshal(selection, &object) != nil || object == nil {
				return nil, errors.New("invalid adapter selection")
			}
			for key := range object {
				if key != "id" && key != "index" {
					return nil, errors.New("unknown adapter selection field")
				}
			}
			if json.Unmarshal(object["index"], &index) != nil || json.Unmarshal(object["id"], &identity) != nil || !stableID(identity) {
				return nil, errors.New("invalid stable adapter selection")
			}
		}
		if index <= 0 || index >= 1<<24 {
			return nil, errors.New("invalid interface index")
		}
		var row *Adapter
		matches := 0
		for i := range adapters {
			if (identity != "" && strings.EqualFold(adapters[i].ID, identity)) || (identity == "" && adapters[i].Index == index) {
				row = &adapters[i]
				matches++
			}
		}
		if row == nil || matches != 1 {
			return nil, errors.New("selected adapter disappeared; refresh the networks")
		}
		index = row.Index
		if index <= 0 || index >= 1<<24 || seen[index] {
			return nil, errors.New("choose distinct positive interface indices; remove an offline selection if its index was reused")
		}
		seen[index] = true
		indices = append(indices, index)
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
