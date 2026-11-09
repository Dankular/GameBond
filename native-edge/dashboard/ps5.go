package dashboard

import "strings"

// Hardware identity comes from the device and its USB parent, never an alias
// such as a user-renamed "UGREEN" network connection.
type USBNetworkDevice struct {
	ID           string `json:"id"`
	PNP          string `json:"pnp"`
	Description  string `json:"description"`
	Manufacturer string `json:"manufacturer"`
	Parent       string `json:"parent"`
}

type PS5AdapterMatch struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Confirmed bool   `json:"confirmed"`
}

func ps5Adapters(rows []Adapter, hardware []USBNetworkDevice, ids []string, indices []int) []PS5AdapterMatch {
	out := []PS5AdapterMatch{}
	for _, row := range rows {
		excluded := row.Gateway != "" || !stableID(row.ID)
		for _, id := range ids {
			excluded = excluded || strings.EqualFold(id, row.ID)
		}
		for _, index := range indices {
			excluded = excluded || index == row.Index
		}
		if excluded {
			continue
		}
		for _, device := range hardware {
			if !strings.EqualFold(device.ID, row.ID) || !strings.HasPrefix(strings.ToUpper(device.PNP), `USB\`) {
				continue
			}
			identity := strings.ToLower(device.Description + " " + device.Manufacturer + " " + device.Parent)
			out = append(out, PS5AdapterMatch{ID: row.ID, Name: row.Name, Confirmed: strings.Contains(identity, "ugreen")})
			break
		}
	}
	return out
}
