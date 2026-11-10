package dashboard

import (
	"strconv"
	"strings"
)

// WiFiInfo is one wireless adapter's link state as reported by netsh.
type WiFiInfo struct {
	Name      string  `json:"name"`
	SSID      string  `json:"ssid"`
	SignalPct int     `json:"signal_pct"`
	RSSIdBm   int     `json:"rssi_dbm"`
	RxMbps    float64 `json:"link_rx_mbps"`
	TxMbps    float64 `json:"link_tx_mbps"`
	Radio     string  `json:"radio"`
	Channel   string  `json:"channel"`
	Connected bool    `json:"connected"`
}

// ParseNetshWLAN parses `netsh wlan show interfaces` output. Field labels are
// matched on the English text; unknown locales simply yield no rows.
func ParseNetshWLAN(out string) []WiFiInfo {
	var rows []WiFiInfo
	var cur *WiFiInfo
	flush := func() {
		if cur != nil && cur.Name != "" {
			if cur.SignalPct > 0 {
				// Windows exposes quality %, which maps linearly to dBm in the
				// range -100 (0%) .. -50 (100%).
				cur.RSSIdBm = cur.SignalPct/2 - 100
			}
			rows = append(rows, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		i := strings.Index(line, " : ")
		if i < 0 {
			continue
		}
		key, val := strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+3:])
		switch key {
		case "Name":
			flush()
			cur = &WiFiInfo{Name: val}
		case "State":
			if cur != nil {
				cur.Connected = strings.EqualFold(val, "connected")
			}
		case "SSID":
			if cur != nil {
				cur.SSID = val
			}
		case "Signal":
			if cur != nil {
				cur.SignalPct, _ = strconv.Atoi(strings.TrimSuffix(val, "%"))
			}
		case "Radio type":
			if cur != nil {
				cur.Radio = val
			}
		case "Channel":
			if cur != nil {
				cur.Channel = val
			}
		case "Receive rate (Mbps)":
			if cur != nil {
				cur.RxMbps, _ = strconv.ParseFloat(val, 64)
			}
		case "Transmit rate (Mbps)":
			if cur != nil {
				cur.TxMbps, _ = strconv.ParseFloat(val, 64)
			}
		}
	}
	flush()
	return rows
}
