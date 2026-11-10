package dashboard

import "testing"

func TestParseNetshWLAN(t *testing.T) {
	out := "\r\nThere is 1 interface on the system:\r\n\r\n    Name                   : Wi-Fi\r\n    State                  : connected\r\n    SSID                   : Phone\r\n    Radio type             : 802.11ac\r\n    Channel                : 36\r\n    Receive rate (Mbps)    : 433.3\r\n    Transmit rate (Mbps)   : 351\r\n    Signal                 : 80%\r\n"
	r := ParseNetshWLAN(out)
	if len(r) != 1 || !r[0].Connected || r[0].SignalPct != 80 || r[0].RSSIdBm != -60 || r[0].RxMbps != 433.3 || r[0].SSID != "Phone" {
		t.Fatalf("%+v", r)
	}
}
