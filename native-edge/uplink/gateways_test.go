package uplink

import "testing"

func TestChooseLowestMetricGatewayPerAdapter(t *testing.T) {
	routes := []defaultRoute{{22, "192.168.1.254", 100}, {22, "192.168.1.1", 5}, {30, "192.168.5.1", 50}, {22, "192.168.1.2", 5}, {22, "0.0.0.0", 0}, {22, "::1", 0}, {22, "127.0.0.1", 0}, {22, "bad", 0}}
	for _, rows := range [][]defaultRoute{routes, reverseRoutes(routes)} {
		got := chooseDefaultGateways(rows)
		if len(got) != 2 || got[22].Gateway != "192.168.1.1" || got[22].Metric != 5 || got[30].Gateway != "192.168.5.1" {
			t.Fatal(got)
		}
	}
}

func reverseRoutes(rows []defaultRoute) []defaultRoute {
	out := append([]defaultRoute{}, rows...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
