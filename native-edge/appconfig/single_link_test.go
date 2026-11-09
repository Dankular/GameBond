package appconfig

import "testing"

func TestSingleLinkVPNConfiguration(t *testing.T) {
	for _, windows := range []bool{false, true} {
		for _, bonding := range []string{"false", "true"} {
			_, err := Load([]byte(`{"role":"client","bind":[["192.168.1.93",0]],"interface_indices":[22],"peer":["203.0.113.7",4433],"session":"00112233445566778899aabbccddeeff","client_tunnel_ip":"10.77.0.2","redundant_mode":false,"bonding_mode":`+bonding+`}`), Options{Windows: windows})
			if err != nil {
				t.Fatalf("single link windows=%v bonding=%s: %v", windows, bonding, err)
			}
		}
	}
}
