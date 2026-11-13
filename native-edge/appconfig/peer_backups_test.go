package appconfig

import "testing"

func TestPeerBackupsValidation(t *testing.T) {
	const head = `{"role":"client","bind":[["192.168.1.93",0]],"interface_indices":[22],"peer":["203.0.113.7",4433],"session":"00112233445566778899aabbccddeeff","client_tunnel_ip":"10.77.0.2","redundant_mode":false,"bonding_mode":true`
	cases := []struct {
		name, extra string
		ok          bool
	}{
		{"absent", ``, true},
		{"one backup", `,"peer_backups":[["198.51.100.9",4433]]`, true},
		{"same address other port", `,"peer_backups":[["203.0.113.7",4434]]`, true},
		{"with failover time", `,"peer_backups":[["198.51.100.9",4433]],"exit_failover_ms":1500`, true},
		{"repeats the primary", `,"peer_backups":[["203.0.113.7",4433]]`, false},
		{"repeats itself", `,"peer_backups":[["198.51.100.9",4433],["198.51.100.9",4433]]`, false},
		{"four servers", `,"peer_backups":[["198.51.100.1",1],["198.51.100.2",1],["198.51.100.3",1],["198.51.100.4",1]]`, false},
		{"not a list", `,"peer_backups":"198.51.100.9"`, false},
		{"bad pair", `,"peer_backups":[["198.51.100.9"]]`, false},
		{"loopback", `,"peer_backups":[["127.0.0.1",4433]]`, false},
		{"unspecified", `,"peer_backups":[["0.0.0.0",4433]]`, false},
		{"port zero", `,"peer_backups":[["198.51.100.9",0]]`, false},
		{"failover too fast", `,"peer_backups":[["198.51.100.9",4433]],"exit_failover_ms":100`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load([]byte(head+c.extra+`}`), Options{Windows: true})
			if (err == nil) != c.ok {
				t.Fatalf("ok=%v, err=%v", c.ok, err)
			}
		})
	}
}
