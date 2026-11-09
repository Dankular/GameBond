package edge

import (
	"encoding/json"
	"testing"
)

func configFixture() map[string]any {
	return map[string]any{"role": "server", "session": "000102030405060708090a0b0c0d0e0f", "bind": [][]any{{"0.0.0.0", 4433}}, "client_tunnel_ip": "10.77.0.2", "tun_name": "gamebond0", "mtu": 1280, "bonding_mode": true, "redundant_mode": false, "bulk_rate_mbps": 0}
}
func TestContainerConfigAndPartialQoSRetainDefaults(t *testing.T) {
	input := configFixture()
	input["adaptive_qos"] = map[string]any{"duplicate_mbps": 2}
	data, _ := json.Marshal(input)
	_, options, address, session, err := DecodeConfig(data)
	if err != nil || address.String() != "0.0.0.0:4433" || len(session) != 16 || options.QoS.DuplicateMbps != 2 || options.QoS.CallDeadlineMS != 60 || !options.QoS.Enabled {
		t.Fatal("configuration/defaults changed", err)
	}
	if _, _, _, _, err = DecodeConfig(append(data, []byte("garbage")...)); err == nil {
		t.Fatal("trailing garbage accepted")
	}
}
func TestUnsupportedOrUnsafeTopologyFailsBeforeOpeningDevices(t *testing.T) {
	for key, value := range map[string]any{"role": "client", "session": "bad", "bind": [][]any{{"0.0.0.0", 53}}, "client_tunnel_ip": "10.77.0.3", "tun_name": "eth0", "mtu": 1500, "bonding_mode": false, "bulk_rate_mbps": 1, "stream_relays": []any{}} {
		input := configFixture()
		input[key] = value
		data, _ := json.Marshal(input)
		if _, _, _, _, err := DecodeConfig(data); err == nil {
			t.Fatal("unsupported topology accepted", key)
		}
	}
}

func TestAdminBlockIsValidatedAtLoad(t *testing.T) {
	good := map[string]any{"enabled": true, "bind": []any{"127.0.0.1", 8443}, "password_hash": "scrypt$32768$c2FsdA==$ZGlnZXN0"}
	for name, c := range map[string]struct {
		admin any
		ok    bool
	}{"valid": {good, true}, "absent-ok": {nil, true}, "bad port": {map[string]any{"enabled": true, "bind": []any{"127.0.0.1", 0}, "password_hash": good["password_hash"]}, false},
		"bad hash": {map[string]any{"enabled": true, "bind": []any{"127.0.0.1", 8443}, "password_hash": "x"}, false}} {
		input := configFixture()
		if c.admin != nil {
			input["admin"] = c.admin
		}
		data, _ := json.Marshal(input)
		_, _, _, _, err := DecodeConfig(data)
		if (err == nil) != c.ok {
			t.Fatal(name, "ok =", c.ok, "err =", err)
		}
	}
}
