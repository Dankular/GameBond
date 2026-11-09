package edge

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"

	"gamebond.local/nativeedge/adminportal"
	"gamebond.local/nativeedge/bond"
)

type Config struct {
	Role           string                      `json:"role"`
	Session        string                      `json:"session"`
	Bind           [][]json.RawMessage         `json:"bind"`
	ClientIP       string                      `json:"client_tunnel_ip"`
	TunName        string                      `json:"tun_name"`
	MTU            int                         `json:"mtu"`
	Bonding        bool                        `json:"bonding_mode"`
	Redundant      bool                        `json:"redundant_mode"`
	DirectPriority bool                        `json:"direct_priority"`
	BulkRate       float64                     `json:"bulk_rate_mbps"`
	InitialRate    float64                     `json:"bonding_initial_rate_mbps"`
	MaximumRate    float64                     `json:"bonding_max_rate_mbps"`
	ReorderMS      float64                     `json:"reorder_timeout_ms"`
	GamePorts      []uint16                    `json:"game_udp_ports"`
	Queues         map[string]bond.QueuePolicy `json:"queues"`
	QoS            bond.QoSSettings            `json:"adaptive_qos"`
	Admin          json.RawMessage             `json:"admin"`
	LossTracking   bool                        `json:"loss_tracking"`
	PathMTU        bool                        `json:"path_mtu_discovery"`
	Failover       bool                        `json:"failover_replay"`
}

func DecodeConfig(data []byte) (Config, bond.SessionOptions, netip.AddrPort, []byte, error) {
	c := Config{MTU: 1280, TunName: "gamebond0", InitialRate: 1, MaximumRate: 100, ReorderMS: 30, QoS: bond.DefaultQoSSettings()}
	options := bond.DefaultSessionOptions()
	fail := func(err error) (Config, bond.SessionOptions, netip.AddrPort, []byte, error) {
		return c, options, netip.AddrPort{}, nil, err
	}
	if len(data) > 1024*1024 {
		return fail(fmt.Errorf("configuration exceeds size limit"))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return fail(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fail(fmt.Errorf("trailing configuration data"))
	}
	if c.Role != "server" || !c.Bonding || c.TunName != "gamebond0" || c.MTU != 1280 || c.ClientIP != "10.77.0.2" || c.BulkRate != 0 {
		return fail(fmt.Errorf("native container requires bonded IPv4 server, gamebond0, MTU1280, client 10.77.0.2 and bulk_rate_mbps=0"))
	}
	if len(c.Bind) != 1 || len(c.Bind[0]) != 2 {
		return fail(fmt.Errorf("one numeric IPv4 UDP bind required"))
	}
	var address string
	var port int
	if json.Unmarshal(c.Bind[0][0], &address) != nil || json.Unmarshal(c.Bind[0][1], &port) != nil || address != "0.0.0.0" || port != 4433 {
		return fail(fmt.Errorf("native container bind must be 0.0.0.0:4433"))
	}
	if len(c.Admin) > 0 && string(bytes.TrimSpace(c.Admin)) != "null" {
		if _, err := adminportal.ParseSettings(c.Admin); err != nil {
			return fail(err)
		}
	}
	session, err := hex.DecodeString(c.Session)
	if err != nil || len(session) != 16 {
		return fail(fmt.Errorf("invalid session identifier"))
	}
	options.MTU = c.MTU
	options.ClientIP = netip.MustParseAddr(c.ClientIP)
	options.InitialRate = c.InitialRate
	options.MaximumRate = c.MaximumRate
	options.Redundant = c.Redundant
	options.GamePorts = c.GamePorts
	options.QoS = c.QoS
	options.LossTracking, options.PathMTUDiscovery, options.FailoverReplay = c.LossTracking, c.PathMTU, c.Failover
	if c.ReorderMS < 1 || c.ReorderMS > 200 {
		return fail(fmt.Errorf("reorder timeout must be 1..200ms"))
	}
	options.ReorderTimeout = time.Duration(c.ReorderMS * float64(time.Millisecond))
	options.Policies = make(map[byte]bond.QueuePolicy)
	for tag, p := range c.Queues {
		n, err := strconv.Atoi(tag)
		if err != nil || n < 0 || n > 63 || p.Validate() != nil {
			return fail(fmt.Errorf("invalid queue policy"))
		}
		options.Policies[byte(n)] = p
	}
	if options.QoS.Validate() != nil {
		return fail(fmt.Errorf("invalid adaptive QoS settings"))
	}
	if _, err := bond.NewBudget(options.InitialRate, options.MaximumRate); err != nil {
		return fail(err)
	}
	for _, port := range options.GamePorts {
		if port == 0 {
			return fail(fmt.Errorf("invalid game port"))
		}
	}
	return c, options, netip.AddrPortFrom(netip.MustParseAddr(address), uint16(port)), session, nil
}
