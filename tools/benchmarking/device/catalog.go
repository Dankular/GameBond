package device

import (
	"fmt"
	"strings"
	"time"

	"gamebond.local/benchmarking/report"
)

type Condition struct {
	Key   string
	Label string
}

type Benchmark struct {
	Key            string
	Name           string
	Unit           string
	Conditions     []Condition
	Prerequisites  []string
	Interpretation string
}

func c(key, label string) Condition { return Condition{Key: key, Label: label} }

var catalog = []Benchmark{
	{Key: "switching_capacity", Name: "Switching capacity", Unit: "Gbps", Conditions: []Condition{c("port_count", "port count"), c("port_speeds", "port speeds"), c("packet_size", "packet size"), c("duplex", "duplex"), c("traffic_direction", "traffic direction")}, Prerequisites: []string{"traffic generator at every tested port", "isolated test topology"}, Interpretation: "Report the aggregate offered and forwarded rate; state whether the figure counts one or both directions."},
	{Key: "total_non_blocking_throughput", Name: "Total non-blocking throughput", Unit: "Gbps", Conditions: []Condition{c("active_port_count", "active port count"), c("port_speeds", "port speeds"), c("packet_size", "packet size"), c("traffic_matrix", "traffic matrix"), c("duplex", "duplex")}, Prerequisites: []string{"traffic generator ports covering the tested forwarding matrix", "isolated test topology"}, Interpretation: "Call a fabric non-blocking only when all tested ports sustain the documented offered load without unexplained loss."},
	{Key: "forwarding_rate", Name: "Forwarding rate", Unit: "Mpps", Conditions: []Condition{c("packet_size", "packet size"), c("port_count", "port count"), c("traffic_direction", "traffic direction"), c("offered_rate", "offered rate"), c("loss_threshold", "loss threshold")}, Prerequisites: []string{"packet-capable traffic generator", "isolated test topology"}, Interpretation: "Record packet size and loss threshold; frame rate changes substantially with packet size."},
	{Key: "supported_vlans", Name: "Supported VLANs", Unit: "VLANs", Conditions: []Condition{c("configured_vlan_count", "configured VLAN count"), c("tested_vlan_count", "tested VLAN count"), c("traffic_per_vlan", "traffic per VLAN")}, Prerequisites: []string{"preconfigured isolated VLAN testbed", "traffic endpoints on tested VLANs"}, Interpretation: "A configured count is not a forwarding-capacity measurement; record how many VLANs carried verified traffic."},
	{Key: "mac_address_table_size", Name: "MAC address table size", Unit: "entries", Conditions: []Condition{c("learned_address_count", "learned address count"), c("aging_time", "aging time"), c("vlan_distribution", "VLAN distribution"), c("verified_forwarding_count", "verified forwarding count")}, Prerequisites: []string{"preconfigured isolated testbed", "traffic source with controllable source MAC addresses"}, Interpretation: "Record learned entries and the highest count that continued to forward correctly."},
	{Key: "ipv4_static_routes", Name: "IPv4 static routes", Unit: "routes", Conditions: []Condition{c("installed_route_count", "installed route count"), c("prefix_lengths", "prefix lengths"), c("next_hop_count", "next-hop count"), c("forwarding_verification", "forwarding verification")}, Prerequisites: []string{"preconfigured isolated routing testbed", "traffic endpoints behind test routes"}, Interpretation: "Separate accepted/installed routes from routes verified in the forwarding plane."},
	{Key: "packet_buffer_size", Name: "Packet buffer size", Unit: "bytes", Conditions: []Condition{c("offered_load", "offered load"), c("egress_rate", "egress rate"), c("burst_duration", "burst duration"), c("queue_policy", "queue policy"), c("loss", "loss"), c("latency", "latency")}, Prerequisites: []string{"traffic generator with burst control", "isolated test topology"}, Interpretation: "Treat vendor buffer capacity as reported specification; measured buffer behavior should include queueing latency and loss under congestion."},
	{Key: "multi_wan_load_balancing", Name: "Multi-WAN load balancing", Unit: "Mbps", Conditions: []Condition{c("wan_count", "WAN count"), c("per_wan_capacity_and_latency", "per-WAN capacity and latency"), c("flow_count", "flow count"), c("direction", "direction"), c("per_wan_byte_counts", "per-WAN byte counts"), c("loss", "loss")}, Prerequisites: []string{"at least two preconfigured WANs", "independent traffic endpoints per WAN"}, Interpretation: "Report per-WAN useful bytes/rates and total useful throughput; use both one-flow and multi-flow profiles."},
	{Key: "dpi_traffic_identification", Name: "DPI and traffic identification", Unit: "Mbps", Conditions: []Condition{c("traffic_mix", "traffic mix"), c("offered_load", "offered load"), c("identified_flow_count", "identified flow count"), c("classification_accuracy", "classification accuracy"), c("latency", "latency"), c("loss", "loss")}, Prerequisites: []string{"repeatable labeled traffic corpus", "isolated test topology"}, Interpretation: "Report throughput together with classification accuracy, flow count, latency, and loss; throughput alone is incomplete."},
}

func ListBenchmarks() []Benchmark { return append([]Benchmark(nil), catalog...) }

func Find(key string) (Benchmark, bool) {
	for _, benchmark := range catalog {
		if benchmark.Key == key {
			return benchmark, true
		}
	}
	return Benchmark{}, false
}

func ValidateRun(run report.Run) error {
	if err := report.Validate(run); err != nil {
		return err
	}
	if run.Mode != "device" && run.Mode != "specs" {
		return fmt.Errorf("mode must be device or specs")
	}
	for i, result := range run.Results {
		benchmark, ok := Find(result.Key)
		if !ok {
			return fmt.Errorf("results[%d].key: unsupported device benchmark %q", i, result.Key)
		}
		if result.Method == "measured" && result.Unit != benchmark.Unit {
			return fmt.Errorf("results[%d].unit: %s requires %q", i, result.Key, benchmark.Unit)
		}
		conditionValues := make(map[string]string, len(result.Conditions))
		for _, condition := range result.Conditions {
			if _, duplicate := conditionValues[condition.Name]; duplicate {
				return fmt.Errorf("results[%d].conditions: duplicate key %q", i, condition.Name)
			}
			conditionValues[condition.Name] = strings.TrimSpace(condition.Value)
		}
		if result.Method != "measured" {
			continue
		}
		allowedConditions := make(map[string]bool, len(benchmark.Conditions))
		for _, condition := range benchmark.Conditions {
			allowedConditions[condition.Key] = true
		}
		for condition := range conditionValues {
			if !allowedConditions[condition] {
				return fmt.Errorf("results[%d].conditions: unknown key %q", i, condition)
			}
		}
		available := make(map[string]bool, len(run.Prerequisites))
		for _, prerequisite := range run.Prerequisites {
			available[prerequisite] = true
		}
		for _, prerequisite := range benchmark.Prerequisites {
			if !available[prerequisite] {
				return fmt.Errorf("results[%d]: missing lab prerequisite %q", i, prerequisite)
			}
		}
		for _, condition := range benchmark.Conditions {
			if conditionValues[condition.Key] == "" {
				return fmt.Errorf("results[%d]: missing condition %q (%s)", i, condition.Key, condition.Label)
			}
		}
	}
	return nil
}

type Setup struct {
	Target                 string   `json:"target"`
	AvailablePrerequisites []string `json:"available_prerequisites"`
}

type AssessmentResult struct {
	Key                  string   `json:"key"`
	Name                 string   `json:"name"`
	Status               string   `json:"status"`
	Unit                 string   `json:"unit"`
	MissingPrerequisites []string `json:"missing_prerequisites,omitempty"`
	RequiredConditions   []string `json:"required_conditions"`
	Interpretation       string   `json:"interpretation"`
}

type Assessment struct {
	Timestamp string             `json:"timestamp"`
	Target    string             `json:"target"`
	Results   []AssessmentResult `json:"results"`
	Note      string             `json:"note"`
}

func Assess(setup Setup) (Assessment, error) {
	if strings.TrimSpace(setup.Target) == "" {
		return Assessment{}, fmt.Errorf("target is required")
	}
	available := make(map[string]bool, len(setup.AvailablePrerequisites))
	for _, item := range setup.AvailablePrerequisites {
		available[strings.TrimSpace(item)] = true
	}
	out := Assessment{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Target:    setup.Target,
		Note:      "Ready means listed lab prerequisites are present. Traffic generation and device configuration remain external; no measurement was run.",
	}
	for _, benchmark := range catalog {
		result := AssessmentResult{Key: benchmark.Key, Name: benchmark.Name, Status: "ready", Unit: benchmark.Unit, Interpretation: benchmark.Interpretation}
		for _, prerequisite := range benchmark.Prerequisites {
			if !available[prerequisite] {
				result.Status = "skipped"
				result.MissingPrerequisites = append(result.MissingPrerequisites, prerequisite)
			}
		}
		for _, condition := range benchmark.Conditions {
			result.RequiredConditions = append(result.RequiredConditions, condition.Key)
		}
		out.Results = append(out.Results, result)
	}
	return out, nil
}

func Guide(key string) (string, error) {
	b, ok := Find(key)
	if !ok {
		return "", fmt.Errorf("unknown device benchmark %q", key)
	}
	text := fmt.Sprintf("%s (%s)\n\nPrerequisites:\n", b.Name, b.Unit)
	for _, p := range b.Prerequisites {
		text += "- " + p + "\n"
	}
	text += "\nRecord these conditions:\n"
	for _, c := range b.Conditions {
		text += fmt.Sprintf("- %s: %s\n", c.Key, c.Label)
	}
	text += "\nInterpretation: " + b.Interpretation + "\n"
	text += "\nUse a measured result only when the setup and forwarding outcome were directly observed. Otherwise record the vendor figure with method=vendor_reported. This utility does not configure the device or generate traffic.\n"
	return text, nil
}
