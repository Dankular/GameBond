package specs

import (
	"fmt"
	"sort"
	"strings"

	"gamebond.local/benchmarking/device"
	"gamebond.local/benchmarking/report"
)

type Row struct {
	Device string  `json:"device"`
	Value  float64 `json:"value"`
	Unit   string  `json:"unit"`
	Method string  `json:"method"`
	Note   string  `json:"note,omitempty"`
}

type BenchmarkComparison struct {
	Benchmark  string   `json:"benchmark"`
	Rows       []Row    `json:"rows"`
	Comparable bool     `json:"comparable"`
	Reasons    []string `json:"reasons,omitempty"`
}

type Comparison struct {
	Benchmarks []BenchmarkComparison `json:"benchmarks"`
	Comparable bool                  `json:"comparable"`
}

func Compare(runs []report.Run) (Comparison, error) {
	if len(runs) < 2 {
		return Comparison{}, fmt.Errorf("at least two device reports are required")
	}
	byKey := make(map[string][]Row)
	for _, run := range runs {
		if err := device.ValidateRun(run); err != nil {
			return Comparison{}, fmt.Errorf("%s: %w", run.Target, err)
		}
		for _, result := range run.Results {
			byKey[result.Key] = append(byKey[result.Key], Row{Device: run.Target, Value: result.Value, Unit: result.Unit, Method: result.Method, Note: result.Note})
		}
	}
	if len(byKey) == 0 {
		return Comparison{}, fmt.Errorf("reports contain no device capability results")
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := Comparison{Comparable: true}
	for _, key := range keys {
		rows := byKey[key]
		sort.Slice(rows, func(i, j int) bool { return rows[i].Device < rows[j].Device })
		group := BenchmarkComparison{Benchmark: key, Rows: rows, Comparable: true}
		if len(rows) < len(runs) {
			group.Comparable = false
			group.Reasons = append(group.Reasons, "benchmark is missing from one or more device reports")
		}
		units, methods := map[string]bool{}, map[string]bool{}
		conditions := map[string]bool{}
		for _, run := range runs {
			for _, result := range run.Results {
				if result.Key == key {
					units[result.Unit] = true
					methods[result.Method] = true
					conditions[canonicalConditions(result.Conditions)] = true
				}
			}
		}
		if len(units) > 1 {
			group.Comparable = false
			group.Reasons = append(group.Reasons, "values use different units")
		}
		if len(methods) > 1 {
			group.Comparable = false
			group.Reasons = append(group.Reasons, "values mix measured and vendor-reported methods")
		}
		if len(conditions) > 1 {
			group.Comparable = false
			group.Reasons = append(group.Reasons, "test conditions differ")
		}
		if !group.Comparable {
			out.Comparable = false
		}
		out.Benchmarks = append(out.Benchmarks, group)
	}
	return out, nil
}

func canonicalConditions(conditions []report.Condition) string {
	copyOf := append([]report.Condition(nil), conditions...)
	sort.Slice(copyOf, func(i, j int) bool {
		if copyOf[i].Name == copyOf[j].Name {
			return copyOf[i].Value < copyOf[j].Value
		}
		return copyOf[i].Name < copyOf[j].Name
	})
	var b strings.Builder
	for _, condition := range copyOf {
		fmt.Fprintf(&b, "%s=%s\x00", condition.Name, condition.Value)
	}
	return b.String()
}

func Markdown(c Comparison) string {
	var b strings.Builder
	b.WriteString("# Device specification comparison\n\n")
	b.WriteString("Values retain their source method. Matching units are a basic comparability check; vendor methodologies may still differ. No overall score is calculated.\n")
	for _, benchmark := range c.Benchmarks {
		fmt.Fprintf(&b, "\n## %s\n\n", benchmark.Benchmark)
		b.WriteString("| Device | Value | Method | Note |\n|---|---:|---|---|\n")
		for _, row := range benchmark.Rows {
			fmt.Fprintf(&b, "| %s | %g %s | %s | %s |\n", row.Device, row.Value, row.Unit, row.Method, row.Note)
		}
		if !benchmark.Comparable {
			b.WriteString("\nNot directly comparable: " + strings.Join(benchmark.Reasons, "; ") + "\n")
		}
	}
	return b.String()
}
