package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"gamebond.local/benchmarking/report"
	"gamebond.local/benchmarking/specs"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func RunSpecs(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("specs compare", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var inputs stringList
	fs.Var(&inputs, "input", "device report JSON file (repeat for each device)")
	format := fs.String("format", "markdown", "output format: markdown or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(inputs) < 2 {
		return fmt.Errorf("usage: benchmark specs compare --input <report.json> --input <report.json> [--format markdown|json]")
	}
	if *format != "markdown" && *format != "json" {
		return fmt.Errorf("format must be markdown or json")
	}
	runs := make([]report.Run, 0, len(inputs))
	for _, path := range inputs {
		run, err := report.Read(path)
		if err != nil {
			return err
		}
		runs = append(runs, run)
	}
	comparison, err := specs.Compare(runs)
	if err != nil {
		return err
	}
	if *format == "markdown" {
		_, err = io.WriteString(stdout, specs.Markdown(comparison))
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(comparison)
}
