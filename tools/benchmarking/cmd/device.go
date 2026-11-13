package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"gamebond.local/benchmarking/device"
	"gamebond.local/benchmarking/report"
)

func RunDevice(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: benchmark device <list|guide|record>")
	}
	switch args[0] {
	case "list":
		for _, b := range device.ListBenchmarks() {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", b.Key, b.Name, b.Unit)
		}
		return nil
	case "guide":
		if len(args) != 2 {
			return fmt.Errorf("usage: benchmark device guide <key>")
		}
		text, err := device.Guide(args[1])
		if err != nil {
			return err
		}
		_, err = io.WriteString(stdout, text)
		return err
	case "assess":
		fs := flag.NewFlagSet("device assess", flag.ContinueOnError)
		fs.SetOutput(stderr)
		input := fs.String("input", "", "JSON lab setup with available_prerequisites")
		output := fs.String("output", "", "output setup assessment JSON path")
		force := fs.Bool("force", false, "replace an existing output file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *input == "" || *output == "" {
			return fmt.Errorf("device assess requires --input and --output")
		}
		raw, err := os.ReadFile(*input)
		if err != nil {
			return fmt.Errorf("read %s: %w", *input, err)
		}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		var setup device.Setup
		if err := decoder.Decode(&setup); err != nil {
			return fmt.Errorf("parse setup: %w", err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return fmt.Errorf("parse setup: expected one JSON object")
		}
		assessment, err := device.Assess(setup)
		if err != nil {
			return err
		}
		if err := report.Write(*output, assessment, *force); err != nil {
			return err
		}
		ready, skipped := 0, 0
		for _, result := range assessment.Results {
			if result.Status == "ready" {
				ready++
			} else {
				skipped++
			}
		}
		fmt.Fprintf(stdout, "saved %s: %d ready, %d skipped; no traffic was generated\n", *output, ready, skipped)
		return nil
	case "record":
		fs := flag.NewFlagSet("device record", flag.ContinueOnError)
		fs.SetOutput(stderr)
		input := fs.String("input", "", "JSON run record containing observed device results")
		output := fs.String("output", "", "output JSON report path")
		force := fs.Bool("force", false, "replace an existing output file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *input == "" || *output == "" {
			return fmt.Errorf("device record requires --input and --output")
		}
		run, err := report.Read(*input)
		if err != nil {
			return err
		}
		if err := device.ValidateRun(run); err != nil {
			return err
		}
		if err := report.WriteJSON(*output, run, *force); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "validated %d result(s); saved %s\n", len(run.Results), *output)
		return nil
	default:
		return fmt.Errorf("unknown device command %q; use list, guide, or record", args[0])
	}
}
