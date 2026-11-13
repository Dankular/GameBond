package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"

	"gamebond.local/benchmarking/gamebond"
	"gamebond.local/benchmarking/report"
)

func RunGameBond(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gamebond import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	input := fs.String("input", "", "existing speedtest-last.json result")
	output := fs.String("output", "", "output JSON report path")
	target := fs.String("target", "", "human-readable tunnel or path name")
	force := fs.Bool("force", false, "replace an existing output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" || *output == "" {
		return fmt.Errorf("usage: benchmark gamebond import --input <speedtest-last.json> --output <report.json> [--target name] [--force]")
	}
	raw, err := os.ReadFile(*input)
	if err != nil {
		return fmt.Errorf("read %s: %w", *input, err)
	}
	run, err := gamebond.FromSpeedTest(raw, *target)
	if err != nil {
		return err
	}
	if err := report.WriteJSON(*output, run, *force); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "saved %s: download %.2f Mbps, upload %.2f Mbps; wire bytes unavailable\n", *output, run.Results[0].Value, run.Results[1].Value)
	return nil
}
