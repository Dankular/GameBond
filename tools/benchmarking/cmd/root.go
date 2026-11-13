package cmd

import (
	"fmt"
	"io"
)

func Help(w io.Writer) {
	fmt.Fprintln(w, "Usage: benchmark <device|specs|gamebond> <command> [options]")
	fmt.Fprintln(w, "  device list")
	fmt.Fprintln(w, "  device guide <benchmark-key>")
	fmt.Fprintln(w, "  device assess --input <lab-setup.json> --output <assessment.json> [--force]")
	fmt.Fprintln(w, "  device record --input <run.json> --output <report.json> [--force]")
	fmt.Fprintln(w, "  specs compare --input <report.json> --input <report.json> [--format markdown|json]")
	fmt.Fprintln(w, "  gamebond import --input <speedtest-last.json> --output <report.json> [--target name] [--force]")
}

func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		Help(stdout)
		return nil
	}
	switch args[0] {
	case "device":
		return RunDevice(args[1:], stdout, stderr)
	case "specs":
		if len(args) < 2 || args[1] != "compare" {
			return fmt.Errorf("usage: benchmark specs compare --input <report.json> --input <report.json>")
		}
		return RunSpecs(args[2:], stdout, stderr)
	case "gamebond":
		if len(args) < 2 || args[1] != "import" {
			return fmt.Errorf("usage: benchmark gamebond import --input <speedtest-last.json> --output <report.json>")
		}
		return RunGameBond(args[2:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q (use --help)", args[0])
	}
}
