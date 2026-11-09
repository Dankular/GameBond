//go:build !windows

package dashboard

import "gamebond.local/nativeedge/scanner"

func scannerInventory() (scanner.Inventory, error) { return scanner.Inventory{}, errScannerUnsupported }
func scannerProbe(source, target string, timeout int) (scanner.ProbeResult, error) {
	return scanner.ProbeResult{}, errScannerUnsupported
}
