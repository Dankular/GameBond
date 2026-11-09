package dashboard

import "gamebond.local/nativeedge/scanner"

func scannerInventory() (scanner.Inventory, error) { return scanner.TakeInventory() }
func scannerProbe(source, target string, timeout int) (scanner.ProbeResult, error) {
	return scanner.ICMPProbe(source, target, timeout)
}
