//go:build !windows

package appauth

// ResolveProcess needs Windows process handles; elsewhere nothing verifies.
func ResolveProcess(int64, string) map[string]any { return nil }
