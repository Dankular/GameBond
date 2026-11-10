//go:build !windows

package capture

func KillStale(dir string) int { return 0 }
