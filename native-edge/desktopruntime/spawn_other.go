//go:build !windows

package desktopruntime

import "os/exec"

func hideSupervisor(cmd *exec.Cmd) {}
