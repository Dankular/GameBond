package desktopruntime

import (
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
)

func hideSupervisor(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP}
}
