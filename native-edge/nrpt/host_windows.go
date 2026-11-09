package nrpt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	shell32            = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin  = shell32.NewProc("IsUserAnAdmin")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetProcessTime = kernel32.NewProc("GetProcessTimes")
)

const createNoWindow = 0x08000000

// WindowsHost is the real operating-system binding. Running the worker needs
// an elevated session; it is exercised only by the injectable-host tests here.
func WindowsHost() Host {
	return Host{
		PID: os.Getpid(),
		RequireAdmin: func() error {
			if r, _, _ := procIsUserAnAdmin.Call(); r == 0 {
				return errors.New("--configure requires Run as administrator")
			}
			return nil
		},
		Created: processCreated,
		RunWorker: func(script string, stdin []byte) ([]byte, []byte, int, error) {
			root := os.Getenv("SystemRoot")
			if root == "" {
				root = `C:\Windows`
			}
			cmd := exec.Command(filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
				"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
			cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
			cmd.Stdin = bytes.NewReader(stdin)
			var out, errb bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errb
			err := cmd.Run()
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return out.Bytes(), errb.Bytes(), exit.ExitCode(), nil
			}
			return out.Bytes(), errb.Bytes(), 0, err
		},
	}
}

// processCreated is _process_created: the creation FILETIME, "" if the pid is gone.
func processCreated(pid int) (string, error) {
	h, err := syscall.OpenProcess(0x1000, false, uint32(pid))
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == 87 {
			return "", nil
		}
		return "", fmt.Errorf("Cannot verify journal process %d: %w", pid, err)
	}
	defer syscall.CloseHandle(h)
	var times [4]uint64
	r, _, err := procGetProcessTime.Call(uintptr(h), uintptr(unsafe.Pointer(&times[0])), uintptr(unsafe.Pointer(&times[1])),
		uintptr(unsafe.Pointer(&times[2])), uintptr(unsafe.Pointer(&times[3])))
	if r == 0 {
		return "", err
	}
	return fmt.Sprint(times[0]), nil
}
