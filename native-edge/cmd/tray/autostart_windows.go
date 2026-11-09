package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// autostartValue is the command the Run entry launches: this binary for this root.
func autostartValue(root, config, profile string) string {
	exe, _ := os.Executable()
	args := []string{exe, "-root", filepath.Clean(root)}
	if config != "" {
		args = append(args, "-config", config)
	}
	if profile != "" {
		args = append(args, "-runtime-profile", profile)
	}
	return windows.ComposeCommandLine(args)
}

func autostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue("GameBondTray")
	return err == nil
}

func setAutostart(on bool, value string) error {
	return setAutostartAt(runKey, on, value)
}

func setAutostartAt(key string, on bool, value string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if on {
		return k.SetStringValue("GameBondTray", value)
	}
	if err := k.DeleteValue("GameBondTray"); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}
