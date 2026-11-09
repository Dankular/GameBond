package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// autostartValue is the command the Run entry launches: this binary for this root.
func autostartValue(root, config string) string {
	exe, _ := os.Executable()
	v := `"` + exe + `" -root "` + filepath.Clean(root) + `"`
	if config != "" {
		v += ` -config "` + config + `"`
	}
	return v
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
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
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
