package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestAutostartCommandRoundTripsPersistentPaths(t *testing.T) {
	exe, _ := os.Executable()
	for _, root := range []string{`D:\Dev Proj\Speedify`, `D:\`} {
		config := filepath.Join(root, "configs", "local-client.json")
		profile := filepath.Join(root, "configs", "local-desktop.json")
		got, err := windows.DecomposeCommandLine(autostartValue(root, config, profile))
		if err != nil {
			t.Fatal(err)
		}
		want := []string{exe, "-root", filepath.Clean(root), "-config", config, "-runtime-profile", profile}
		if !reflect.DeepEqual(got, want) {
			t.Fatal(got, want)
		}
	}
}

func TestAutostartRegistryWriteAndDisableAtIsolatedKey(t *testing.T) {
	// A separate HKCU leaf cannot register a Windows startup action.
	path := fmt.Sprintf(`Software\GameBondTest-%d-%d`, os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() { registry.DeleteKey(registry.CURRENT_USER, path) })
	if err := setAutostartAt(path, true, "test command"); err != nil {
		t.Fatal(err)
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	value, _, err := k.GetStringValue("GameBondTray")
	k.Close()
	if err != nil || value != "test command" {
		t.Fatal(value, err)
	}
	if err := setAutostartAt(path, false, ""); err != nil {
		t.Fatal(err)
	}
	k, err = registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if _, _, err := k.GetStringValue("GameBondTray"); err != registry.ErrNotExist {
		t.Fatal("autostart value retained", err)
	}
}
