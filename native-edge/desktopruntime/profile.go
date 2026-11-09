// Package desktopruntime joins the desktop widget to a persistent Go supervisor.
// Merely opening the widget or sampling status never starts a VPN session.
package desktopruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gamebond.local/nativeedge/appconfig"
	"gamebond.local/nativeedge/atomicio"
)

const ProfilePath = "configs/local-desktop.json"

type Profile struct {
	Version   int    `json:"version"`
	Config    string `json:"config"`
	Key       string `json:"key"`
	Netstack  string `json:"netstack"`
	Proxifyre bool   `json:"proxifyre"`
}

type Plan struct {
	Root, Client, Config, Key, Netstack, Metadata, Status, Usage string
	Proxifyre                                                    bool
}

func Resolve(root, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(root, path)
}

func Load(root, profilePath, config, metadata, status string) (Plan, error) {
	var p Profile
	if err := atomicio.ReadJSONShared(Resolve(root, profilePath), 64<<10, &p); err != nil {
		return Plan{}, err
	}
	if p.Version != 1 || p.Config == "" || p.Key == "" || p.Netstack == "" {
		return Plan{}, errors.New("desktop launch profile needs version 1, config, key and netstack")
	}
	if config != "" {
		p.Config = config
	}
	return Plan{Root: root, Client: Resolve(root, "build/gamebond-native-client.exe"), Config: Resolve(root, p.Config), Key: Resolve(root, p.Key), Netstack: Resolve(root, p.Netstack), Metadata: Resolve(root, metadata), Status: Resolve(root, status), Usage: Resolve(root, ".runtime/usage.json"), Proxifyre: p.Proxifyre}, nil
}

func (p Plan) Validate() error {
	for label, path := range map[string]string{"client binary": p.Client, "client config": p.Config, "shared key": p.Key, "netstack binary": p.Netstack} {
		st, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("%s is unavailable: %w", label, err)
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular file", label)
		}
	}
	raw, err := atomicio.ReadBytesShared(p.Config, 4<<20)
	if err != nil {
		return err
	}
	if _, err = appconfig.Load(raw, appconfig.Options{Windows: runtime.GOOS == "windows", AllowUnavailableLinks: true}); err != nil {
		return fmt.Errorf("client config: %w", err)
	}
	key, err := atomicio.ReadBytesShared(p.Key, 33)
	if err != nil {
		return err
	}
	if len(key) != 32 {
		return errors.New("shared key must contain exactly 32 bytes")
	}
	return nil
}

func (p Plan) Args() []string {
	args := []string{"-root", p.Root, "-config", p.Config, "-key", p.Key, "-netstack", p.Netstack, "-tty", p.Metadata, "-status", p.Status, "-usage", p.Usage, "-app-history", Resolve(p.Root, ".runtime/app-history.json"), "-supervise", "-stopped"}
	if p.Proxifyre {
		args = append(args, "-proxifyre")
	}
	return args
}

func (p Profile) Write(root string) error {
	if err := os.MkdirAll(Resolve(root, "configs"), 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return atomicio.WriteFileAtomic(Resolve(root, ProfilePath), append(raw, '\n'), 0600)
}
