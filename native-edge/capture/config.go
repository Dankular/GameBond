// Package capture is capture.py plus the ProxiFyre staging half of
// userspace.py: which applications are routed into the netstack's SOCKS
// endpoint, the attribution extension's integrity check, and the staged
// ProxiFyre process.
package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gamebond.local/nativeedge/appevents"
	"gamebond.local/nativeedge/apppolicy"
)

// NormalizeApps is capture.normalize_apps: strip, ntpath.normpath, require a
// drive-qualified absolute .exe path, de-duplicate case-insensitively.
func NormalizeApps(applications []any) ([]string, error) {
	result := []string{}
	seen := map[string]bool{}
	for _, item := range applications {
		s, ok := item.(string)
		if !ok {
			return nil, errors.New("Choose executable files")
		}
		s = apppolicy.NormPath(apppolicy.PyStrip(s))
		if !apppolicy.IsAbs(s) || apppolicy.SplitDrive(s) == "" || !apppolicy.HasExeSuffix(s) || strings.ContainsRune(s, 0) {
			return nil, errors.New("Each application must have a full .exe path")
		}
		key := appevents.Casefold(s)
		if !seen[key] {
			result = append(result, s)
			seen[key] = true
		}
	}
	return result, nil
}

// Proxy is one ProxiFyre proxy entry (JSON key names are ProxiFyre's).
type Proxy struct {
	AppNames                 []string `json:"appNames"`
	Socks5ProxyEndpoint      string   `json:"socks5ProxyEndpoint"`
	Socks5Transport          string   `json:"socks5Transport"`
	SupportedProtocols       []string `json:"supportedProtocols"`
	SupportedAddressFamilies []string `json:"supportedAddressFamilies"`
	Username                 string   `json:"username,omitempty"`
	Password                 string   `json:"password,omitempty"`
}

// Configuration is ProxiFyre's app-config.json.
type Configuration struct {
	LogLevel  string   `json:"logLevel"`
	BypassLAN bool     `json:"bypassLan"`
	Excludes  []string `json:"excludes"`
	Proxies   []Proxy  `json:"proxies"`
}

func dedupe(items []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range items {
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out
}

// ProxyConfiguration is capture.proxy_configuration. mode is capture_mode
// ("all" when empty), apps is cod_executables. carriers are the executables
// that must never be captured themselves (Python passes python.exe and
// pythonw.exe next to its interpreter; the Go daemon passes its own binary).
func ProxyConfiguration(mode string, apps []any, address, root string, carriers []string, netstackExecutable string) (*Configuration, error) {
	if mode == "" {
		mode = "all"
	}
	if mode != "all" && mode != "selected" {
		return nil, errors.New("Choose All apps or Selected apps")
	}
	excluded := append([]string(nil), carriers...)
	excluded = append(excluded, filepath.Join(root, "build", "gamebond-netstack.exe"),
		filepath.Join(root, ".runtime", "userspace-proxy", "ProxiFyre.exe"))
	if netstackExecutable != "" {
		excluded = append(excluded, netstackExecutable)
	}
	names := []string{""}
	if mode == "selected" {
		normal, err := NormalizeApps(apps)
		if err != nil {
			return nil, err
		}
		names = append(normal, filepath.Join(root, "build", "gamebond-internet-probe.exe"))
	}
	return &Configuration{LogLevel: "Info", Excludes: dedupe(excluded), Proxies: []Proxy{{
		AppNames: dedupe(names), Socks5ProxyEndpoint: address, Socks5Transport: "TCP",
		SupportedProtocols: []string{"TCP", "UDP"}, SupportedAddressFamilies: []string{"IPv4"}}}}, nil
}

// Manifest is build/native-capture/manifest.json.
type Manifest struct {
	Schema    int    `json:"schema"`
	Feature   string `json:"feature"`
	DLLSHA256 string `json:"dll_sha256"`
}

// VerifyExtension is the userspace.py check before enabling attribution: the
// manifest exists next to socksify.dll, names schema 1 / gamebond-owner-v1,
// and the DLL's SHA-256 matches. (nil, nil) means "no extension installed".
func VerifyExtension(dir string) (extension string, err error) {
	manifest := filepath.Join(dir, "manifest.json")
	dll := filepath.Join(dir, "socksify.dll")
	if info, e := os.Stat(manifest); e != nil || !info.Mode().IsRegular() {
		return "", nil
	}
	if info, e := os.Stat(dll); e != nil || !info.Mode().IsRegular() {
		return "", nil
	}
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return "", err
	}
	var record Manifest
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return "", err
	}
	schema, isNum := generic["schema"].(float64)
	feature, _ := generic["feature"].(string)
	want, _ := generic["dll_sha256"].(string)
	record = Manifest{Feature: feature, DLLSHA256: want}
	body, err := os.ReadFile(dll)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	if !isNum || schema != 1 || record.Feature != "gamebond-owner-v1" || hex.EncodeToString(sum[:]) != record.DLLSHA256 {
		return "", errors.New("Native application attribution build integrity check failed")
	}
	return dll, nil
}
