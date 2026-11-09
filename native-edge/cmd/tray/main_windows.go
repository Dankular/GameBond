// Command tray is the Windows notification-area agent for the Go client daemon
// (the replacement for gamebond/tray.py and the widget that hosted it): an icon
// whose colour and tooltip follow the daemon's status file, a menu to connect,
// disconnect and open the dashboard, and one agent per workspace.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"gamebond.local/nativeedge/atomicio"
	"gamebond.local/nativeedge/dashboard"
	"gamebond.local/nativeedge/hwmon"
	"gamebond.local/nativeedge/tray"
	"gamebond.local/nativeedge/ttyrelay"
)

const (
	cmdShow = iota + 1
	cmdToggle
	cmdApps
	cmdNetworks
	cmdLinks
	cmdAutostart
	cmdQuit
)

func main() {
	root := flag.String("root", ".", "workspace root (one tray agent per root)")
	statusPath := flag.String("status", filepath.Join(".runtime", "userspace-status.json"), "daemon status file")
	relayPath := flag.String("relay", filepath.Join(".runtime", "go-relay.json"), "daemon relay metadata (supervisor control)")
	configPath := flag.String("config", "", "client config the link roles & limits editor changes")
	printURL := flag.Bool("print-url", false, "print the dashboard URL (contains the access token) to stdout")
	flag.Parse()
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fail(err)
	}
	abs := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(absRoot, p)
	}
	lease, err := tray.AcquireLease(absRoot)
	if err != nil {
		fail(err)
	}
	defer lease.Close()
	if !lease.Owner {
		return // the running agent was asked to show itself
	}
	var busy atomic.Bool
	control := func(command string) (map[string]any, error) {
		busy.Store(true)
		defer busy.Store(false)
		return ttyrelay.Control(abs(*relayPath), command, 60*time.Second, io.Discard)
	}
	var hardware func() map[string]any
	if sampler, err := hwmon.New(hwmon.WindowsBackend{}, hwmon.Options{}); err == nil {
		hardware = sampler.Sample
	}
	logLines := func() []string {
		var buf bytes.Buffer
		if ttyrelay.Attach(abs(*relayPath), 200, 400*time.Millisecond, &buf) != nil {
			return []string{}
		}
		return strings.Split(strings.TrimRight(strings.ReplaceAll(buf.String(), "\r\n", "\n"), "\n"), "\n")
	}
	server, url, err := dashboard.Start(dashboard.Options{StatusPath: abs(*statusPath), ConfigPath: abs(*configPath), Control: control, Hardware: hardware, Log: logLines})
	if err != nil {
		fail(err)
	}
	defer server.Close()
	if *printURL {
		fmt.Println(url)
	}

	model := tray.NewModel()
	shell := &tray.Shell{}
	sample := func() map[string]any {
		var doc map[string]any
		if atomicio.ReadJSONShared(abs(*statusPath), 4<<20, &doc) != nil {
			return nil
		}
		// A status file the daemon stopped refreshing means it is gone.
		if at, ok := doc["updated_at"].(float64); ok && time.Since(time.Unix(int64(at), 0)) > 15*time.Second {
			return nil
		}
		return doc
	}
	shell.Menu = func() []tray.MenuItem {
		return []tray.MenuItem{
			{ID: cmdShow, Label: "Show GameBond", Enabled: true},
			{ID: cmdToggle, Label: model.ToggleLabel, Enabled: model.ToggleEnabled && !busy.Load()},
			{},
			{ID: cmdApps, Label: "Manage apps", Enabled: true},
			{ID: cmdNetworks, Label: "Network settings", Enabled: true},
			{ID: cmdLinks, Label: "Link roles & limits", Enabled: true},
			{ID: cmdAutostart, Label: autostartLabel(), Enabled: true},
			{},
			{ID: cmdQuit, Label: "Quit (stop tunnel)", Enabled: true},
		}
	}
	open := func() { _ = tray.Open(url) }
	shell.OnDefault = open
	shell.OnCommand = func(id int) {
		switch id {
		case cmdShow, cmdApps, cmdNetworks, cmdLinks:
			open()
		case cmdToggle:
			command := "restart"
			if model.ToggleLabel == "Disconnect" {
				command = "stop"
			}
			go control(command)
		case cmdAutostart:
			_ = setAutostart(!autostartEnabled(), autostartValue(absRoot, *configPath))
		case cmdQuit:
			go func() {
				control("stop")
				shell.Quit()
			}()
		}
	}
	shell.OnTick = func() {
		if lease.ShowRequested() {
			open()
		}
		if model.Update(sample(), busy.Load(), "") {
			shell.SetIcon(model.Color, model.Title)
		}
	}
	if err := shell.Run(model.Color, model.Title); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "tray:", err)
	os.Exit(1)
}

func autostartLabel() string {
	if autostartEnabled() {
		return "Start with Windows (on)"
	}
	return "Start with Windows (off)"
}
