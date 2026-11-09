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
	"sync"
	"sync/atomic"
	"time"

	"gamebond.local/nativeedge/atomicio"
	"gamebond.local/nativeedge/dashboard"
	"gamebond.local/nativeedge/eventjournal"
	"gamebond.local/nativeedge/hwmon"
	"gamebond.local/nativeedge/tray"
	"gamebond.local/nativeedge/ttyrelay"
	"gamebond.local/nativeedge/uplink"
)

const (
	cmdShow = iota + 1
	cmdToggle
	cmdApps
	cmdNetworks
	cmdLinks
	cmdAutostart
	cmdQuit
	cmdDashboard
)

func main() {
	root := flag.String("root", ".", "workspace root (one tray agent per root)")
	statusPath := flag.String("status", filepath.Join(".runtime", "userspace-status.json"), "daemon status file")
	relayPath := flag.String("relay", filepath.Join(".runtime", "go-relay.json"), "daemon relay metadata (supervisor control)")
	configPath := flag.String("config", "", "client config the link roles & limits editor changes")
	assetsPath := flag.String("assets", filepath.Join("assets", "glasswire"), "desktop theme and icon assets")
	printURL := flag.Bool("print-url", false, "print the dashboard URL (contains the access token) to stdout")
	trayOnly := flag.Bool("tray", false, "start with the desktop widget hidden")
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
	if *configPath == "" {
		*configPath = filepath.Join("configs", "local-client.json")
		if raw, err := os.ReadFile(abs(filepath.Join(".runtime", "widget-config-path.txt"))); err == nil {
			candidate := strings.TrimSpace(string(raw))
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				*configPath = candidate
			}
		}
	}
	lease, err := tray.AcquireLease(absRoot)
	if err != nil {
		fail(err)
	}
	defer lease.Close()
	if !lease.Owner {
		return // the running agent was asked to show itself
	}
	journal, err := eventjournal.Open(abs(filepath.Join(".runtime", "dashboard-events.json")), 2048)
	if err != nil {
		fail(err)
	}
	defer journal.Close()
	var appHistory struct {
		Events []any `json:"events"`
	}
	if atomicio.ReadJSONShared(abs(filepath.Join(".runtime", "app-history.json")), 4<<20, &appHistory) == nil {
		journal.Ingest(appHistory.Events)
	}
	var busy atomic.Bool
	var latest atomic.Value
	var refreshMu sync.Mutex
	var appActivity dashboard.AppActivitySampler
	latest.Store(map[string]any{"state": "starting"})
	refresh := func() {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		doc := dashboard.ReadStatus(abs(*statusPath), func() (map[string]any, error) {
			return ttyrelay.Control(abs(*relayPath), "status", 2*time.Second, io.Discard)
		})
		doc["adapter_activity"] = latest.Load().(map[string]any)["adapter_activity"]
		doc["protect_activity"] = appActivity.Sample(doc, time.Now())
		journal.Observe(doc)
		latest.Store(doc)
	}
	control := func(command string) (map[string]any, error) {
		if !busy.CompareAndSwap(false, true) {
			return nil, fmt.Errorf("a connection action is already in progress")
		}
		defer busy.Store(false)
		result, err := ttyrelay.Control(abs(*relayPath), command, 60*time.Second, io.Discard)
		refresh()
		return result, err
	}
	var hardware func() map[string]any
	if sampler, err := hwmon.New(hwmon.WindowsBackend{}, hwmon.Options{GPU: hwmon.NewGPUSampler(5, nil, nil, nil)}); err == nil {
		hardware = sampler.Sample
	}
	logLines := func() []string {
		var buf bytes.Buffer
		if ttyrelay.Attach(abs(*relayPath), 200, 400*time.Millisecond, &buf) != nil {
			return []string{}
		}
		return strings.Split(strings.TrimRight(strings.ReplaceAll(buf.String(), "\r\n", "\n"), "\n"), "\n")
	}
	sample := func() map[string]any { return latest.Load().(map[string]any) }
	go func() {
		activity := &dashboard.ActivitySampler{}
		network := hwmon.WindowsBackend{}
		for {
			refresh()
			counters, err := network.NetIO()
			adapters, inventoryErr := uplink.Adapters()
			if err == nil && inventoryErr == nil {
				rows := activity.Sample(counters, adapters, time.Now())
				refreshMu.Lock()
				doc := sample()
				withActivity := make(map[string]any, len(doc)+1)
				for k, v := range doc {
					withActivity[k] = v
				}
				withActivity["adapter_activity"] = rows
				latest.Store(withActivity)
				refreshMu.Unlock()
			}
			time.Sleep(time.Second)
		}
	}()
	server, url, err := dashboard.Start(dashboard.Options{StatusPath: abs(*statusPath), ConfigPath: abs(*configPath), RootPath: absRoot, AssetsPath: abs(*assetsPath), Snapshot: sample, Control: control, Hardware: hardware, Log: logLines, Journal: journal})
	if err != nil {
		fail(err)
	}
	defer server.Close()
	if *printURL {
		fmt.Println(url)
	}

	var lastColor string
	model := tray.NewModel()
	widget := &tray.Widget{URL: strings.Replace(url, "/?t=", "/widget?t=", 1), ProfilePath: abs(filepath.Join(".runtime", "widget-profile"))}
	defer widget.Close()
	shell := &tray.Shell{}
	shell.Menu = func() []tray.MenuItem {
		return []tray.MenuItem{
			{ID: cmdShow, Label: "Show GameBond", Enabled: true},
			{ID: cmdDashboard, Label: "Open web dashboard", Enabled: true},
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
	show := func() {
		if err := widget.Show(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	toggle := func() {
		command := "restart"
		if sample()["state"] == "running" {
			command = "stop"
		}
		go func() {
			if _, err := control(command); err != nil {
				fmt.Fprintln(os.Stderr, "connection action:", err)
			}
		}()
	}
	shell.OnDefault = show
	shell.OnReady = func() {
		if !*trayOnly {
			show()
		}
	}
	shell.OnCommand = func(id int) {
		switch id {
		case cmdShow:
			show()
		case cmdDashboard, cmdApps, cmdNetworks, cmdLinks:
			open()
		case cmdToggle:
			toggle()
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
			show()
		}
		if model.Update(sample(), busy.Load(), "") {
			shell.SetIcon(model.Color, model.Title)
			if lastColor != "" && lastColor != model.Color {
				shell.Balloon("GameBond", model.Title)
			}
			lastColor = model.Color
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
