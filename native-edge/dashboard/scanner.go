package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"gamebond.local/nativeedge/scanner"
)

type scanController struct {
	mu           sync.Mutex
	job          *scanner.DiscoveryJob
	finished     chan struct{}
	closed       bool
	inventoryMu  sync.Mutex
	inventory    scanner.Inventory
	readAt       time.Time
	history      *scanner.History
	historyError string
}

func copyScanInventory(inv scanner.Inventory) scanner.Inventory {
	inv.Adapters = append([]scanner.Adapter{}, inv.Adapters...)
	inv.Devices = append([]scanner.Device{}, inv.Devices...)
	return inv
}

func (s *Server) scanInventory(force bool) (scanner.Inventory, error) {
	c := &s.scan
	c.inventoryMu.Lock()
	defer c.inventoryMu.Unlock()
	if !force && !c.readAt.IsZero() && time.Since(c.readAt) < 5*time.Second {
		return copyScanInventory(c.inventory), nil
	}
	read := s.o.ScanInventory
	if read == nil {
		read = scannerInventory
	}
	inv, err := read()
	if err != nil {
		return scanner.Inventory{}, err
	}
	if c.history == nil {
		path := ""
		if s.o.RootPath != "" {
			path = filepath.Join(s.o.RootPath, ".runtime", "scanner-history.json")
		}
		c.history, err = scanner.OpenHistory(path, 4096)
		if err != nil {
			return scanner.Inventory{}, err
		}
	}
	inv.Devices, err = c.history.Observe(inv.Devices, inv.ObservedAt)
	if err != nil {
		return scanner.Inventory{}, err
	}
	c.inventory, c.readAt = copyScanInventory(inv), time.Now()
	return inv, nil
}

func (s *Server) scannerAPI(w http.ResponseWriter, r *http.Request) {
	c := &s.scan
	switch r.Method {
	case http.MethodGet:
		// Job polling never runs PowerShell or writes history.
		if r.URL.Query().Get("job") == "1" {
			c.mu.Lock()
			defer c.mu.Unlock()
			var snapshot any
			if c.job != nil {
				snapshot = c.job.Snapshot()
			}
			c.inventoryMu.Lock()
			historyError := c.historyError
			c.inventoryMu.Unlock()
			reply(w, 200, map[string]any{"job": snapshot, "history_error": historyError})
			return
		}
		inv, err := s.scanInventory(r.URL.Query().Get("refresh") == "1")
		if err != nil {
			reply(w, 503, map[string]any{"error": err.Error()})
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		var snapshot any
		if c.job != nil {
			snapshot = c.job.Snapshot()
		}
		reply(w, 200, map[string]any{"inventory": inv, "job": snapshot})
	case http.MethodPost:
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		var req struct {
			Action string `json:"action"`
			Subnet string `json:"subnet"`
			Source string `json:"source"`
			Index  int    `json:"interface_index"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err != nil || len(raw) > maxBody || !json.Valid(raw) || decoder.Decode(&req) != nil {
			reply(w, 422, map[string]any{"error": "invalid scanner request"})
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed {
			reply(w, 503, map[string]any{"error": "scanner is closing"})
			return
		}
		if req.Action == "cancel" {
			if c.job != nil {
				c.job.Cancel()
			}
			reply(w, 200, map[string]any{"state": "cancelling"})
			return
		}
		if req.Action != "start" {
			reply(w, 422, map[string]any{"error": "choose start or cancel"})
			return
		}
		if c.job != nil && c.job.Snapshot().State == "running" {
			reply(w, 409, map[string]any{"error": "a discovery job is already running"})
			return
		}
		if c.finished != nil {
			<-c.finished
		}
		probe := s.o.ScanProbe
		if probe == nil {
			probe = scannerProbe
		}
		revalidate := func() ([]scanner.Adapter, error) {
			inv, err := s.scanInventory(true)
			return inv.Adapters, err
		}
		job, err := scanner.NewDiscoveryJob(req.Subnet, req.Source, req.Index, nil, revalidate, 8, 300, 256, probe)
		if err == nil {
			err = job.Start(false)
		}
		if err != nil {
			reply(w, 422, map[string]any{"error": err.Error()})
			return
		}
		c.job = job
		c.finished = make(chan struct{})
		done := c.finished
		go func() { defer close(done); s.finishScan(job) }()
		reply(w, 202, map[string]any{"job": job.Snapshot()})
	default:
		reply(w, 405, map[string]any{"error": "method not allowed"})
	}
}

func (s *Server) finishScan(job *scanner.DiscoveryJob) {
	job.Wait()
	// Record responsive hosts even if Windows has not populated the ARP cache.
	c := &s.scan
	c.inventoryMu.Lock()
	defer c.inventoryMu.Unlock()
	if c.history == nil {
		return
	}
	rows := []scanner.Device{}
	now := scanner.Now()
	for _, result := range job.Snapshot().Results {
		if result.Responded {
			row := scanner.Device{InterfaceIndex: job.InterfaceIndex, Address: result.Address, State: "Reachable", Source: "icmp", ReachableNow: true}
			for _, old := range c.inventory.Devices {
				if old.InterfaceIndex == row.InterfaceIndex && old.Address == row.Address {
					row.MAC = old.MAC
					break
				}
			}
			rows = append(rows, row)
		}
	}
	observed, err := c.history.Observe(rows, now)
	if err != nil {
		c.historyError = err.Error()
		return
	}
	c.historyError = ""
	for _, row := range observed {
		found := false
		for i, old := range c.inventory.Devices {
			if old.InterfaceIndex == row.InterfaceIndex && old.Address == row.Address {
				c.inventory.Devices[i].ReachableNow = true
				c.inventory.Devices[i].FirstSeen = row.FirstSeen
				c.inventory.Devices[i].LastSeen = row.LastSeen
				found = true
				break
			}
		}
		if !found {
			c.inventory.Devices = append(c.inventory.Devices, row)
		}
	}
}

var errScannerUnsupported = errors.New("network discovery is not available on this platform")
