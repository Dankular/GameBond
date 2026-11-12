//go:build windows

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"gamebond.local/nativeedge/client"
	"gamebond.local/nativeedge/uplink"
)

// startDriverHealth polls the Windows Packet Filter driver service and every adapter the
// tunnel depends on once a second and journals only changes: driver stopped, link down or
// cable out, adapter gone, and growth of the adapter's error or discard counters. The
// outage journal then shows whether a stall began in a driver rather than in a line.
func startDriverHealth(ctx context.Context, c *client.Client, adapterIDs []string) {
	want := map[string]bool{}
	var ids []string
	for _, id := range adapterIDs {
		k := strings.ToLower(strings.Trim(id, "{} "))
		if k != "" && !want[k] {
			want[k] = true
			ids = append(ids, k)
		}
	}
	type nic struct {
		name  string
		index int
	}
	known := map[string]nic{}
	prev := map[string]uint64{}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		ok, note := packetFilterState()
		c.NoteComponent("drv:ndisrd", ok, note)
		if n%5 == 0 { // adapter indexes change on re-plug; refresh the table every 5 s
			if rows, err := uplink.Adapters(); err == nil {
				known = map[string]nic{}
				for _, a := range rows {
					known[strings.ToLower(strings.Trim(a.ID, "{} "))] = nic{a.Name, a.Index}
				}
			}
		}
		for _, id := range ids {
			a, found := known[id]
			if !found {
				short := id
				if len(short) > 8 {
					short = short[:8]
				}
				c.NoteComponent("nic:"+short, false, "adapter_missing")
				continue
			}
			src := "nic:" + a.name
			row := windows.MibIfRow2{InterfaceIndex: uint32(a.index)}
			if err := windows.GetIfEntry2Ex(0, &row); err != nil {
				c.NoteComponent(src, false, "query_failed")
				continue
			}
			switch {
			case row.OperStatus != 1:
				c.NoteComponent(src, false, "oper_down")
			case row.MediaConnectState == 2:
				c.NoteComponent(src, false, "no_media")
			default:
				c.NoteComponent(src, true, "")
			}
			errs := row.InErrors + row.OutErrors + row.InDiscards + row.OutDiscards
			if last, seen := prev[id]; seen && errs > last {
				c.NoteComponentError(src, fmt.Sprintf("+%d err/drop", errs-last))
			}
			prev[id] = errs // a counter reset (adapter restart) just rebaselines
		}
	}
}

// packetFilterState reports whether the Windows Packet Filter driver service is running.
// Only query rights are requested, so it works without elevation.
func packetFilterState() (bool, string) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return true, "" // cannot ask; do not invent a failure
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString("ndisrd")
	h, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false, "not_installed"
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &st); err != nil {
		return false, "query_failed"
	}
	if st.CurrentState == windows.SERVICE_RUNNING {
		return true, ""
	}
	return false, fmt.Sprintf("state_%d", st.CurrentState)
}
