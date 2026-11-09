//go:build windows

package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const inventoryScript = `
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$links=@(Get-NetAdapter | Select-Object Name,ifIndex,Status,MacAddress,InterfaceDescription)
$addresses=@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
 Where-Object {$_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*'} |
 Select-Object -First 129 |
 ForEach-Object {
  $ip=$_;$adapter=$links | Where-Object {$_.ifIndex -eq $ip.InterfaceIndex} | Select-Object -First 1
  [pscustomobject]@{index=[int]$ip.InterfaceIndex;name=$ip.InterfaceAlias;address=$ip.IPAddress;
   prefix_length=[int]$ip.PrefixLength;up=($adapter.Status -eq 'Up');mac=$adapter.MacAddress;
   description=$adapter.InterfaceDescription}
 })
$neighbors=@(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
 Select-Object -First 4097 |
 Select-Object @{n='interface_index';e={[int]$_.InterfaceIndex}},
 @{n='address';e={$_.IPAddress}},@{n='mac';e={$_.LinkLayerAddress}},@{n='state';e={$_.State.ToString()}})
ConvertTo-Json -InputObject ([pscustomobject]@{adapters=$addresses;neighbors=$neighbors}) -Depth 5 -Compress
`

// TakeInventory reads adapters and the neighbor cache through PowerShell
// (passive; nothing is sent on the LAN).
func TakeInventory() (Inventory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", inventoryScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.Output()
	if err != nil {
		return Inventory{}, errors.New("Windows could not enumerate local adapters and neighbors")
	}
	out = bytes.TrimPrefix(out, []byte{0xEF, 0xBB, 0xBF})
	var rec RawRecord
	if err := json.Unmarshal(out, &rec); err != nil {
		return Inventory{}, fmt.Errorf("invalid network inventory: %w", err)
	}
	return Normalize(rec, Now()), nil
}

var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose    = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho = iphlpapi.NewProc("IcmpSendEcho2Ex")
)

// ICMPProbe sends one echo from an explicit local source address.
func ICMPProbe(source, target string, timeoutMS int) (ProbeResult, error) {
	if timeoutMS < 50 || timeoutMS > 1500 {
		return ProbeResult{}, errors.New("Discovery timeout must be 50..1500 milliseconds")
	}
	src, err := netip.ParseAddr(source)
	if err != nil || !src.Is4() {
		return ProbeResult{}, fmt.Errorf("invalid source %q", source)
	}
	dst, err := netip.ParseAddr(target)
	if err != nil || !dst.Is4() {
		return ProbeResult{}, fmt.Errorf("invalid target %q", target)
	}
	h, _, e := procIcmpCreate.Call()
	if h == 0 || h == ^uintptr(0) {
		return ProbeResult{}, e
	}
	defer procIcmpClose.Call(h)
	request := []byte("GameBond discovery")
	reply := make([]byte, 512)
	s, d := src.As4(), dst.As4()
	n, _, callErr := procIcmpSendEcho.Call(h, 0, 0, 0,
		uintptr(binary.LittleEndian.Uint32(s[:])), uintptr(binary.LittleEndian.Uint32(d[:])),
		uintptr(unsafe.Pointer(&request[0])), uintptr(len(request)), 0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeoutMS))
	if n == 0 {
		code := 0
		if en, ok := callErr.(syscall.Errno); ok {
			code = int(en)
		}
		return ProbeResult{Address: target, Status: code}, nil
	}
	from := reply[0:4]
	status := binary.LittleEndian.Uint32(reply[4:8])
	rtt := int(binary.LittleEndian.Uint32(reply[8:12]))
	res := ProbeResult{Address: target, Status: int(status), Responded: status == 0 && netip.AddrFrom4([4]byte{from[0], from[1], from[2], from[3]}) == dst}
	if status == 0 {
		res.RTTMS = &rtt
	}
	return res, nil
}
