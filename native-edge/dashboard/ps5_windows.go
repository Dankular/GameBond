package dashboard

import (
	"context"
	"encoding/json"
	"os/exec"
	"syscall"
	"time"
)

// This read-only query runs only when opening/refreshing Connected devices.
// Some branded adapters expose their brand only on the parent USB device.
func discoverUSBNetworkDevices() ([]USBNetworkDevice, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	const script = `$ErrorActionPreference='Stop'; $result=@(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PNPDeviceID -like 'USB\*' } | ForEach-Object {
 $parts=@(); $instance=$_.PNPDeviceID
 for($i=0;$i -lt 4 -and $instance;$i++) {
  foreach($key in @('DEVPKEY_Device_Manufacturer','DEVPKEY_Device_BusReportedDeviceDesc')) {
   $v=Get-PnpDeviceProperty -InstanceId $instance -KeyName $key -ErrorAction SilentlyContinue
   if($v.Data) { $parts += [string]$v.Data }
  }
  $instance=(Get-PnpDeviceProperty -InstanceId $instance -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data
  if($instance -notlike 'USB\*') { break }
 }
 [pscustomobject]@{id=$_.GUID;pnp=$_.PNPDeviceID;description=$_.Name;manufacturer=$_.Manufacturer;parent=($parts -join ' ')}
}); ConvertTo-Json -InputObject $result -Compress`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var devices []USBNetworkDevice
	err = json.Unmarshal(raw, &devices)
	return devices, err
}
