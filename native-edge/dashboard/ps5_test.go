package dashboard

import "testing"

func TestPS5IdentificationRequiresUSBHardwareBrandAndExcludesUplinks(t *testing.T) {
	rows := []Adapter{{ID: spareGUID, Index: 30, Name: "UGREEN renamed alias"}}
	usb := USBNetworkDevice{ID: spareGUID, PNP: `USB\VID_1234\ABC`, Description: "USB GbE", Manufacturer: "Realtek"}
	check := func(h USBNetworkDevice, ids []string, indices []int, count int, confirmed bool) {
		t.Helper()
		got := ps5Adapters(rows, []USBNetworkDevice{h}, ids, indices)
		if len(got) != count || (count > 0 && got[0].Confirmed != confirmed) {
			t.Fatalf("unexpected identification: %+v", got)
		}
	}
	check(usb, nil, nil, 1, false) // A renamed alias cannot establish the brand.
	usb.Parent = "UGREEN USB Ethernet"
	check(usb, nil, nil, 1, true)
	check(usb, []string{spareGUID}, nil, 0, false)
	check(usb, nil, []int{30}, 0, false)
	rows[0].Gateway = "192.168.1.1"
	check(usb, nil, nil, 0, false)
	rows[0].Gateway = ""
	usb.PNP = `PCI\VEN_1234`
	check(usb, nil, nil, 0, false)
}
