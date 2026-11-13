module gamebond.local/netstack

go 1.26.0

require golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)

require github.com/Dankular/GameBond.Core v0.1.17

replace gamebond.local/nativeedge => ../native-edge
