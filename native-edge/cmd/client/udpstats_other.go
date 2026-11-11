//go:build !windows

package main

func osUDPReceiveErrors() (uint64, bool) { return 0, false }
