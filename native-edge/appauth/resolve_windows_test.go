//go:build windows

package appauth

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func ownFiletime(t *testing.T) int64 {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		t.Fatal(err)
	}
	return int64(c.HighDateTime)<<32 | int64(c.LowDateTime)
}

func TestResolveProcessOwnGeneration(t *testing.T) {
	ft := ownFiletime(t)
	id := ResolveProcess(int64(os.Getpid()), strconv.FormatInt(ft, 10))
	if id == nil {
		t.Fatal("own process not resolved")
	}
	if !strings.HasSuffix(strings.ToLower(id["path"].(string)), ".exe") || id["pid"] != int64(os.Getpid()) ||
		id["created_filetime"] != strconv.FormatInt(ft, 10) || !strings.HasSuffix(strings.ToLower(id["path"].(string)), strings.ToLower(id["name"].(string))) {
		t.Fatalf("%v", id)
	}
	// a different creation time is a different generation of the PID
	if ResolveProcess(int64(os.Getpid()), strconv.FormatInt(ft+20_000, 10)) != nil { // +2 ms
		t.Error("a different creation time resolved")
	}
	if ResolveProcess(int64(os.Getpid()), strconv.FormatInt(ft+5_000, 10)) == nil { // +0.5 ms is within tolerance
		t.Error("within 1 ms tolerance rejected")
	}
	for _, bad := range []struct {
		pid int64
		ft  string
	}{{0, "133"}, {-1, "133"}, {int64(os.Getpid()), "x"}, {int64(os.Getpid()), "116444736000000000"}, {int64(os.Getpid()), ""}, {1 << 40, "133000000000000000"}} {
		if ResolveProcess(bad.pid, bad.ft) != nil {
			t.Errorf("%v resolved", bad)
		}
	}
}
