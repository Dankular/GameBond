package main

import (
	"errors"
	"sync/atomic"
	"testing"
)

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return 2, errors.New("short write") }

func TestApplicationCountersOnlyCountSuccessfullyWrittenBytes(t *testing.T) {
	var count atomic.Uint64
	n, err := (countedWriter{shortWriter{}, &count}).Write([]byte("payload"))
	if n != 2 || err == nil || count.Load() != 2 {
		t.Fatalf("n=%d err=%v count=%d", n, err, count.Load())
	}
}
