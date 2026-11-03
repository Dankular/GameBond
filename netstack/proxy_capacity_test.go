package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestProxyKeepsNewConnectionsWorkingAlongsideIdleConnections(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		done <- serveProxyConnections(listener, func(conn net.Conn) {
			conn.Write([]byte{1})
			io.Copy(io.Discard, conn)
		})
	}()
	// Keep all earlier sockets open, like idle browser and streaming sockets.
	for i := 0; i < 96; i++ {
		conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var response [1]byte
		if _, err := io.ReadFull(conn, response[:]); err != nil {
			t.Fatalf("connection %d rejected while earlier sockets remain idle: %v", i+1, err)
		}
	}
	listener.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accept loop did not stop")
	}
}
