package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

var frameLock sync.Mutex

// Private child-process IPC: endpoint byte, uint16 length, then one IP packet.
// Endpoints 0/1 carry packets; endpoint 2 carries the test phase marker.
func writeFrame(endpoint byte, packet []byte) error {
	if len(packet) == 0 || len(packet) > 65535 {
		return fmt.Errorf("invalid frame length")
	}
	frameLock.Lock()
	defer frameLock.Unlock()
	frame := make([]byte, 3+len(packet))
	frame[0] = endpoint
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(packet)))
	copy(frame[3:], packet)
	_, err := io.Copy(os.Stdout, bytes.NewReader(frame))
	return err
}

func bridgeDevices(devices ...tun.Device) {
	for index, device := range devices {
		go func(index int, device tun.Device) {
			buffer, sizes := make([]byte, 65535), make([]int, 1)
			for {
				count, err := device.Read([][]byte{buffer}, sizes, 0)
				if err != nil {
					return
				}
				if count == 1 {
					if err := writeFrame(byte(index), buffer[:sizes[0]]); err != nil {
						return
					}
				}
			}
		}(index, device)
	}
	go func() {
		// One large buffered reader: the pipe's own buffer is a few KB, so reading a
		// header and a payload per packet straight from it made two system calls per
		// packet and let the writer block whenever this loop was descheduled.
		in := bufio.NewReaderSize(os.Stdin, 1<<20)
		for {
			var header [3]byte
			if _, err := io.ReadFull(in, header[:]); err != nil {
				return
			}
			length := int(binary.BigEndian.Uint16(header[1:]))
			if header[0] == 3 {
				if length < 2 || length > 4096 {
					return
				}
				packet := make([]byte, length)
				if _, err := io.ReadFull(in, packet); err != nil {
					return
				}
				handleControlFrame(packet)
				continue
			}
			if int(header[0]) >= len(devices) || length < 20 || length > 1280 {
				return
			}
			packet := make([]byte, length)
			if _, err := io.ReadFull(in, packet); err != nil {
				return
			}
			if _, err := devices[header[0]].Write([][]byte{packet}, 0); err != nil {
				return
			}
		}
	}()
}
