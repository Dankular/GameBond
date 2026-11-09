//go:build !windows

package uplink

import "errors"

func Adapters() ([]Adapter, error) {
	return nil, errors.New("adapter selection requires Windows")
}
