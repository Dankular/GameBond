//go:build !windows

package dashboard

import "errors"

func discoverAdapters() ([]Adapter, error) {
	return nil, errors.New("adapter selection requires Windows")
}
