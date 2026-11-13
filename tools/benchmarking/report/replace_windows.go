//go:build windows

package report

import (
	"errors"
	"os"
)

// Windows does not replace an existing path with os.Rename. --force explicitly
// permits replacement, so remove the destination before renaming the completed
// temporary file. Replacement is not atomic on Windows.
func replaceFile(source, destination string) error {
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}
