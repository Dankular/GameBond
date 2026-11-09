// Package atomicio is the Go port of gamebond/atomic_io.py: bounded state-file
// reads that never block an atomic rename, and replace-with-retry on Windows.
package atomicio

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// DefaultLimit is Python's 4 MiB state-file bound.
const DefaultLimit = 4 * 1024 * 1024

// ErrTooLarge is returned when a state file exceeds its limit.
var ErrTooLarge = errors.New("State file exceeds its size limit")

// ReadBytesShared reads at most limit bytes (4 MiB when limit <= 0). On
// Windows the file is opened with FILE_SHARE_DELETE so polling readers do not
// block a writer's atomic rename.
func ReadBytesShared(path string, limit int) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultLimit
	}
	f, err := openShared(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, ErrTooLarge
	}
	return data, nil
}

// ReadJSONShared decodes a state file, ignoring a UTF-8 BOM like utf-8-sig.
func ReadJSONShared(path string, limit int, v any) error {
	data, err := ReadBytesShared(path, limit)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}), v)
}

// WriteFileAtomic writes data to a temp file beside dst and replaces dst.
func WriteFileAtomic(dst string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(dirOf(dst), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	os.Chmod(name, perm)
	if err := ReplaceFile(name, dst, 0); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func dirOf(p string) string { return filepath.Dir(p) }
