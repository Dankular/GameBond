// Package status writes the runtime status file the control tooling and GUI
// read (.runtime/userspace-status.json). Writes are atomic: a reader sees the
// previous or the next complete document, never a partial one.
package status

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// WriteJSON atomically replaces path with the JSON encoding of v.
func WriteJSON(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var tag [4]byte
	if _, err = rand.Read(tag[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), filepath.Base(path)+".tmp-"+hex.EncodeToString(tag[:]))
	if err = os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	// Rename replaces on Windows and POSIX. Windows refuses while a reader or a
	// concurrent replace holds the target, so retry briefly.
	for attempt := 0; ; attempt++ {
		if err = os.Rename(tmp, path); err == nil {
			return nil
		}
		if attempt >= 40 {
			os.Remove(tmp)
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
}
