// Package status writes the runtime status file the control tooling and GUI
// read (.runtime/userspace-status.json). Writes are atomic: a reader sees the
// previous or the next complete document, never a partial one.
package status

import (
	"encoding/json"
	"gamebond.local/nativeedge/atomicio"
	"sync"
)

// writeMu serialises writers inside this process: two concurrent ReplaceFileW calls on
// the same target can fail with ERROR_UNABLE_TO_MOVE_REPLACEMENT and strand a ~RF backup.
var writeMu sync.Mutex

// WriteJSON atomically replaces path with the JSON encoding of v.
func WriteJSON(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	// ReplaceFile retries while Windows readers hold the target.
	return atomicio.WriteFileAtomic(path, raw, 0o600)
}
