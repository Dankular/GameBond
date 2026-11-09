// Package status writes the runtime status file the control tooling and GUI
// read (.runtime/userspace-status.json). Writes are atomic: a reader sees the
// previous or the next complete document, never a partial one.
package status

import (
	"encoding/json"
	"gamebond.local/nativeedge/atomicio"
)

// WriteJSON atomically replaces path with the JSON encoding of v.
func WriteJSON(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	// ReplaceFile retries while Windows readers hold the target.
	return atomicio.WriteFileAtomic(path, raw, 0o600)
}
