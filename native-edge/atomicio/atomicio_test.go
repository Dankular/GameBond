package atomicio

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReadLimitAndBOM(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "s.json")
	os.WriteFile(p, append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"a": 1}`)...), 0o600)
	var v map[string]int
	if err := ReadJSONShared(p, 0, &v); err != nil || v["a"] != 1 {
		t.Fatalf("%v %v", v, err)
	}
	os.WriteFile(p, bytes.Repeat([]byte("x"), 11), 0o600)
	if _, err := ReadBytesShared(p, 10); err != ErrTooLarge {
		t.Fatalf("limit+1 must fail, got %v", err)
	}
	if b, err := ReadBytesShared(p, 11); err != nil || len(b) != 11 {
		t.Fatalf("exact limit must pass: %v", err)
	}
	if _, err := ReadBytesShared(filepath.Join(d, "none"), 0); err == nil {
		t.Fatal("missing file read")
	}
}

// Readers polling while a writer replaces the file must neither fail the
// replace nor ever see a partial document.
func TestReplaceWhileReading(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if err := WriteFileAtomic(p, []byte(`{"n": 0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	bad := make(chan error, 1)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				var v map[string]int
				if err := ReadJSONShared(p, 0, &v); err != nil && !os.IsNotExist(err) { // ReplaceFileW has a short no-file window, as in Python
					select {
					case bad <- err:
					default:
					}
					return
				}
			}
		}()
	}
	for i := 1; i <= 300; i++ {
		if err := WriteFileAtomic(p, []byte(`{"n": `+string(rune('0'+i%10))+`}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-bad:
		t.Fatalf("reader saw %v", err)
	default:
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("temp files left: %d", len(ents))
	}
}
