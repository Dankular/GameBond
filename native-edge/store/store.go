// Package store opens the client's SQLite database. The driver is pure Go (no cgo), so the Windows
// build needs no C toolchain. Settings keep memory small and writes cheap: WAL with synchronous
// NORMAL (a crash loses at most the last transactions, never corrupts), a small page cache, no
// memory map, and one connection per process, so a process never holds more than one cache.
package store

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Open opens (creating if needed) the database at path and applies steps in order: step i runs once,
// inside a transaction, when the file's user_version is below i+1. Steps are only ever appended.
func Open(path string, steps []string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	q := url.Values{}
	for _, p := range []string{"journal_mode(WAL)", "busy_timeout(5000)", "synchronous(NORMAL)", "cache_size(-1024)", "mmap_size(0)", "foreign_keys(1)"} {
		q.Add("_pragma", p)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db, steps); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB, steps []string) error {
	var have int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&have); err != nil {
		return err
	}
	if have > len(steps) {
		return fmt.Errorf("store: database is version %d, this build knows %d", have, len(steps))
	}
	for i := have; i < len(steps); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(steps[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
