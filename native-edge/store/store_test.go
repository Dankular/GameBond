package store

import (
	"path/filepath"
	"testing"
)

func TestOpenMigratesOnceAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "t.db")
	steps := []string{`CREATE TABLE a(x INTEGER)`, `ALTER TABLE a ADD COLUMN y TEXT`}
	db, err := Open(path, steps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO a(x,y) VALUES (1,'k')`); err != nil {
		t.Fatal(err)
	}
	var mode string
	if err = db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal mode %q %v", mode, err)
	}
	db.Close()
	db, err = Open(path, steps)
	if err != nil {
		t.Fatal(err)
	}
	var y string
	if err = db.QueryRow(`SELECT y FROM a`).Scan(&y); err != nil || y != "k" {
		t.Fatalf("%q %v", y, err)
	}
	db.Close()
	if _, err = Open(path, steps[:1]); err == nil {
		t.Fatal("an older build opened a newer database")
	}
}
