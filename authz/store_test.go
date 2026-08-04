package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInitialViewersAreImportedOnlyOnTheFirstEmptyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authz.db")
	database, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 5, 0, 0, 0, time.UTC)
	admins := map[string]struct{}{"admin@example.com": {}}
	if err := database.seed(t.Context(), admins, []string{"first@example.com"}, now); err != nil {
		t.Fatal(err)
	}
	if err := database.seed(t.Context(), admins, []string{"second@example.com"}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.userByEmail(t.Context(), "first@example.com"); err != nil {
		t.Fatalf("first viewer missing: %v", err)
	}
	if _, err := database.userByEmail(t.Context(), "second@example.com"); err == nil {
		t.Fatal("second seed unexpectedly imported a new initial viewer")
	}
	_ = database.Close()
}

func TestOnlineBackupIsReadableAndOldBackupsArePruned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authz.db")
	database, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 8, 4, 6, 0, 0, 0, time.UTC)
	admins := map[string]struct{}{"admin@example.com": {}}
	if err := database.seed(t.Context(), admins, []string{"viewer@example.com"}, now); err != nil {
		t.Fatal(err)
	}
	backupDir := t.TempDir()
	oldBackup := filepath.Join(backupDir, "authz-20260101-000000.db")
	if err := os.WriteFile(oldBackup, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := now.Add(-31 * 24 * time.Hour)
	if err := os.Chtimes(oldBackup, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	backupPath, err := database.backup(context.Background(), backupDir, now, 30)
	if err != nil {
		t.Fatalf("backup() error = %v", err)
	}
	if _, err := os.Stat(oldBackup); !os.IsNotExist(err) {
		t.Fatalf("old backup was not pruned, stat error = %v", err)
	}
	backupDatabase, err := openStore(backupPath)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer backupDatabase.Close()
	if _, err := backupDatabase.userByEmail(t.Context(), "viewer@example.com"); err != nil {
		t.Fatalf("viewer missing from backup: %v", err)
	}
}
