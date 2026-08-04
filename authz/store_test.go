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

func TestOpenStoreClearsLegacyIPDataOnEveryStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authz.db")
	database, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 5, 30, 0, 0, time.UTC)
	if err := database.seed(t.Context(), nil, []string{"viewer@example.com"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(t.Context(), `
UPDATE users SET last_ip = '10.1.2.3' WHERE email = 'viewer@example.com';
INSERT INTO access_events(email, outcome, ip, created_at)
VALUES('viewer@example.com', 'allowed', '10.1.2.3', ?);
INSERT INTO audit_events(actor_email, target_email, action, ip, created_at)
VALUES('admin@example.com', 'viewer@example.com', 'add', '10.1.2.3', ?);`, now.Unix(), now.Unix()); err != nil {
		t.Fatalf("write legacy IP data: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = openStore(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer database.Close()
	assertNoStoredIPData(t, database)

	if err := database.migrate(t.Context()); err != nil {
		t.Fatalf("repeat migrate: %v", err)
	}
	assertNoStoredIPData(t, database)
}

func assertNoStoredIPData(t *testing.T, database *store) {
	t.Helper()
	for _, query := range []string{
		"SELECT COUNT(*) FROM users WHERE last_ip <> ''",
		"SELECT COUNT(*) FROM access_events WHERE ip <> ''",
		"SELECT COUNT(*) FROM audit_events WHERE ip <> ''",
	} {
		var count int
		if err := database.db.QueryRowContext(t.Context(), query).Scan(&count); err != nil {
			t.Fatalf("query stored IP data with %q: %v", query, err)
		}
		if count != 0 {
			t.Fatalf("stored IP rows for %q = %d, want 0", query, count)
		}
	}
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
