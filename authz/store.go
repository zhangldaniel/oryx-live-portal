package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	errNotFound      = errors.New("not found")
	errProtectedUser = errors.New("administrator is protected")
	errInactiveUser  = errors.New("inactive user cannot become administrator")
)

type store struct {
	db *sql.DB
}

func openStore(dbPath string) (*store, error) {
	if dbPath != ":memory:" {
		directory := filepath.Dir(dbPath)
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// A single connection keeps per-connection SQLite pragmas deterministic and
	// is ample for this single-instance, low-volume authorization service.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	for _, statement := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("configure sqlite (%s): %w", statement, err)
		}
	}

	s := &store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *store) Close() error {
	return s.db.Close()
}

func (s *store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'archived')),
    expires_at INTEGER,
    first_seen_at INTEGER,
    last_seen_at INTEGER,
    last_ip TEXT NOT NULL DEFAULT '',
    login_count INTEGER NOT NULL DEFAULT 0 CHECK (login_count >= 0),
    is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS users_status_idx ON users(status);
CREATE INDEX IF NOT EXISTS users_last_seen_idx ON users(last_seen_at);

CREATE TABLE IF NOT EXISTS access_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL COLLATE NOCASE,
    display_name TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied')),
    reason TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    session_hash TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS access_session_outcome_idx
ON access_events(email, session_hash, outcome)
WHERE session_hash <> '';
CREATE INDEX IF NOT EXISTS access_created_idx ON access_events(created_at DESC);
CREATE INDEX IF NOT EXISTS access_outcome_created_idx ON access_events(outcome, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_email TEXT NOT NULL COLLATE NOCASE,
    target_email TEXT NOT NULL COLLATE NOCASE,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_events(created_at DESC);

-- Keep the legacy columns for downgrade compatibility, but never retain their
-- values. These statements intentionally run on every startup so an older
-- release cannot reintroduce stored IP data across a rollback and re-upgrade.
UPDATE users SET last_ip = '' WHERE last_ip <> '';
UPDATE access_events SET ip = '' WHERE ip <> '';
UPDATE audit_events SET ip = '' WHERE ip <> '';
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	return nil
}

func (s *store) seed(ctx context.Context, admins map[string]struct{}, initialViewers []string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin seed transaction: %w", err)
	}
	defer tx.Rollback()

	var seeded string
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key = ?", "initial_seed_complete").Scan(&seeded)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read seed marker: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
			return fmt.Errorf("count users before seed: %w", err)
		}
		if count == 0 {
			for _, email := range initialViewers {
				if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO users(email, status, created_at, updated_at)
VALUES(?, 'active', ?, ?)`, email, now.Unix(), now.Unix()); err != nil {
					return fmt.Errorf("seed viewer %s: %w", email, err)
				}
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO metadata(key, value) VALUES(?, ?)", "initial_seed_complete", formatUnix(now.Unix())); err != nil {
			return fmt.Errorf("write seed marker: %w", err)
		}
	}

	for email := range admins {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO users(email, status, is_admin, created_at, updated_at)
VALUES(?, 'active', 1, ?, ?)
ON CONFLICT(email) DO UPDATE SET
	status = 'active', is_admin = 1, updated_at = excluded.updated_at`,
			email, now.Unix(), now.Unix()); err != nil {
			return fmt.Errorf("synchronize administrator %s: %w", email, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit seed transaction: %w", err)
	}
	return nil
}

func (s *store) health(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *store) authorizeViewer(ctx context.Context, email string) (userRecord, bool, string, error) {
	user, err := s.userByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return userRecord{}, false, "not_authorized", nil
	}
	if err != nil {
		return userRecord{}, false, "database_error", err
	}
	if user.Status == statusDisabled {
		return user, false, "disabled", nil
	}
	if user.Status == statusArchived {
		return user, false, "archived", nil
	}
	return user, true, "", nil
}

func (s *store) userByEmail(ctx context.Context, email string) (userRecord, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, email, display_name, status, first_seen_at, last_seen_at,
       login_count, is_admin, created_at, updated_at
FROM users WHERE email = ?`, email)
	return scanUser(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (userRecord, error) {
	var user userRecord
	var isAdmin int
	err := row.Scan(
		&user.ID, &user.Email, &user.DisplayName, &user.Status,
		&user.FirstSeenAt, &user.LastSeenAt, &user.LoginCount,
		&isAdmin, &user.CreatedAt, &user.UpdatedAt,
	)
	user.IsAdmin = isAdmin == 1
	return user, err
}

func (s *store) recordDecision(ctx context.Context, subject identity, outcome, reason, sessionHash string, now time.Time, throttle time.Duration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin access transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO access_events(email, display_name, outcome, reason, session_hash, created_at)
VALUES(?, ?, ?, ?, ?, ?)`,
		subject.Email, subject.DisplayName, outcome, reason, sessionHash, now.Unix())
	if err != nil {
		return fmt.Errorf("write access event: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read access insert result: %w", err)
	}

	if outcome == outcomeAllowed {
		loginIncrement := int64(0)
		if inserted > 0 {
			loginIncrement = 1
		}
		cutoff := now.Add(-throttle).Unix()
		result, err := tx.ExecContext(ctx, `
UPDATE users SET
    display_name = CASE WHEN ? <> '' THEN ? ELSE display_name END,
    first_seen_at = COALESCE(first_seen_at, ?),
    last_seen_at = CASE WHEN last_seen_at IS NULL OR last_seen_at <= ? THEN ? ELSE last_seen_at END,
    login_count = login_count + ?,
    updated_at = CASE WHEN last_seen_at IS NULL OR last_seen_at <= ? OR ? > 0 THEN ? ELSE updated_at END
WHERE email = ?`,
			subject.DisplayName, subject.DisplayName, now.Unix(), cutoff, now.Unix(),
			loginIncrement, cutoff, loginIncrement, now.Unix(), subject.Email)
		if err != nil {
			return fmt.Errorf("update viewer activity: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read viewer activity result: %w", err)
		}
		if rows == 0 {
			return fmt.Errorf("record allowed access for missing user %s", subject.Email)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit access transaction: %w", err)
	}
	return nil
}

func (s *store) overview(ctx context.Context, now time.Time, onlineWindow time.Duration) (overviewResponse, error) {
	var result overviewResponse
	err := s.db.QueryRowContext(ctx, `
SELECT
	SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END),
	SUM(CASE WHEN status = 'disabled' THEN 1 ELSE 0 END),
	SUM(CASE WHEN status = 'active' AND last_seen_at >= ? THEN 1 ELSE 0 END)
FROM users`, now.Add(-onlineWindow).Unix()).Scan(
		&result.Authorized, &result.Disabled, &result.Online,
	)
	if err != nil {
		return overviewResponse{}, fmt.Errorf("query overview users: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM access_events WHERE outcome = 'denied' AND created_at >= ?`, now.Add(-24*time.Hour).Unix()).Scan(&result.DeniedRecent); err != nil {
		return overviewResponse{}, fmt.Errorf("query recent denials: %w", err)
	}
	return result, nil
}

func (s *store) listUsers(ctx context.Context, search, status string, page, pageSize int) (pagedResponse[userResponse], error) {
	where := []string{"1 = 1"}
	args := make([]any, 0, 4)
	if search != "" {
		where = append(where, "(LOWER(email) LIKE ? OR LOWER(display_name) LIKE ?)")
		term := "%" + strings.ToLower(search) + "%"
		args = append(args, term, term)
	}
	switch status {
	case "", "all":
	case "authorized", statusActive:
		where = append(where, "status = 'active'")
	case statusDisabled, statusArchived:
		where = append(where, "status = ?")
		args = append(args, status)
	default:
		return pagedResponse[userResponse]{}, fmt.Errorf("unsupported status filter %q", status)
	}

	condition := strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE "+condition, args...).Scan(&total); err != nil {
		return pagedResponse[userResponse]{}, fmt.Errorf("count users: %w", err)
	}

	queryArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, email, display_name, status, first_seen_at, last_seen_at,
       login_count, is_admin, created_at, updated_at
FROM users WHERE `+condition+`
ORDER BY is_admin DESC, email ASC
LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return pagedResponse[userResponse]{}, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	items := make([]userResponse, 0, pageSize)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return pagedResponse[userResponse]{}, fmt.Errorf("scan user: %w", err)
		}
		items = append(items, userToResponse(user))
	}
	if err := rows.Err(); err != nil {
		return pagedResponse[userResponse]{}, fmt.Errorf("iterate users: %w", err)
	}
	return pagedResponse[userResponse]{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *store) addUsers(ctx context.Context, emails []string, actor string, now time.Time) (addUsersResponse, error) {
	response := addUsersResponse{Results: make([]addUserResult, 0, len(emails))}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return response, fmt.Errorf("begin add users transaction: %w", err)
	}
	defer tx.Rollback()

	for _, email := range emails {
		var existingID int64
		err := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE email = ?", email).Scan(&existingID)
		if err == nil {
			response.Summary.Existing++
			response.Results = append(response.Results, addUserResult{Email: email, Result: "existing"})
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return response, fmt.Errorf("check existing user %s: %w", email, err)
		}

		if _, err := tx.ExecContext(ctx, `
INSERT INTO users(email, status, created_at, updated_at)
VALUES(?, 'active', ?, ?)`, email, now.Unix(), now.Unix()); err != nil {
			return response, fmt.Errorf("add user %s: %w", email, err)
		}
		detail, _ := json.Marshal(map[string]any{"status": "authorized"})
		if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_events(actor_email, target_email, action, detail, created_at)
VALUES(?, ?, 'add', ?, ?)`, actor, email, string(detail), now.Unix()); err != nil {
			return response, fmt.Errorf("audit added user %s: %w", email, err)
		}
		response.Summary.Added++
		response.Results = append(response.Results, addUserResult{Email: email, Result: "added"})
	}

	if err := tx.Commit(); err != nil {
		return response, fmt.Errorf("commit add users transaction: %w", err)
	}
	return response, nil
}

func (s *store) mutateUser(ctx context.Context, id int64, action, actor string, now time.Time, superAdmins map[string]struct{}) (userResponse, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return userResponse{}, fmt.Errorf("begin user mutation: %w", err)
	}
	defer tx.Rollback()

	user, err := scanUser(tx.QueryRowContext(ctx, `
SELECT id, email, display_name, status, first_seen_at, last_seen_at,
       login_count, is_admin, created_at, updated_at
FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return userResponse{}, errNotFound
	}
	if err != nil {
		return userResponse{}, fmt.Errorf("load user for mutation: %w", err)
	}
	newStatus := user.Status
	newIsAdmin := user.IsAdmin
	_, isSuperAdmin := superAdmins[user.Email]
	switch action {
	case "disable":
		if user.IsAdmin || isSuperAdmin {
			return userResponse{}, errProtectedUser
		}
		newStatus = statusDisabled
	case "restore":
		if user.IsAdmin || isSuperAdmin {
			return userResponse{}, errProtectedUser
		}
		newStatus = statusActive
	case "archive":
		if user.IsAdmin || isSuperAdmin {
			return userResponse{}, errProtectedUser
		}
		newStatus = statusArchived
	case "grant_admin":
		if user.Status != statusActive {
			return userResponse{}, errInactiveUser
		}
		newIsAdmin = true
	case "revoke_admin":
		if isSuperAdmin {
			return userResponse{}, errProtectedUser
		}
		newIsAdmin = false
	default:
		return userResponse{}, fmt.Errorf("unsupported action %q", action)
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE users SET status = ?, is_admin = ?, updated_at = ? WHERE id = ?`,
		newStatus, newIsAdmin, now.Unix(), id); err != nil {
		return userResponse{}, fmt.Errorf("update user: %w", err)
	}
	detail, _ := json.Marshal(map[string]any{
		"previousStatus":  userToResponse(user).Status,
		"status":          effectiveStatus(newStatus),
		"previousIsAdmin": user.IsAdmin,
		"isAdmin":         newIsAdmin,
	})
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_events(actor_email, target_email, action, detail, created_at)
VALUES(?, ?, ?, ?, ?)`, actor, user.Email, action, string(detail), now.Unix()); err != nil {
		return userResponse{}, fmt.Errorf("write mutation audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return userResponse{}, fmt.Errorf("commit user mutation: %w", err)
	}

	updated, err := s.userByEmail(ctx, user.Email)
	if err != nil {
		return userResponse{}, fmt.Errorf("reload updated user: %w", err)
	}
	return userToResponse(updated), nil
}

func effectiveStatus(status string) string {
	if status == statusActive {
		return "authorized"
	}
	return status
}

func (s *store) listAccessEvents(ctx context.Context, outcome string, page, pageSize int) (pagedResponse[accessEventResponse], error) {
	where := "1 = 1"
	args := make([]any, 0, 1)
	if outcome != "" {
		if outcome != outcomeAllowed && outcome != outcomeDenied {
			return pagedResponse[accessEventResponse]{}, fmt.Errorf("unsupported outcome %q", outcome)
		}
		where = "outcome = ?"
		args = append(args, outcome)
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM access_events WHERE "+where, args...).Scan(&total); err != nil {
		return pagedResponse[accessEventResponse]{}, fmt.Errorf("count access events: %w", err)
	}
	queryArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, email, display_name, outcome, created_at
FROM access_events WHERE `+where+`
ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return pagedResponse[accessEventResponse]{}, fmt.Errorf("list access events: %w", err)
	}
	defer rows.Close()
	items := make([]accessEventResponse, 0, pageSize)
	for rows.Next() {
		var item accessEventResponse
		var createdAt int64
		if err := rows.Scan(&item.ID, &item.Email, &item.DisplayName, &item.Outcome, &createdAt); err != nil {
			return pagedResponse[accessEventResponse]{}, fmt.Errorf("scan access event: %w", err)
		}
		item.CreatedAt = formatUnix(createdAt)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return pagedResponse[accessEventResponse]{}, fmt.Errorf("iterate access events: %w", err)
	}
	return pagedResponse[accessEventResponse]{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *store) listAuditEvents(ctx context.Context, page, pageSize int) (pagedResponse[auditResponse], error) {
	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events").Scan(&total); err != nil {
		return pagedResponse[auditResponse]{}, fmt.Errorf("count audit events: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, actor_email, target_email, action, detail, created_at
FROM audit_events ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, pageSize, (page-1)*pageSize)
	if err != nil {
		return pagedResponse[auditResponse]{}, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()
	items := make([]auditResponse, 0, pageSize)
	for rows.Next() {
		var item auditResponse
		var createdAt int64
		if err := rows.Scan(&item.ID, &item.ActorEmail, &item.TargetEmail, &item.Action, &item.Detail, &createdAt); err != nil {
			return pagedResponse[auditResponse]{}, fmt.Errorf("scan audit event: %w", err)
		}
		item.CreatedAt = formatUnix(createdAt)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return pagedResponse[auditResponse]{}, fmt.Errorf("iterate audit events: %w", err)
	}
	return pagedResponse[auditResponse]{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *store) cleanupEvents(ctx context.Context, now time.Time, retentionDays int) error {
	cutoff := now.Add(-time.Duration(retentionDays) * 24 * time.Hour).Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin event cleanup: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM access_events WHERE created_at < ?", cutoff); err != nil {
		return fmt.Errorf("clean access events: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM audit_events WHERE created_at < ?", cutoff); err != nil {
		return fmt.Errorf("clean audit events: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit event cleanup: %w", err)
	}
	return nil
}

func (s *store) backup(ctx context.Context, directory string, now time.Time, retentionDays int) (string, error) {
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	filename := filepath.Join(directory, "authz-"+now.UTC().Format("20060102-150405")+".db")
	if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("remove colliding backup: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", filename); err != nil {
		return "", fmt.Errorf("create online sqlite backup: %w", err)
	}
	if err := pruneBackups(directory, now.Add(-time.Duration(retentionDays)*24*time.Hour)); err != nil {
		return filename, err
	}
	return filename, nil
}

func pruneBackups(directory string, cutoff time.Time) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read backup directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "authz-") || !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect backup %s: %w", entry.Name(), err)
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
				return fmt.Errorf("remove expired backup %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}
