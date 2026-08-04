package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddr      = ":8081"
	defaultDBPath          = "/data/authz.db"
	defaultBackupDir       = "/data/backups"
	defaultOAuth2AuthURL   = "http://oauth2-proxy:4180/oauth2/auth"
	defaultAllowedDomain   = "example.com"
	defaultRetentionDays   = 90
	defaultBackupKeepDays  = 30
	defaultOnlineWindow    = 2 * time.Minute
	defaultWriteThrottle   = time.Minute
	defaultOAuthTimeout    = 5 * time.Second
	defaultCSRFValidity    = 8 * time.Hour
	minimumGatewaySecret   = 32
	maximumConfiguredUsers = 500
)

type config struct {
	ListenAddr          string
	DBPath              string
	BackupDir           string
	OAuth2AuthURL       string
	AllowedDomain       string
	GatewaySecret       string
	CSRFSecret          []byte
	AdminEmails         map[string]struct{}
	InitialViewers      []string
	RetentionDays       int
	BackupRetentionDays int
	OnlineWindow        time.Duration
	WriteThrottle       time.Duration
	OAuthTimeout        time.Duration
	CSRFValidity        time.Duration
}

func loadConfig() (config, error) {
	cfg := config{
		ListenAddr:          envOrDefault("AUTHZ_LISTEN_ADDR", defaultListenAddr),
		DBPath:              envOrDefault("AUTHZ_DB_PATH", defaultDBPath),
		BackupDir:           envOrDefault("AUTHZ_BACKUP_DIR", defaultBackupDir),
		OAuth2AuthURL:       envOrDefault("OAUTH2_PROXY_AUTH_URL", defaultOAuth2AuthURL),
		AllowedDomain:       strings.ToLower(strings.TrimSpace(envOrDefault("AUTHZ_ALLOWED_EMAIL_DOMAIN", defaultAllowedDomain))),
		GatewaySecret:       os.Getenv("AUTHZ_GATEWAY_SECRET"),
		RetentionDays:       defaultRetentionDays,
		BackupRetentionDays: defaultBackupKeepDays,
		OnlineWindow:        defaultOnlineWindow,
		WriteThrottle:       defaultWriteThrottle,
		OAuthTimeout:        defaultOAuthTimeout,
		CSRFValidity:        defaultCSRFValidity,
	}

	if len(cfg.GatewaySecret) < minimumGatewaySecret {
		return config{}, fmt.Errorf("AUTHZ_GATEWAY_SECRET must be at least %d characters", minimumGatewaySecret)
	}
	if cfg.AllowedDomain == "" || strings.Contains(cfg.AllowedDomain, "@") {
		return config{}, errors.New("AUTHZ_ALLOWED_EMAIL_DOMAIN must be a domain without @")
	}
	if cfg.ListenAddr == "" || cfg.DBPath == "" || cfg.BackupDir == "" || cfg.OAuth2AuthURL == "" {
		return config{}, errors.New("listen address, database path, backup directory and OAuth auth URL must not be empty")
	}

	var err error
	if cfg.RetentionDays, err = positiveEnvInt("AUTHZ_AUDIT_RETENTION_DAYS", defaultRetentionDays); err != nil {
		return config{}, err
	}
	if cfg.BackupRetentionDays, err = positiveEnvInt("AUTHZ_BACKUP_RETENTION_DAYS", defaultBackupKeepDays); err != nil {
		return config{}, err
	}

	cfg.AdminEmails, err = parseEmailSet(os.Getenv("PORTAL_ADMIN_EMAILS"), cfg.AllowedDomain, true)
	if err != nil {
		return config{}, fmt.Errorf("PORTAL_ADMIN_EMAILS: %w", err)
	}
	if len(cfg.AdminEmails) == 0 {
		return config{}, errors.New("PORTAL_ADMIN_EMAILS must contain at least one company email")
	}

	initial, err := parseEmailList(os.Getenv("PORTAL_INITIAL_VIEWERS"), cfg.AllowedDomain)
	if err != nil {
		return config{}, fmt.Errorf("PORTAL_INITIAL_VIEWERS: %w", err)
	}
	if len(initial) > maximumConfiguredUsers {
		return config{}, fmt.Errorf("PORTAL_INITIAL_VIEWERS exceeds %d entries", maximumConfiguredUsers)
	}
	cfg.InitialViewers = initial

	csrfSecret := os.Getenv("AUTHZ_CSRF_SECRET")
	if csrfSecret == "" {
		generated := make([]byte, 32)
		if _, err := rand.Read(generated); err != nil {
			return config{}, fmt.Errorf("generate CSRF secret: %w", err)
		}
		cfg.CSRFSecret = generated
	} else {
		if len(csrfSecret) < 32 {
			return config{}, errors.New("AUTHZ_CSRF_SECRET must be at least 32 characters")
		}
		cfg.CSRFSecret = []byte(csrfSecret)
	}

	return cfg, nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func positiveEnvInt(name string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func parseEmailSet(raw, domain string, requireValid bool) (map[string]struct{}, error) {
	emails, err := parseEmailList(raw, domain)
	if err != nil && requireValid {
		return nil, err
	}
	result := make(map[string]struct{}, len(emails))
	for _, email := range emails {
		result[email] = struct{}{}
	}
	return result, err
}

func parseEmailList(raw, domain string) ([]string, error) {
	raw = strings.NewReplacer("\r", ",", "\n", ",", ";", ",").Replace(raw)
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			continue
		}
		email, ok := normalizeEmail(part, domain)
		if !ok {
			return nil, fmt.Errorf("invalid company email %q", strings.TrimSpace(part))
		}
		if _, exists := seen[email]; exists {
			continue
		}
		seen[email] = struct{}{}
		result = append(result, email)
	}
	return result, nil
}

func normalizeEmail(raw, domain string) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if len(email) < 3 || len(email) > 254 || strings.ContainsAny(email, " \t\r\n<>,;\"") {
		return "", false
	}
	if strings.Count(email, "@") != 1 {
		return "", false
	}
	parts := strings.SplitN(email, "@", 2)
	if parts[0] == "" || parts[1] != strings.ToLower(strings.TrimSpace(domain)) {
		return "", false
	}
	if strings.HasPrefix(parts[0], ".") || strings.HasSuffix(parts[0], ".") || strings.Contains(parts[0], "..") {
		return "", false
	}
	return email, true
}
