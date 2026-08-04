package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxJSONBody         = 64 << 10
	maxBatchUsers       = 100
	defaultPageSize     = 20
	maximumPageSize     = 100
	maximumOAuthCookies = 4
	gatewayTokenHeader  = "X-Authz-Gateway-Token"
)

var (
	errOAuthUnauthenticated = errors.New("oauth session is not authenticated")
	errOAuthForbidden       = errors.New("oauth provider denied the session")
	errOAuthUnavailable     = errors.New("oauth provider is unavailable")
)

type app struct {
	cfg            config
	store          *store
	httpClient     *http.Client
	now            func() time.Time
	decisionMu     sync.Mutex
	decisionWrites map[string]time.Time
}

func newApp(cfg config, store *store) *app {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   cfg.OAuthTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: cfg.OAuthTimeout,
	}
	return &app{
		cfg:   cfg,
		store: store,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.OAuthTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now:            time.Now,
		decisionWrites: make(map[string]time.Time),
	}
}

func (a *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("GET /readyz", a.handleReady)
	mux.HandleFunc("GET /auth/viewer", a.handleViewerAuth)
	mux.HandleFunc("GET /auth/admin", a.handleAdminAuth)
	mux.HandleFunc("GET /api/me", a.handleMe)
	mux.HandleFunc("GET /api/admin/overview", a.handleOverview)
	mux.HandleFunc("GET /api/admin/users", a.handleListUsers)
	mux.HandleFunc("POST /api/admin/users", a.handleAddUsers)
	mux.HandleFunc("POST /api/admin/users/batch", a.handleAddUsers)
	mux.HandleFunc("PATCH /api/admin/users/{id}", a.handleMutateUser)
	mux.HandleFunc("GET /api/admin/access-events", a.handleAccessEvents)
	mux.HandleFunc("GET /api/admin/access", a.handleAccessEvents)
	mux.HandleFunc("GET /api/admin/audit-events", a.handleAuditEvents)
	mux.HandleFunc("GET /api/admin/audit", a.handleAuditEvents)
	return a.securityHeaders(a.requireGatewayToken(mux))
}

func (a *app) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (a *app) requireGatewayToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		provided := r.Header.Get(gatewayTokenHeader)
		if len(provided) != len(a.cfg.GatewaySecret) || subtle.ConstantTimeCompare([]byte(provided), []byte(a.cfg.GatewaySecret)) != 1 {
			writeError(w, http.StatusForbidden, "gateway_forbidden", "request must come through the trusted gateway")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (a *app) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.store.health(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "authorization database is unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (a *app) handleViewerAuth(w http.ResponseWriter, r *http.Request) {
	a.handleAuthorization(w, r, false)
}

func (a *app) handleAdminAuth(w http.ResponseWriter, r *http.Request) {
	a.handleAuthorization(w, r, true)
}

func (a *app) handleAuthorization(w http.ResponseWriter, r *http.Request, requireAdmin bool) {
	subject, refreshedCookies, err := a.authenticateOAuth(r)
	for index, cookie := range refreshedCookies {
		w.Header().Add("Set-Cookie", cookie)
		if index > 0 {
			w.Header().Set("X-Authz-Set-Cookie-"+strconv.Itoa(index), cookie)
		}
	}
	if err != nil {
		switch {
		case errors.Is(err, errOAuthUnauthenticated):
			writeError(w, http.StatusUnauthorized, "unauthenticated", "SSO login is required")
		case errors.Is(err, errOAuthForbidden):
			writeError(w, http.StatusForbidden, "identity_forbidden", "SSO identity is not allowed")
		default:
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "identity_provider_unavailable", "SSO validation is temporarily unavailable")
		}
		return
	}

	now := a.now().UTC()
	_, isSuperAdmin := a.cfg.AdminEmails[subject.Email]
	isAdmin := isSuperAdmin
	allowed := isSuperAdmin
	reason := ""
	if !isSuperAdmin {
		user, viewerAllowed, viewerReason, authorizationErr := a.store.authorizeViewer(r.Context(), subject.Email)
		if authorizationErr != nil {
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "authorization database is temporarily unavailable")
			return
		}
		isAdmin = viewerAllowed && user.IsAdmin
		if requireAdmin {
			allowed = isAdmin
			if viewerAllowed && !isAdmin {
				reason = "not_admin"
			} else {
				reason = viewerReason
			}
		} else {
			allowed = viewerAllowed
			reason = viewerReason
		}
	} else if requireAdmin {
		allowed = true
	}

	outcome := outcomeDenied
	if allowed {
		outcome = outcomeAllowed
	}
	subject.Role = "viewer"
	if isAdmin {
		subject.Role = "admin"
	}
	subject.IsAdmin = isAdmin
	subject.IsSuperAdmin = isSuperAdmin
	fingerprint := sessionFingerprint(r, subject.Email, now)
	decisionKey := subject.Email + "\x00" + outcome + "\x00" + fingerprint
	if a.reserveDecisionWrite(decisionKey, now) {
		if err := a.store.recordDecision(
			r.Context(), subject, outcome, reason, requestIP(r), fingerprint, now, a.cfg.WriteThrottle,
		); err != nil {
			a.releaseDecisionWrite(decisionKey, now)
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "authorization database is temporarily unavailable")
			return
		}
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "viewer_forbidden", "this account does not have portal access")
		return
	}

	w.Header().Set("X-Auth-Request-Email", subject.Email)
	w.Header().Set("X-Auth-Request-User", subject.DisplayName)
	w.Header().Set("X-Portal-Role", subject.Role)
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) authenticateOAuth(r *http.Request) (identity, []string, error) {
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.cfg.OAuth2AuthURL, nil)
	if err != nil {
		return identity{}, nil, fmt.Errorf("create OAuth validation request: %w", err)
	}
	request.Header.Set("Cookie", r.Header.Get("Cookie"))
	copyHeader(request.Header, r.Header, "X-Original-URI")
	copyHeader(request.Header, r.Header, "X-Original-Method")
	copyHeader(request.Header, r.Header, "X-Real-IP")
	copyHeader(request.Header, r.Header, "X-Forwarded-For")
	copyHeader(request.Header, r.Header, "X-Forwarded-Proto")

	response, err := a.httpClient.Do(request)
	if err != nil {
		return identity{}, nil, fmt.Errorf("%w: %v", errOAuthUnavailable, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	refreshedCookies := append([]string(nil), response.Header.Values("Set-Cookie")...)
	if len(refreshedCookies) > maximumOAuthCookies {
		return identity{}, nil, fmt.Errorf("%w: oauth provider returned too many Set-Cookie headers", errOAuthUnavailable)
	}

	if response.StatusCode == http.StatusUnauthorized {
		return identity{}, refreshedCookies, errOAuthUnauthenticated
	}
	if response.StatusCode == http.StatusForbidden {
		return identity{}, refreshedCookies, errOAuthForbidden
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return identity{}, refreshedCookies, fmt.Errorf("%w: status %d", errOAuthUnavailable, response.StatusCode)
	}

	email, ok := normalizeEmail(response.Header.Get("X-Auth-Request-Email"), a.cfg.AllowedDomain)
	if !ok {
		return identity{}, refreshedCookies, errOAuthForbidden
	}
	displayName := sanitizeClaim(response.Header.Get("X-Auth-Request-User"), 200)
	if displayName == "" || isNumericClaim(displayName) {
		displayName = emailLocalPart(email)
	}
	return identity{Email: email, DisplayName: displayName}, refreshedCookies, nil
}

func copyHeader(destination, source http.Header, name string) {
	if value := source.Get(name); value != "" {
		destination.Set(name, value)
	}
}

func sanitizeClaim(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func isNumericClaim(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !unicode.IsDigit(character) {
			return false
		}
	}
	return true
}

func emailLocalPart(email string) string {
	localPart, _, found := strings.Cut(email, "@")
	if !found || localPart == "" {
		return email
	}
	return localPart
}

func requestIP(r *http.Request) string {
	ip := strings.TrimSpace(strings.Split(r.Header.Get("X-Real-IP"), ",")[0])
	if ip == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			ip = host
		} else {
			ip = r.RemoteAddr
		}
	}
	if len(ip) > 64 {
		return ip[:64]
	}
	return ip
}

func sessionFingerprint(r *http.Request, email string, now time.Time) string {
	value := ""
	if cookie, err := r.Cookie("__Secure-oryx_live_portal"); err == nil {
		value = cookie.Value
	} else if cookie, err := r.Cookie("_oauth2_proxy"); err == nil {
		value = cookie.Value
	} else {
		value = r.Header.Get("Cookie")
	}
	if value == "" {
		value = email + "|" + now.UTC().Truncate(8*time.Hour).Format(time.RFC3339)
	}
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (a *app) apiIdentity(r *http.Request) (identity, error) {
	email, ok := normalizeEmail(r.Header.Get("X-Portal-Email"), a.cfg.AllowedDomain)
	if !ok {
		return identity{}, errors.New("trusted gateway identity is missing")
	}
	trustedRole := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Portal-Role")))
	if trustedRole != "viewer" && trustedRole != "admin" {
		return identity{}, errors.New("trusted gateway role is missing")
	}
	_, isSuperAdmin := a.cfg.AdminEmails[email]
	isAdmin := isSuperAdmin
	if !isSuperAdmin {
		user, allowed, _, err := a.store.authorizeViewer(r.Context(), email)
		if err != nil {
			return identity{}, fmt.Errorf("load trusted gateway identity: %w", err)
		}
		if !allowed {
			return identity{}, errors.New("trusted gateway identity is no longer authorized")
		}
		isAdmin = user.IsAdmin
	}
	if trustedRole == "admin" && !isAdmin {
		return identity{}, errors.New("trusted gateway administrator is no longer authorized")
	}
	name := sanitizeClaim(r.Header.Get("X-Portal-User"), 200)
	if name == "" || isNumericClaim(name) {
		name = emailLocalPart(email)
	}
	return identity{
		Email: email, DisplayName: name, Role: trustedRole,
		IsAdmin: isAdmin, IsSuperAdmin: isSuperAdmin,
	}, nil
}

func (a *app) adminIdentity(w http.ResponseWriter, r *http.Request) (identity, bool) {
	subject, err := a.apiIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "gateway_identity_missing", "trusted gateway identity is missing")
		return identity{}, false
	}
	if subject.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin_required", "administrator permission is required")
		return identity{}, false
	}
	return subject, true
}

func (a *app) handleMe(w http.ResponseWriter, r *http.Request) {
	subject, err := a.apiIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "gateway_identity_missing", "trusted gateway identity is missing")
		return
	}
	_, err = a.store.userByEmail(r.Context(), subject.Email)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "authorization database is temporarily unavailable")
		return
	}
	response := meResponse{
		Email:              subject.Email,
		DisplayName:        subject.DisplayName,
		Name:               subject.DisplayName,
		Role:               subject.Role,
		IsAdmin:            subject.IsAdmin,
		IsSuperAdmin:       subject.IsSuperAdmin,
		CanManageAdmins:    subject.IsSuperAdmin,
		CSRFToken:          a.issueCSRFToken(subject.Email, a.now().UTC()),
		AllowedEmailDomain: a.cfg.AllowedDomain,
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *app) handleOverview(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.adminIdentity(w, r); !ok {
		return
	}
	result, err := a.store.overview(r.Context(), a.now().UTC(), a.cfg.OnlineWindow)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "could not load overview")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *app) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.adminIdentity(w, r); !ok {
		return
	}
	page, pageSize, err := pagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	result, err := a.store.listUsers(
		r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status"))), page, pageSize,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unsupported status") {
			writeError(w, http.StatusBadRequest, "invalid_status", "unsupported user status")
		} else {
			writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "could not load users")
		}
		return
	}
	for index := range result.Items {
		if _, isSuperAdmin := a.cfg.AdminEmails[result.Items[index].Email]; isSuperAdmin {
			result.Items[index].IsAdmin = true
			result.Items[index].IsSuperAdmin = true
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *app) handleAddUsers(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.adminIdentity(w, r)
	if !ok || !a.requireCSRF(w, r, actor.Email) {
		return
	}
	var request addUsersRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}
	rawEmails := append([]string{}, request.Emails...)
	if strings.TrimSpace(request.Email) != "" {
		rawEmails = append(rawEmails, request.Email)
	}
	if len(rawEmails) == 0 {
		writeError(w, http.StatusBadRequest, "emails_required", "at least one email is required")
		return
	}
	if len(rawEmails) > maxBatchUsers {
		writeError(w, http.StatusBadRequest, "batch_too_large", fmt.Sprintf("at most %d emails can be added at once", maxBatchUsers))
		return
	}

	valid := make([]string, 0, len(rawEmails))
	seen := make(map[string]struct{}, len(rawEmails))
	invalidResults := make([]addUserResult, 0)
	for _, raw := range rawEmails {
		email, validEmail := normalizeEmail(raw, a.cfg.AllowedDomain)
		if !validEmail {
			invalidResults = append(invalidResults, addUserResult{Email: strings.TrimSpace(raw), Result: "invalid", Reason: "company_email_required"})
			continue
		}
		if _, duplicate := seen[email]; duplicate {
			continue
		}
		seen[email] = struct{}{}
		valid = append(valid, email)
	}

	response, err := a.store.addUsers(r.Context(), valid, actor.Email, requestIP(r), a.now().UTC())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "could not add users")
		return
	}
	response.Summary.Invalid = len(invalidResults)
	response.Results = append(response.Results, invalidResults...)
	writeJSON(w, http.StatusOK, response)
}

func (a *app) handleMutateUser(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.adminIdentity(w, r)
	if !ok || !a.requireCSRF(w, r, actor.Email) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_user_id", "user id must be a positive integer")
		return
	}
	var request mutateUserRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}
	if request.Action != "disable" && request.Action != "restore" && request.Action != "archive" && request.Action != "grant_admin" && request.Action != "revoke_admin" {
		writeError(w, http.StatusBadRequest, "invalid_action", "unsupported user action")
		return
	}
	if request.Action == "grant_admin" || request.Action == "revoke_admin" {
		if !actor.IsSuperAdmin {
			writeError(w, http.StatusForbidden, "super_admin_required", "super administrator permission is required")
			return
		}
	}
	updated, err := a.store.mutateUser(r.Context(), id, request.Action, actor.Email, requestIP(r), a.now().UTC(), a.cfg.AdminEmails)
	switch {
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, "user_not_found", "user was not found")
	case errors.Is(err, errProtectedUser):
		writeError(w, http.StatusConflict, "administrator_protected", "administrator permission must be revoked before this action")
	case errors.Is(err, errInactiveUser):
		writeError(w, http.StatusConflict, "administrator_requires_active_user", "only an active user can become an administrator")
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "could not update user")
	default:
		if _, isSuperAdmin := a.cfg.AdminEmails[updated.Email]; isSuperAdmin {
			updated.IsAdmin = true
			updated.IsSuperAdmin = true
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func (a *app) handleAccessEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.adminIdentity(w, r); !ok {
		return
	}
	page, pageSize, err := pagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	result, err := a.store.listAccessEvents(r.Context(), strings.ToLower(strings.TrimSpace(r.URL.Query().Get("outcome"))), page, pageSize)
	if err != nil {
		if strings.Contains(err.Error(), "unsupported outcome") {
			writeError(w, http.StatusBadRequest, "invalid_outcome", "outcome must be allowed or denied")
		} else {
			writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "could not load access events")
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *app) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.adminIdentity(w, r); !ok {
		return
	}
	page, pageSize, err := pagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	result, err := a.store.listAuditEvents(r.Context(), page, pageSize)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "could not load audit events")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *app) issueCSRFToken(email string, now time.Time) string {
	expires := now.Add(a.cfg.CSRFValidity).Unix()
	payload := email + "\n" + strconv.FormatInt(expires, 10)
	signature := hmac.New(sha256.New, a.cfg.CSRFSecret)
	_, _ = signature.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(expires, 10))) + "." +
		base64.RawURLEncoding.EncodeToString(signature.Sum(nil))
}

func (a *app) requireCSRF(w http.ResponseWriter, r *http.Request, email string) bool {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "json_required", "Content-Type must be application/json")
		return false
	}
	token := r.Header.Get("X-CSRF-Token")
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		writeError(w, http.StatusForbidden, "csrf_invalid", "CSRF token is missing or invalid")
		return false
	}
	expiresRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		writeError(w, http.StatusForbidden, "csrf_invalid", "CSRF token is missing or invalid")
		return false
	}
	expires, err := strconv.ParseInt(string(expiresRaw), 10, 64)
	now := a.now().UTC()
	if err != nil || expires <= now.Unix() || expires > now.Add(a.cfg.CSRFValidity+time.Minute).Unix() {
		writeError(w, http.StatusForbidden, "csrf_expired", "CSRF token is expired or invalid")
		return false
	}
	payload := email + "\n" + strconv.FormatInt(expires, 10)
	signature := hmac.New(sha256.New, a.cfg.CSRFSecret)
	_, _ = signature.Write([]byte(payload))
	expected := signature.Sum(nil)
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(provided, expected) {
		writeError(w, http.StatusForbidden, "csrf_invalid", "CSRF token is missing or invalid")
		return false
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON with known fields")
		}
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain one JSON object")
		return errors.New("multiple JSON values")
	}
	return nil
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func pagination(r *http.Request) (int, int, error) {
	page, err := positiveQueryInt(r, "page", 1)
	if err != nil {
		return 0, 0, err
	}
	pageSizeName := "pageSize"
	if r.URL.Query().Get(pageSizeName) == "" && r.URL.Query().Get("page_size") != "" {
		pageSizeName = "page_size"
	}
	pageSize, err := positiveQueryInt(r, pageSizeName, defaultPageSize)
	if err != nil {
		return 0, 0, err
	}
	if pageSize > maximumPageSize {
		return 0, 0, fmt.Errorf("pageSize must not exceed %d", maximumPageSize)
	}
	return page, pageSize, nil
}

func positiveQueryInt(r *http.Request, name string, fallback int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorEnvelope{Error: apiError{Code: code, Message: message}})
}

func (a *app) reserveDecisionWrite(key string, now time.Time) bool {
	a.decisionMu.Lock()
	defer a.decisionMu.Unlock()
	if last, exists := a.decisionWrites[key]; exists && now.Sub(last) < a.cfg.WriteThrottle {
		return false
	}
	a.decisionWrites[key] = now
	if len(a.decisionWrites) > 2000 {
		cutoff := now.Add(-2 * a.cfg.WriteThrottle)
		for existingKey, last := range a.decisionWrites {
			if last.Before(cutoff) {
				delete(a.decisionWrites, existingKey)
			}
		}
	}
	return true
}

func (a *app) releaseDecisionWrite(key string, reservedAt time.Time) {
	a.decisionMu.Lock()
	defer a.decisionMu.Unlock()
	if current, exists := a.decisionWrites[key]; exists && current.Equal(reservedAt) {
		delete(a.decisionWrites, key)
	}
}
