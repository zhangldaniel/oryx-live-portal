package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testGatewaySecret = "0123456789abcdef0123456789abcdef"

type testEnvironment struct {
	app        *app
	handler    http.Handler
	store      *store
	oauth      *httptest.Server
	now        *time.Time
	oauthCalls *atomic.Int64
}

func newTestEnvironment(t *testing.T) *testEnvironment {
	t.Helper()
	calls := &atomic.Int64{}
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "unauthenticated" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		identities := map[string][2]string{
			"admin":    {"admin@example.com", "Portal Admin"},
			"viewer":   {"viewer@example.com", "Portal Viewer"},
			"unknown":  {"unknown@example.com", "Unknown User"},
			"external": {"user@outside.example", "External User"},
		}
		identity, ok := identities[cookie.Value]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Auth-Request-Email", identity[0])
		w.Header().Set("X-Auth-Request-User", identity[1])
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(oauth.Close)

	database, err := openStore(filepath.Join(t.TempDir(), "authz.db"))
	if err != nil {
		t.Fatalf("openStore() error = %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 4, 4, 0, 0, 0, time.UTC)
	cfg := config{
		ListenAddr:          ":8081",
		DBPath:              "unused",
		BackupDir:           t.TempDir(),
		OAuth2AuthURL:       oauth.URL,
		AllowedDomain:       "example.com",
		GatewaySecret:       testGatewaySecret,
		CSRFSecret:          []byte("abcdef0123456789abcdef0123456789"),
		AdminEmails:         map[string]struct{}{"admin@example.com": {}},
		InitialViewers:      []string{"viewer@example.com"},
		RetentionDays:       90,
		BackupRetentionDays: 30,
		OnlineWindow:        2 * time.Minute,
		WriteThrottle:       time.Minute,
		OAuthTimeout:        time.Second,
		CSRFValidity:        8 * time.Hour,
	}
	if err := database.seed(t.Context(), cfg.AdminEmails, cfg.InitialViewers, now); err != nil {
		t.Fatalf("seed() error = %v", err)
	}
	application := newApp(cfg, database)
	application.now = func() time.Time { return now }
	return &testEnvironment{
		app: application, handler: application.handler(), store: database,
		oauth: oauth, now: &now, oauthCalls: calls,
	}
}

func TestAuthRejectsUntrustedAndSpoofedRequests(t *testing.T) {
	env := newTestEnvironment(t)

	request := httptest.NewRequest(http.MethodGet, "/auth/viewer", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: "viewer"})
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("untrusted request status = %d, want 403", response.Code)
	}
	if got := env.oauthCalls.Load(); got != 0 {
		t.Fatalf("oauth calls = %d, want 0 before gateway authentication", got)
	}

	request = trustedRequest(http.MethodGet, "/auth/viewer", nil)
	request.Header.Set("X-Auth-Request-Email", "admin@example.com")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("spoofed identity status = %d, want 401", response.Code)
	}
}

func TestOAuthTransportIsTunedForConcurrentHLSAuthorization(t *testing.T) {
	env := newTestEnvironment(t)
	transport, ok := env.app.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("oauth transport type = %T, want *http.Transport", env.app.httpClient.Transport)
	}
	if transport.MaxIdleConnsPerHost < 100 || transport.MaxIdleConns < transport.MaxIdleConnsPerHost {
		t.Fatalf("oauth connection pool is too small: maxIdle=%d perHost=%d", transport.MaxIdleConns, transport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout < time.Minute {
		t.Fatalf("oauth idle timeout = %s, want at least one minute", transport.IdleConnTimeout)
	}
}

func TestAuthEnforcesViewerAndAdministratorPermissions(t *testing.T) {
	env := newTestEnvironment(t)

	tests := []struct {
		name       string
		path       string
		session    string
		wantStatus int
		wantRole   string
	}{
		{name: "viewer can view", path: "/auth/viewer", session: "viewer", wantStatus: http.StatusNoContent, wantRole: "viewer"},
		{name: "viewer cannot administer", path: "/auth/admin", session: "viewer", wantStatus: http.StatusForbidden},
		{name: "administrator can view", path: "/auth/viewer", session: "admin", wantStatus: http.StatusNoContent, wantRole: "admin"},
		{name: "administrator can administer", path: "/auth/admin", session: "admin", wantStatus: http.StatusNoContent, wantRole: "admin"},
		{name: "unknown user cannot view", path: "/auth/viewer", session: "unknown", wantStatus: http.StatusForbidden},
		{name: "external identity cannot view", path: "/auth/viewer", session: "external", wantStatus: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := trustedRequest(http.MethodGet, test.path, nil)
			request.AddCookie(&http.Cookie{Name: "session", Value: test.session})
			request.Header.Set("X-Real-IP", "10.1.2.3")
			response := httptest.NewRecorder()
			env.handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantRole != "" && response.Header().Get("X-Portal-Role") != test.wantRole {
				t.Fatalf("X-Portal-Role = %q, want %q", response.Header().Get("X-Portal-Role"), test.wantRole)
			}
		})
	}
}

func TestAdminAPIAddsDisablesRestoresAndAuditsUsers(t *testing.T) {
	env := newTestEnvironment(t)
	csrf := fetchAdminCSRF(t, env)

	request := adminAPIRequest(http.MethodPost, "/api/admin/users", strings.NewReader(`{"emails":["New@Example.com","bad@outside.example","new@example.com"]}`), "")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("add without CSRF status = %d, want 403", response.Code)
	}

	request = adminAPIRequest(http.MethodPost, "/api/admin/users", strings.NewReader(`{"emails":["New@Example.com","bad@outside.example","new@example.com"]}`), csrf)
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("add users status = %d, body=%s", response.Code, response.Body.String())
	}
	var added addUsersResponse
	decodeResponse(t, response, &added)
	if added.Summary.Added != 1 || added.Summary.Invalid != 1 || added.Summary.Existing != 0 {
		t.Fatalf("add summary = %+v, want added=1 invalid=1 existing=0", added.Summary)
	}

	users := listUsers(t, env, "new@example.com")
	if users.Total != 1 || len(users.Items) != 1 {
		t.Fatalf("new user list = %+v, want one result", users)
	}
	userID := users.Items[0].ID

	assertOAuthStatus(t, env, "unknown", http.StatusForbidden)
	setFakeOAuthIdentity(t, env, "new", "new@example.com", "New User")
	assertOAuthStatus(t, env, "new", http.StatusNoContent)

	mutateUser(t, env, csrf, userID, `{"action":"disable"}`, http.StatusOK)
	assertOAuthStatus(t, env, "new", http.StatusForbidden)
	mutateUser(t, env, csrf, userID, `{"action":"restore"}`, http.StatusOK)
	assertOAuthStatus(t, env, "new", http.StatusNoContent)
	mutateUser(t, env, csrf, userID, `{"action":"archive"}`, http.StatusOK)
	assertOAuthStatus(t, env, "new", http.StatusForbidden)

	adminUsers := listUsers(t, env, "admin@example.com")
	mutateUser(t, env, csrf, adminUsers.Items[0].ID, `{"action":"disable"}`, http.StatusConflict)

	request = adminAPIRequest(http.MethodGet, "/api/admin/audit-events?page=1&pageSize=50", nil, "")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("audit status = %d, body=%s", response.Code, response.Body.String())
	}
	var audit pagedResponse[auditResponse]
	decodeResponse(t, response, &audit)
	if audit.Total != 4 {
		t.Fatalf("audit total = %d, want 4 (add, disable, restore, archive)", audit.Total)
	}
}

func TestSuperAdminCanGrantPersistentDynamicAdminAndRevokeIt(t *testing.T) {
	env := newTestEnvironment(t)
	superCSRF := fetchAdminCSRF(t, env)
	setFakeOAuthIdentity(t, env, "manager", "manager@example.com", "Portal Manager")

	request := adminAPIRequest(http.MethodPost, "/api/admin/users", strings.NewReader(`{"emails":["manager@example.com"]}`), superCSRF)
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("add manager status = %d, body=%s", response.Code, response.Body.String())
	}
	manager := listUsers(t, env, "manager@example.com").Items[0]
	assertOAuthPathStatus(t, env, "/auth/admin", "manager", http.StatusForbidden, "")

	mutateUser(t, env, superCSRF, manager.ID, `{"action":"grant_admin"}`, http.StatusOK)
	assertOAuthPathStatus(t, env, "/auth/admin", "manager", http.StatusNoContent, "admin")

	if err := env.store.seed(t.Context(), env.app.cfg.AdminEmails, env.app.cfg.InitialViewers, *env.now); err != nil {
		t.Fatalf("repeat seed() error = %v", err)
	}
	assertOAuthPathStatus(t, env, "/auth/admin", "manager", http.StatusNoContent, "admin")

	managerCSRF, managerMe := fetchAdminCSRFAs(t, env, "manager@example.com", "Portal Manager")
	if managerMe.Role != "admin" || !managerMe.IsAdmin || managerMe.IsSuperAdmin || managerMe.CanManageAdmins {
		t.Fatalf("dynamic administrator /api/me = %+v", managerMe)
	}
	request = trustedRequest(http.MethodGet, "/api/admin/overview", nil)
	request.Header.Set("X-Portal-Email", "manager@example.com")
	request.Header.Set("X-Portal-User", "Portal Manager")
	request.Header.Set("X-Portal-Role", "viewer")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer-role header for dynamic administrator status = %d, want 403", response.Code)
	}

	request = adminAPIRequestAs(http.MethodPost, "/api/admin/users", strings.NewReader(`{"emails":["ordinary@example.com"]}`), managerCSRF, "manager@example.com", "Portal Manager")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("dynamic administrator add viewer status = %d, body=%s", response.Code, response.Body.String())
	}
	ordinary := listUsers(t, env, "ordinary@example.com").Items[0]

	request = adminAPIRequestAs(http.MethodPatch, "/api/admin/users/"+strconv.FormatInt(ordinary.ID, 10), strings.NewReader(`{"action":"grant_admin"}`), managerCSRF, "manager@example.com", "Portal Manager")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("dynamic administrator grant status = %d, want 403; body=%s", response.Code, response.Body.String())
	}
	request = adminAPIRequestAs(http.MethodPatch, "/api/admin/users/"+strconv.FormatInt(manager.ID, 10), strings.NewReader(`{"action":"revoke_admin"}`), managerCSRF, "manager@example.com", "Portal Manager")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("dynamic administrator revoke status = %d, want 403; body=%s", response.Code, response.Body.String())
	}
	request = adminAPIRequestAs(http.MethodPatch, "/api/admin/users/"+strconv.FormatInt(ordinary.ID, 10), strings.NewReader(`{"action":"disable"}`), managerCSRF, "manager@example.com", "Portal Manager")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("dynamic administrator disable viewer status = %d, body=%s", response.Code, response.Body.String())
	}

	mutateUser(t, env, superCSRF, manager.ID, `{"action":"revoke_admin"}`, http.StatusOK)
	assertOAuthPathStatus(t, env, "/auth/admin", "manager", http.StatusForbidden, "")
	assertOAuthPathStatus(t, env, "/auth/viewer", "manager", http.StatusNoContent, "viewer")
	request = adminAPIRequestAs(http.MethodGet, "/api/admin/overview", nil, "", "manager@example.com", "Portal Manager")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked administrator stale header status = %d, want 401; body=%s", response.Code, response.Body.String())
	}

	request = adminAPIRequest(http.MethodGet, "/api/admin/audit-events?page=1&pageSize=100", nil, "")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	var audit pagedResponse[auditResponse]
	decodeResponse(t, response, &audit)
	actions := make(map[string]bool)
	for _, event := range audit.Items {
		actions[event.Action] = true
	}
	if !actions["grant_admin"] || !actions["revoke_admin"] {
		t.Fatalf("administrator audit actions = %#v, want grant_admin and revoke_admin", actions)
	}
}

func TestSuperAdminIsExplicitAndAdministratorsMustBeRevokedBeforeMutation(t *testing.T) {
	env := newTestEnvironment(t)
	csrf, me := fetchAdminCSRFAs(t, env, "admin@example.com", "Portal Admin")
	if me.Role != "admin" || !me.IsAdmin || !me.IsSuperAdmin || !me.CanManageAdmins {
		t.Fatalf("super administrator /api/me = %+v", me)
	}

	administrator := listUsers(t, env, "admin@example.com").Items[0]
	if !administrator.IsAdmin || !administrator.IsSuperAdmin {
		t.Fatalf("super administrator user response = %+v", administrator)
	}
	mutateUser(t, env, csrf, administrator.ID, `{"action":"revoke_admin"}`, http.StatusConflict)

	viewer := listUsers(t, env, "viewer@example.com").Items[0]
	mutateUser(t, env, csrf, viewer.ID, `{"action":"grant_admin"}`, http.StatusOK)
	viewer = listUsers(t, env, "viewer@example.com").Items[0]
	if !viewer.IsAdmin || viewer.IsSuperAdmin {
		t.Fatalf("dynamic administrator user response = %+v", viewer)
	}
	mutateUser(t, env, csrf, viewer.ID, `{"action":"disable"}`, http.StatusConflict)
	mutateUser(t, env, csrf, viewer.ID, `{"action":"archive"}`, http.StatusConflict)
	mutateUser(t, env, csrf, viewer.ID, `{"action":"revoke_admin"}`, http.StatusOK)
	mutateUser(t, env, csrf, viewer.ID, `{"action":"disable"}`, http.StatusOK)
	mutateUser(t, env, csrf, viewer.ID, `{"action":"grant_admin"}`, http.StatusConflict)
}

func TestLegacyExpiryDoesNotAffectViewerAuthorization(t *testing.T) {
	env := newTestEnvironment(t)
	legacyExpiry := env.now.Add(-time.Hour).Unix()
	if _, err := env.store.db.ExecContext(t.Context(),
		"UPDATE users SET expires_at = ? WHERE email = ?",
		legacyExpiry, "viewer@example.com",
	); err != nil {
		t.Fatalf("seed legacy expiry: %v", err)
	}

	assertOAuthStatus(t, env, "viewer", http.StatusNoContent)

	request := adminAPIRequest(http.MethodGet, "/api/admin/overview", nil, "")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("overview status = %d, body=%s", response.Code, response.Body.String())
	}
	var overview overviewResponse
	decodeResponse(t, response, &overview)
	if overview.Authorized != 2 {
		t.Fatalf("authorized users = %d, want legacy-expired viewer plus administrator", overview.Authorized)
	}

	csrf := fetchAdminCSRF(t, env)
	viewer := listUsers(t, env, "viewer@example.com")
	mutateUser(t, env, csrf, viewer.Items[0].ID, `{"action":"disable"}`, http.StatusOK)
	mutateUser(t, env, csrf, viewer.Items[0].ID, `{"action":"restore"}`, http.StatusOK)
	var expiryAfterMutations int64
	if err := env.store.db.QueryRowContext(t.Context(),
		"SELECT expires_at FROM users WHERE email = ?", "viewer@example.com",
	).Scan(&expiryAfterMutations); err != nil {
		t.Fatalf("read legacy expiry after mutations: %v", err)
	}
	if expiryAfterMutations != legacyExpiry {
		t.Fatalf("legacy expiry changed from %d to %d; runtime must not write the compatibility column", legacyExpiry, expiryAfterMutations)
	}
}

func TestManagementAPIRemovesExpiryFromInputAndOutput(t *testing.T) {
	env := newTestEnvironment(t)
	csrf := fetchAdminCSRF(t, env)

	request := adminAPIRequest(http.MethodGet, "/api/me", nil, "")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	var me map[string]any
	decodeResponse(t, response, &me)
	if _, exists := me["expiresAt"]; exists {
		t.Fatal("/api/me still exposes expiresAt")
	}

	request = adminAPIRequest(http.MethodGet, "/api/admin/users?pageSize=100", nil, "")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	var users struct {
		Items []map[string]any `json:"items"`
	}
	decodeResponse(t, response, &users)
	for _, user := range users.Items {
		if _, exists := user["expiresAt"]; exists {
			t.Fatalf("user response for %v still exposes expiresAt", user["email"])
		}
	}

	request = adminAPIRequest(http.MethodGet, "/api/admin/users?status=expired", nil, "")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("legacy expired filter status = %d, want 400", response.Code)
	}

	request = adminAPIRequest(http.MethodGet, "/api/admin/users/export.csv", nil, "")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("removed CSV export status = %d, want 405 from the remaining PATCH user route; body=%s", response.Code, response.Body.String())
	}

	request = adminAPIRequest(http.MethodPost, "/api/admin/users", strings.NewReader(`{"emails":["legacy-input@example.com"],"expiresAt":null}`), csrf)
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("legacy add expiry status = %d, want 400", response.Code)
	}

	viewer := listUsers(t, env, "viewer@example.com")
	request = adminAPIRequest(http.MethodPatch, "/api/admin/users/"+strconv.FormatInt(viewer.Items[0].ID, 10), strings.NewReader(`{"action":"update_expiry","expiresAt":null}`), csrf)
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("legacy update_expiry status = %d, want 400", response.Code)
	}
}

func TestRepeatedHLSAuthorizationWritesOncePerSessionAndThrottleWindow(t *testing.T) {
	env := newTestEnvironment(t)
	statuses := make(chan int, 100)
	var requests sync.WaitGroup
	for range 100 {
		requests.Add(1)
		go func() {
			defer requests.Done()
			request := trustedRequest(http.MethodGet, "/auth/viewer", nil)
			request.AddCookie(&http.Cookie{Name: "session", Value: "viewer"})
			request.Header.Set("X-Original-URI", "/live/stream01.m3u8")
			response := httptest.NewRecorder()
			env.handler.ServeHTTP(response, request)
			statuses <- response.Code
		}()
	}
	requests.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusNoContent {
			t.Fatalf("concurrent HLS authorization status = %d, want 204", status)
		}
	}

	request := adminAPIRequest(http.MethodGet, "/api/admin/access-events?outcome=allowed&pageSize=100", nil, "")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	var events pagedResponse[accessEventResponse]
	decodeResponse(t, response, &events)
	if events.Total != 1 {
		t.Fatalf("allowed access events = %d, want 1 for repeated HLS requests", events.Total)
	}
	users := listUsers(t, env, "viewer@example.com")
	if users.Items[0].LoginCount != 1 {
		t.Fatalf("login count = %d, want 1 for one session", users.Items[0].LoginCount)
	}

	*env.now = env.now.Add(61 * time.Second)
	assertOAuthStatus(t, env, "viewer", http.StatusNoContent)
	events = pagedResponse[accessEventResponse]{}
	request = adminAPIRequest(http.MethodGet, "/api/admin/access-events?outcome=allowed&pageSize=100", nil, "")
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	decodeResponse(t, response, &events)
	if events.Total != 1 {
		t.Fatalf("access events after throttle = %d, want session-deduplicated 1", events.Total)
	}
}

func TestOAuthFailureFailsClosed(t *testing.T) {
	env := newTestEnvironment(t)
	env.app.cfg.OAuth2AuthURL = "http://127.0.0.1:1/oauth2/auth"
	env.app.httpClient.Timeout = 100 * time.Millisecond
	request := trustedRequest(http.MethodGet, "/auth/viewer", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: "viewer"})
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("oauth failure status = %d, want 503", response.Code)
	}
}

func TestNumericOIDCUserFallsBackToEmailLocalPart(t *testing.T) {
	env := newTestEnvironment(t)
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-Request-Email", "viewer@example.com")
		w.Header().Set("X-Auth-Request-User", " 123456 ")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer oauth.Close()
	env.app.cfg.OAuth2AuthURL = oauth.URL

	assertOAuthStatus(t, env, "viewer", http.StatusNoContent)
	viewer := listUsers(t, env, "viewer@example.com")
	if got := viewer.Items[0].DisplayName; got != "viewer" {
		t.Fatalf("displayName = %q, want email local-part fallback", got)
	}

	request := adminAPIRequest(http.MethodGet, "/api/admin/access-events?outcome=allowed", nil, "")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	var events pagedResponse[accessEventResponse]
	decodeResponse(t, response, &events)
	if len(events.Items) != 1 || events.Items[0].DisplayName != "viewer" {
		t.Fatalf("access event displayName = %#v, want viewer", events.Items)
	}
}

func TestAuthPropagatesEveryOAuthCookieRefreshHeader(t *testing.T) {
	env := newTestEnvironment(t)
	refreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "__Secure-oryx_live_portal=refreshed; Path=/; Secure; HttpOnly")
		w.Header().Add("Set-Cookie", "oauth_nonce=deleted; Path=/; Max-Age=0")
		w.Header().Add("Set-Cookie", "oauth_part_2=value; Path=/; Secure; HttpOnly")
		w.Header().Add("Set-Cookie", "oauth_part_3=value; Path=/; Secure; HttpOnly")
		if cookie, _ := r.Cookie("session"); cookie != nil && cookie.Value == "denied" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Auth-Request-Email", "viewer@example.com")
		w.Header().Set("X-Auth-Request-User", "Portal Viewer")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer refreshServer.Close()
	env.app.cfg.OAuth2AuthURL = refreshServer.URL

	request := trustedRequest(http.MethodGet, "/auth/viewer", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: "viewer"})
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("refresh auth status = %d, body=%s", response.Code, response.Body.String())
	}
	setCookies := response.Header().Values("Set-Cookie")
	if len(setCookies) != 4 {
		t.Fatalf("Set-Cookie headers = %#v, want all oauth2-proxy headers", setCookies)
	}
	for index := 1; index <= 3; index++ {
		if got := response.Header().Get("X-Authz-Set-Cookie-" + strconv.Itoa(index)); got != setCookies[index] {
			t.Fatalf("mirrored cookie %d = %q, want %q", index, got, setCookies[index])
		}
	}

	request = trustedRequest(http.MethodGet, "/auth/viewer", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: "denied"})
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("denied refresh status = %d, want 401", response.Code)
	}
	if setCookies = response.Header().Values("Set-Cookie"); len(setCookies) != 4 {
		t.Fatalf("denied Set-Cookie headers = %#v, want all oauth2-proxy headers", setCookies)
	}
}

func TestAuthRejectsAnUnsafeNumberOfOAuthCookieParts(t *testing.T) {
	env := newTestEnvironment(t)
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for index := 0; index < maximumOAuthCookies+1; index++ {
			w.Header().Add("Set-Cookie", fmt.Sprintf("part_%d=value; Path=/; Secure; HttpOnly", index))
		}
		w.Header().Set("X-Auth-Request-Email", "viewer@example.com")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer oauth.Close()
	env.app.cfg.OAuth2AuthURL = oauth.URL

	request := trustedRequest(http.MethodGet, "/auth/viewer", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: "viewer"})
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("too many cookie parts status = %d, want 503", response.Code)
	}
	if got := response.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("rejected cookie parts leaked to response: %#v", got)
	}
}

func TestAdminAPIRejectsViewerRoleAndOversizedJSON(t *testing.T) {
	env := newTestEnvironment(t)
	request := trustedRequest(http.MethodGet, "/api/admin/overview", nil)
	request.Header.Set("X-Portal-Email", "viewer@example.com")
	request.Header.Set("X-Portal-Role", "viewer")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer admin API status = %d, want 403", response.Code)
	}

	csrf := fetchAdminCSRF(t, env)
	largeBody := `{"emails":["` + strings.Repeat("a", maxJSONBody) + `@example.com"]}`
	request = adminAPIRequest(http.MethodPost, "/api/admin/users", strings.NewReader(largeBody), csrf)
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413; body=%s", response.Code, response.Body.String())
	}
}

func trustedRequest(method, path string, body *strings.Reader) *http.Request {
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, path, nil)
	} else {
		request = httptest.NewRequest(method, path, body)
	}
	request.Header.Set(gatewayTokenHeader, testGatewaySecret)
	return request
}

func adminAPIRequest(method, path string, body *strings.Reader, csrf string) *http.Request {
	return adminAPIRequestAs(method, path, body, csrf, "admin@example.com", "Portal Admin")
}

func adminAPIRequestAs(method, path string, body *strings.Reader, csrf, email, name string) *http.Request {
	request := trustedRequest(method, path, body)
	request.Header.Set("X-Portal-Email", email)
	request.Header.Set("X-Portal-User", name)
	request.Header.Set("X-Portal-Role", "admin")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	return request
}

func fetchAdminCSRF(t *testing.T, env *testEnvironment) string {
	t.Helper()
	token, _ := fetchAdminCSRFAs(t, env, "admin@example.com", "Portal Admin")
	return token
}

func fetchAdminCSRFAs(t *testing.T, env *testEnvironment, email, name string) (string, meResponse) {
	t.Helper()
	request := adminAPIRequestAs(http.MethodGet, "/api/me", nil, "", email, name)
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("/api/me status = %d, body=%s", response.Code, response.Body.String())
	}
	var me meResponse
	decodeResponse(t, response, &me)
	if me.CSRFToken == "" || me.Role != "admin" || me.AllowedEmailDomain != "example.com" {
		t.Fatalf("unexpected /api/me response: %+v", me)
	}
	return me.CSRFToken, me
}

func listUsers(t *testing.T, env *testEnvironment, query string) pagedResponse[userResponse] {
	t.Helper()
	request := adminAPIRequest(http.MethodGet, "/api/admin/users?q="+query+"&pageSize=100", nil, "")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("list users status = %d, body=%s", response.Code, response.Body.String())
	}
	var users pagedResponse[userResponse]
	decodeResponse(t, response, &users)
	return users
}

func mutateUser(t *testing.T, env *testEnvironment, csrf string, id int64, body string, wantStatus int) {
	t.Helper()
	request := adminAPIRequest(http.MethodPatch, "/api/admin/users/"+strconv.FormatInt(id, 10), strings.NewReader(body), csrf)
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != wantStatus {
		t.Fatalf("mutate user status = %d, want %d; body=%s", response.Code, wantStatus, response.Body.String())
	}
}

func assertOAuthStatus(t *testing.T, env *testEnvironment, session string, wantStatus int) {
	t.Helper()
	assertOAuthPathStatus(t, env, "/auth/viewer", session, wantStatus, "")
}

func assertOAuthPathStatus(t *testing.T, env *testEnvironment, path, session string, wantStatus int, wantRole string) {
	t.Helper()
	request := trustedRequest(http.MethodGet, path, nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: session})
	request.Header.Set("X-Original-URI", "/live/stream01.m3u8")
	request.Header.Set("X-Real-IP", "10.1.2.3")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != wantStatus {
		t.Fatalf("session %s status = %d, want %d; body=%s", session, response.Code, wantStatus, response.Body.String())
	}
	if wantRole != "" && response.Header().Get("X-Portal-Role") != wantRole {
		t.Fatalf("session %s role = %q, want %q", session, response.Header().Get("X-Portal-Role"), wantRole)
	}
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), destination); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
}

func setFakeOAuthIdentity(t *testing.T, env *testEnvironment, session, email, name string) {
	t.Helper()
	oldServer := env.oauth
	newServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err == nil && cookie.Value == session {
			w.Header().Set("X-Auth-Request-Email", email)
			w.Header().Set("X-Auth-Request-User", name)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		proxyRequest, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, oldServer.URL, nil)
		proxyRequest.Header = r.Header.Clone()
		proxyResponse, err := http.DefaultClient.Do(proxyRequest)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer proxyResponse.Body.Close()
		for name, values := range proxyResponse.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(proxyResponse.StatusCode)
	}))
	t.Cleanup(newServer.Close)
	env.app.cfg.OAuth2AuthURL = newServer.URL
}

func TestCSRFTokenIsBoundToIdentityAndExpiresWithTheSSOSessionWindow(t *testing.T) {
	env := newTestEnvironment(t)
	token := env.app.issueCSRFToken("admin@example.com", *env.now)

	request := adminAPIRequest(http.MethodPost, "/api/admin/users", strings.NewReader(`{"emails":["one@example.com"]}`), token)
	request.Header.Set("X-Portal-Email", "other@example.com")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		// The configured administrator check runs before CSRF and must also reject
		// a forged administrator identity.
		t.Fatalf("forged admin status = %d, want 401", response.Code)
	}

	*env.now = env.now.Add(8*time.Hour + time.Second)
	request = adminAPIRequest(http.MethodPost, "/api/admin/users", strings.NewReader(`{"emails":["two@example.com"]}`), token)
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expired CSRF status = %d, want 403", response.Code)
	}
}

func TestErrorResponsesUseTheDocumentedEnvelope(t *testing.T) {
	env := newTestEnvironment(t)
	request := trustedRequest(http.MethodGet, "/auth/viewer", nil)
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	var envelope errorEnvelope
	decodeResponse(t, response, &envelope)
	if envelope.Error.Code != "unauthenticated" || envelope.Error.Message == "" {
		t.Fatalf("error envelope = %+v", envelope)
	}
}

func TestHealthDoesNotRequireGatewayToken(t *testing.T) {
	env := newTestEnvironment(t)
	request := httptest.NewRequest(http.MethodGet, "/healthz", bytes.NewReader(nil))
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("health response = %d %q", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response = httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("ready response = %d %q", response.Code, response.Body.String())
	}
}
