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

	request := adminAPIRequest(http.MethodPost, "/api/admin/users", strings.NewReader(`{"emails":["New@Example.com","bad@outside.example","new@example.com"],"expiresAt":null}`), "")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("add without CSRF status = %d, want 403", response.Code)
	}

	request = adminAPIRequest(http.MethodPost, "/api/admin/users", strings.NewReader(`{"emails":["New@Example.com","bad@outside.example","new@example.com"],"expiresAt":null}`), csrf)
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

func TestExpiredViewerIsDeniedAtTheBoundary(t *testing.T) {
	env := newTestEnvironment(t)
	csrf := fetchAdminCSRF(t, env)
	expires := env.now.UTC().Format(time.RFC3339)
	body := fmt.Sprintf(`{"emails":["expired@example.com"],"expiresAt":%q}`, expires)
	request := adminAPIRequest(http.MethodPost, "/api/admin/users", strings.NewReader(body), csrf)
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("add expired user status = %d, body=%s", response.Code, response.Body.String())
	}
	setFakeOAuthIdentity(t, env, "expired", "expired@example.com", "Expired User")
	assertOAuthStatus(t, env, "expired", http.StatusForbidden)

	users := listUsers(t, env, "expired@example.com")
	if got := users.Items[0].Status; got != "expired" {
		t.Fatalf("effective status = %q, want expired", got)
	}

	mutateUser(t, env, csrf, users.Items[0].ID, `{"action":"restore"}`, http.StatusOK)
	assertOAuthStatus(t, env, "expired", http.StatusNoContent)
	restored := listUsers(t, env, "expired@example.com").Items[0]
	if restored.Status != "authorized" || restored.ExpiresAt != nil {
		t.Fatalf("restored expired user = %#v, want authorized with no expiry", restored)
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
	request := trustedRequest(method, path, body)
	request.Header.Set("X-Portal-Email", "admin@example.com")
	request.Header.Set("X-Portal-User", "Portal Admin")
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
	request := adminAPIRequest(http.MethodGet, "/api/me", nil, "")
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
	return me.CSRFToken
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
	request := trustedRequest(http.MethodGet, "/auth/viewer", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: session})
	request.Header.Set("X-Original-URI", "/live/stream01.m3u8")
	request.Header.Set("X-Real-IP", "10.1.2.3")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if response.Code != wantStatus {
		t.Fatalf("session %s status = %d, want %d; body=%s", session, response.Code, wantStatus, response.Body.String())
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
