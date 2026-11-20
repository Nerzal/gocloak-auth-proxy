package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
)

type stubVerifier struct{}

func (stubVerifier) Verify(_ context.Context, authorization string) (auth.Identity, error) {
	if !strings.HasPrefix(authorization, "Bearer ") {
		return auth.Identity{}, auth.ErrForbidden
	}
	return auth.Identity{User: "alice", RawToken: strings.TrimPrefix(authorization, "Bearer ")}, nil
}

func TestOIDCFullFlowRefreshAndLogout(t *testing.T) {
	var seenChallenge string
	var refreshedCount int
	var logoutCalled bool

	kc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/demo/protocol/openid-connect/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			switch r.FormValue("grant_type") {
			case "authorization_code":
				v := r.FormValue("code_verifier")
				sum := sha256.Sum256([]byte(v))
				if base64.RawURLEncoding.EncodeToString(sum[:]) != seenChallenge {
					http.Error(w, "pkce mismatch", http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "initial-access-token",
					"refresh_token": "refresh-1",
					"id_token":      "id-tok-1",
					"expires_in":    1, // expires immediately to exercise auto-refresh
				})
			case "refresh_token":
				refreshedCount++
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "refreshed-access-token",
					"refresh_token": "refresh-2",
					"expires_in":    300,
				})
			default:
				http.Error(w, "unsupported grant", http.StatusBadRequest)
			}
		case "/realms/demo/protocol/openid-connect/logout":
			logoutCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer kc.Close()

	mgr, err := New(Config{
		Issuer:                  kc.URL + "/realms/demo",
		ClientID:                "my-app",
		ClientSecret:            "my-secret",
		RedirectURL:             "http://localhost/oauth2/callback",
		CookieSecret:            strings.Repeat("a", 32),
		CookieSecure:            false,
		RedirectUnauthenticated: true,
	}, stubVerifier{})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mgr.RegisterRoutes(mux)

	// 1. Start login with open-redirect attempt -> must sanitize to "/".
	startRec := httptest.NewRecorder()
	mux.ServeHTTP(startRec, httptest.NewRequest(http.MethodGet, "/oauth2/start?rd=https://evil.test/phish", nil))
	if startRec.Code != http.StatusFound {
		t.Fatalf("start status = %d, want 302", startRec.Code)
	}
	loc, err := url.Parse(startRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := loc.Query().Get("state")
	seenChallenge = loc.Query().Get("code_challenge")
	if state == "" || seenChallenge == "" || loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("missing PKCE/state params: %s", loc.String())
	}
	stateCookies := startRec.Result().Cookies()

	// 2. Callback exchanges code + PKCE verifier and sets encrypted session cookie.
	cbReq := httptest.NewRequest(http.MethodGet, "/oauth2/callback?code=auth-code&state="+url.QueryEscape(state), nil)
	for _, c := range stateCookies {
		cbReq.AddCookie(c)
	}
	cbRec := httptest.NewRecorder()
	mux.ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusFound || cbRec.Header().Get("Location") != "/" {
		t.Fatalf("callback failed: %d loc=%q", cbRec.Code, cbRec.Header().Get("Location"))
	}
	sessionCookies := cbRec.Result().Cookies()

	// 3. ResolveBearer automatically refreshes the near-expiry token.
	resolveReq := httptest.NewRequest(http.MethodGet, "/app", nil)
	for _, c := range sessionCookies {
		if c.MaxAge > 0 {
			resolveReq.AddCookie(c)
		}
	}
	resolveRec := httptest.NewRecorder()
	bearer, ok := mgr.ResolveBearer(resolveRec, resolveReq)
	if !ok || bearer != "Bearer refreshed-access-token" || refreshedCount != 1 {
		t.Fatalf("expected auto-refreshed bearer, got ok=%v bearer=%q refreshes=%d", ok, bearer, refreshedCount)
	}

	// 4. Logout clears cookies and calls Keycloak logout.
	logoutReq := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	for _, c := range resolveRec.Result().Cookies() {
		if c.MaxAge > 0 {
			logoutReq.AddCookie(c)
		}
	}
	logoutRec := httptest.NewRecorder()
	mux.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusFound || !logoutCalled {
		t.Fatalf("logout failed: code=%d logoutCalled=%v", logoutRec.Code, logoutCalled)
	}

	// 5. ShouldRedirect only triggers for GET HTML requests.
	htmlReq := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	htmlReq.Header.Set("Accept", "text/html,application/xhtml+xml")
	if !mgr.ShouldRedirect(htmlReq) {
		t.Error("expected ShouldRedirect=true for HTML GET")
	}
	apiReq := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	apiReq.Header.Set("Accept", "application/json")
	if mgr.ShouldRedirect(apiReq) {
		t.Error("expected ShouldRedirect=false for JSON API GET")
	}
}

func TestChunkedLargeSessionCookie(t *testing.T) {
	mgr, err := New(Config{
		Issuer:       "https://keycloak.example/realms/demo",
		ClientID:     "my-app",
		RedirectURL:  "https://app.example/oauth2/callback",
		CookieSecret: strings.Repeat("k", 32),
		CookieSecure: true,
	}, stubVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	large := sessionData{
		AccessToken:  strings.Repeat("x", 5000),
		RefreshToken: strings.Repeat("y", 1000),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	}
	rec := httptest.NewRecorder()
	if err := mgr.writeSession(rec, large); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	var activeChunks int
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge > 0 {
			activeChunks++
			req.AddCookie(c)
		}
	}
	if activeChunks < 2 {
		t.Fatalf("expected >= 2 cookie chunks, got %d", activeChunks)
	}
	got, ok := mgr.readSession(req)
	if !ok || got.AccessToken != large.AccessToken || got.RefreshToken != large.RefreshToken {
		t.Fatalf("chunked session round-trip failed: ok=%v", ok)
	}
}
