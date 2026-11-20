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
	"sync"
	"sync/atomic"
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

func fakeIDTokenWithNonce(nonce string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	body, _ := json.Marshal(map[string]string{"nonce": nonce})
	pld := base64.RawURLEncoding.EncodeToString(body)
	return hdr + "." + pld + ".sig"
}

func TestOIDCFullFlowRefreshAndLogout(t *testing.T) {
	var seenChallenge string
	var seenNonce string
	var refreshedCount atomic.Int32
	var logoutCalled atomic.Bool

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
					"id_token":      fakeIDTokenWithNonce(seenNonce),
					"expires_in":    1, // expires immediately to exercise auto-refresh
				})
			case "refresh_token":
				refreshedCount.Add(1)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "refreshed-access-token",
					"refresh_token": "refresh-2",
					"expires_in":    300,
				})
			default:
				http.Error(w, "unsupported grant", http.StatusBadRequest)
			}
		case "/realms/demo/protocol/openid-connect/logout":
			logoutCalled.Store(true)
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
	seenNonce = loc.Query().Get("nonce")
	if state == "" || seenChallenge == "" || seenNonce == "" || loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("missing PKCE/state/nonce params: %s", loc.String())
	}
	stateCookies := startRec.Result().Cookies()

	// 2. Callback exchanges code + PKCE verifier, checks nonce, and sets encrypted session cookie.
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

	// 3. Parallel ResolveBearer calls coalesce into a single refresh (rotation-safe).
	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)
	var lastCookies []*http.Cookie
	var cookieMu sync.Mutex
	for range workers {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/app", nil)
			for _, c := range sessionCookies {
				if c.MaxAge > 0 {
					req.AddCookie(c)
				}
			}
			rec := httptest.NewRecorder()
			bearer, ok := mgr.ResolveBearer(rec, req)
			if !ok || bearer != "Bearer refreshed-access-token" {
				t.Errorf("expected auto-refreshed bearer, got ok=%v bearer=%q", ok, bearer)
			}
			cookieMu.Lock()
			if lastCookies == nil {
				lastCookies = rec.Result().Cookies()
			}
			cookieMu.Unlock()
		}()
	}
	wg.Wait()
	if refreshedCount.Load() != 1 {
		t.Fatalf("expected 1 coalesced refresh, got %d", refreshedCount.Load())
	}

	// 4. Cross-site logout CSRF is rejected.
	csrfLogout := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	csrfLogout.Header.Set("Sec-Fetch-Site", "cross-site")
	csrfRec := httptest.NewRecorder()
	mux.ServeHTTP(csrfRec, csrfLogout)
	if csrfRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-site logout, got %d", csrfRec.Code)
	}

	// 5. Same-origin logout clears cookies and calls Keycloak logout.
	logoutReq := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	logoutReq.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, c := range lastCookies {
		if c.MaxAge > 0 {
			logoutReq.AddCookie(c)
		}
	}
	logoutRec := httptest.NewRecorder()
	mux.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusFound || !logoutCalled.Load() {
		t.Fatalf("logout failed: code=%d logoutCalled=%v", logoutRec.Code, logoutCalled.Load())
	}

	// 6. ShouldRedirect only triggers for GET HTML requests.
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

func TestStripCookiesAndNonceRejection(t *testing.T) {
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

	headers := http.Header{}
	headers.Set("Cookie", "app_pref=dark; __Host-gocloak_session=secret0; __Host-gocloak_session_1=secret1; __Host-gocloak_session_state=st; theme=light")
	mgr.StripCookies(headers)
	if got := headers.Get("Cookie"); got != "app_pref=dark; theme=light" {
		t.Fatalf("unexpected remaining cookies: %q", got)
	}

	if verifyIDTokenNonce(fakeIDTokenWithNonce("wrong"), "expected") {
		t.Error("accepted mismatched ID token nonce")
	}
	if !verifyIDTokenNonce(fakeIDTokenWithNonce("expected"), "expected") {
		t.Error("rejected matching ID token nonce")
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

func BenchmarkReadSession(b *testing.B) {
	mgr, err := New(Config{
		Issuer:       "https://keycloak.example/realms/demo",
		ClientID:     "my-app",
		RedirectURL:  "https://app.example/oauth2/callback",
		CookieSecret: strings.Repeat("k", 32),
		CookieSecure: true,
	}, stubVerifier{})
	if err != nil {
		b.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := mgr.writeSession(rec, sessionData{
		AccessToken:  strings.Repeat("a", 800),
		RefreshToken: strings.Repeat("r", 300),
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
	}); err != nil {
		b.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge > 0 {
			req.AddCookie(c)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, ok := mgr.readSession(req); !ok {
			b.Fatal("readSession failed")
		}
	}
}
