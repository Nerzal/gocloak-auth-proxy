package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type staticKeySource struct {
	pub any
}

func (s staticKeySource) Key(_ context.Context, _ string, _ string) (any, error) {
	return s.pub, nil
}

func signLogoutToken(t *testing.T, priv *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign logout token: %v", err)
	}
	return s
}

func TestBackchannelLogoutSIDAndSub(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://idp.example.com/realms/demo"
	var events []string
	mgr, err := New(Config{
		Issuer:       issuer,
		ClientID:     "demo-client",
		RedirectURL:  "https://app.example.com/oauth2/callback",
		CookieSecret: "0123456789abcdef0123456789abcdef",
		CookieSecure: true,
		Keys:         staticKeySource{pub: &priv.PublicKey},
		OnEvent:      func(e string) { events = append(events, e) },
	}, stubVerifier{})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	mux := http.NewServeMux()
	mgr.RegisterRoutes(mux)

	// Helper to create a request with an encrypted session cookie.
	makeSessionReq := func(sess sessionData) *http.Request {
		w := httptest.NewRecorder()
		if err := mgr.writeSession(w, sess); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
		for _, c := range w.Result().Cookies() {
			if c.MaxAge >= 0 {
				req.AddCookie(c)
			}
		}
		return req
	}

	now := time.Now().Unix()
	reqSID1 := makeSessionReq(sessionData{AccessToken: "tok-1", SID: "sid-1", Sub: "sub-1", IssuedAt: now, ExpiresAt: now + 300, SessionExpiresAt: now + 3600})
	reqSID2 := makeSessionReq(sessionData{AccessToken: "tok-2", SID: "sid-2", Sub: "sub-1", IssuedAt: now, ExpiresAt: now + 300, SessionExpiresAt: now + 3600})

	// Both sessions work before backchannel logout.
	if _, ok := mgr.ResolveBearer(httptest.NewRecorder(), reqSID1); !ok {
		t.Fatal("expected sid-1 to be active")
	}
	if _, ok := mgr.ResolveBearer(httptest.NewRecorder(), reqSID2); !ok {
		t.Fatal("expected sid-2 to be active")
	}

	// Send valid backchannel logout for sid-1 only.
	lt := signLogoutToken(t, priv, jwt.MapClaims{
		"iss":    issuer,
		"aud":    "demo-client",
		"iat":    now,
		"jti":    "jti-1",
		"sid":    "sid-1",
		"sub":    "sub-1",
		"events": map[string]any{backchannelEventURI: map[string]any{}},
	})
	form := url.Values{"logout_token": {lt}}.Encode()
	post := httptest.NewRequest(http.MethodPost, "/oauth2/backchannel-logout", strings.NewReader(form))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, post)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	// sid-1 must now be revoked; sid-2 remains active.
	recRevoked := httptest.NewRecorder()
	if _, ok := mgr.ResolveBearer(recRevoked, reqSID1); ok {
		t.Fatal("expected sid-1 to be revoked")
	}
	if _, ok := mgr.ResolveBearer(httptest.NewRecorder(), reqSID2); !ok {
		t.Fatal("expected sid-2 to remain active after sid-1 logout")
	}

	// Subject-wide logout (no sid) invalidates sid-2 created at `now`, but allows a newer session.
	ltSub := signLogoutToken(t, priv, jwt.MapClaims{
		"iss":    issuer,
		"aud":    "demo-client",
		"iat":    now,
		"jti":    "jti-2",
		"sub":    "sub-1",
		"events": map[string]any{backchannelEventURI: map[string]any{}},
	})
	postSub := httptest.NewRequest(http.MethodPost, "/oauth2/backchannel-logout", strings.NewReader(url.Values{"logout_token": {ltSub}}.Encode()))
	postSub.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recSub := httptest.NewRecorder()
	mux.ServeHTTP(recSub, postSub)
	if recSub.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for sub logout, got %d", recSub.Code)
	}
	if _, ok := mgr.ResolveBearer(httptest.NewRecorder(), reqSID2); ok {
		t.Fatal("expected sid-2 to be revoked by sub-wide logout")
	}
	reqNew := makeSessionReq(sessionData{AccessToken: "tok-3", SID: "sid-3", Sub: "sub-1", IssuedAt: now + 10, ExpiresAt: now + 300, SessionExpiresAt: now + 3600})
	if _, ok := mgr.ResolveBearer(httptest.NewRecorder(), reqNew); !ok {
		t.Fatal("expected re-logged-in session created after sub logout to be allowed")
	}
}

func TestBackchannelLogoutRejectsInvalidTokens(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://idp.example.com/realms/demo"
	mgr, err := New(Config{
		Issuer:       issuer,
		ClientID:     "demo-client",
		RedirectURL:  "https://app.example.com/oauth2/callback",
		CookieSecret: "0123456789abcdef0123456789abcdef",
		CookieSecure: true,
		Keys:         staticKeySource{pub: &priv.PublicKey},
	}, stubVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mgr.RegisterRoutes(mux)

	now := time.Now().Unix()
	cases := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{"contains nonce", jwt.MapClaims{"iss": issuer, "aud": "demo-client", "iat": now, "sid": "s1", "nonce": "bad", "events": map[string]any{backchannelEventURI: map[string]any{}}}},
		{"missing events", jwt.MapClaims{"iss": issuer, "aud": "demo-client", "iat": now, "sid": "s1"}},
		{"missing sid and sub", jwt.MapClaims{"iss": issuer, "aud": "demo-client", "iat": now, "events": map[string]any{backchannelEventURI: map[string]any{}}}},
		{"wrong audience", jwt.MapClaims{"iss": issuer, "aud": "other-client", "iat": now, "sid": "s1", "events": map[string]any{backchannelEventURI: map[string]any{}}}},
		{"stale iat", jwt.MapClaims{"iss": issuer, "aud": "demo-client", "iat": now - 600, "sid": "s1", "events": map[string]any{backchannelEventURI: map[string]any{}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lt := signLogoutToken(t, priv, tc.claims)
			req := httptest.NewRequest(http.MethodPost, "/oauth2/backchannel-logout", strings.NewReader(url.Values{"logout_token": {lt}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 Bad Request for %s, got %d", tc.name, rec.Code)
			}
		})
	}
	// GET must be rejected with 405.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/backchannel-logout", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestMultiDomainRedirectAndCookieDomain(t *testing.T) {
	// __Host- prefix + CookieDomain must be rejected.
	_, err := New(Config{
		Issuer:       "https://idp.example.com/realms/demo",
		ClientID:     "demo-client",
		RedirectURL:  "https://auth.example.com/oauth2/callback",
		CookieSecret: "0123456789abcdef0123456789abcdef",
		CookieName:   "__Host-gocloak_session",
		CookieDomain: ".example.com",
		CookieSecure: true,
	}, stubVerifier{})
	if err == nil {
		t.Fatal("expected error for __Host- cookie with CookieDomain")
	}

	mgr, err := New(Config{
		Issuer:                 "https://idp.example.com/realms/demo",
		ClientID:               "demo-client",
		RedirectURL:            "https://auth.example.com/oauth2/callback",
		CookieSecret:           "0123456789abcdef0123456789abcdef",
		CookieDomain:           ".example.com",
		CookieSecure:           true,
		AllowedRedirectDomains: []string{"exact.corp.io", ".example.com"},
	}, stubVerifier{})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if mgr.cookieName != "gocloak_session" {
		t.Fatalf("expected default cookie name gocloak_session when CookieDomain set, got %q", mgr.cookieName)
	}
	if c := mgr.newCookie("test", "v", 60); c.Domain != ".example.com" {
		t.Fatalf("expected cookie Domain .example.com, got %q", c.Domain)
	}

	tests := []struct {
		in   string
		want string
	}{
		{"/dashboard?tab=1", "/dashboard?tab=1"},
		{"https://app1.example.com/home", "https://app1.example.com/home"},
		{"https://exact.corp.io:8443/api", "https://exact.corp.io:8443/api"},
		{"http://app1.example.com/insecure", "/"},    // CookieSecure=true rejects http://
		{"https://evil.com/phish", "/"},              // not in allowlist
		{"https://notexample.com/phish", "/"},        // suffix boundary check
		{"https://user@app1.example.com/phish", "/"}, // userinfo rejected
		{"//evil.com/phish", "/"},                    // protocol-relative rejected
	}
	for _, tc := range tests {
		if got := mgr.safeRedirectURL(tc.in); got != tc.want {
			t.Errorf("safeRedirectURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// Forward-Auth multi-domain RedirectToLogin uses X-Forwarded-Host when allowed.
	req := httptest.NewRequest(http.MethodGet, "/orders?id=42", nil)
	req.Header.Set("X-Forwarded-Host", "shop.example.com")
	rec := httptest.NewRecorder()
	mgr.RedirectToLogin(rec, req)
	loc := rec.Header().Get("Location")
	wantLoc := "/oauth2/start?rd=" + url.QueryEscape("https://shop.example.com/orders?id=42")
	if loc != wantLoc {
		t.Fatalf("RedirectToLogin Location = %q, want %q", loc, wantLoc)
	}
}
