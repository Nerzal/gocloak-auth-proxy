package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Nerzal/gocloak-auth-proxy/internal/config"
	"github.com/Nerzal/gocloak-auth-proxy/internal/metrics"
	"github.com/golang-jwt/jwt/v5"
)

func mockKeycloak(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	jwk := map[string]any{
		"kid": "k1", "kty": "EC", "alg": "ES256", "use": "sig", "crv": "P-256",
		"x": enc(key.X.FillBytes(make([]byte, 32))),
		"y": enc(key.Y.FillBytes(make([]byte, 32))),
	}
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/demo/protocol/openid-connect/certs":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
		case "/realms/demo/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			tok := strings.TrimPrefix(issueToken(t, key, srvURL+"/realms/demo", "my-api"), "Bearer ")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  tok,
				"refresh_token": "r-1",
				"expires_in":    300,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return srv, key
}

func issueToken(t *testing.T, key *ecdsa.PrivateKey, issuer, audience string) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":                issuer,
		"aud":                audience,
		"typ":                "Bearer",
		"exp":                now.Add(time.Minute).Unix(),
		"iat":                now.Add(-time.Second).Unix(),
		"sub":                "user-123",
		"preferred_username": "alice",
		"email":              "alice@example.test",
		"tenant_id":          "acme",
		"realm_access":       map[string]any{"roles": []string{"reader"}},
	})
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + signed
}

func TestEndToEndForwardAuthAndHealth(t *testing.T) {
	kc, key := mockKeycloak(t)
	issuer := kc.URL + "/realms/demo"
	cfg := config.Config{
		Issuer:              issuer,
		Audience:            "my-api",
		ListenAddr:          ":0",
		HeaderUser:          "X-Custom-User",
		RequiredRealmRoles:  []string{"reader"},
		JWKSRefreshInterval: time.Minute,
		ClockSkew:           5 * time.Second,
	}
	reg := metrics.New()
	handler, cache, err := buildHandler(cfg, slog.New(slog.DiscardHandler), reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	// Operational endpoints work without authentication.
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := proxySrv.Client().Get(proxySrv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s returned %d, want 200", path, resp.StatusCode)
		}
	}

	// Authenticated forward-auth request returns verified custom headers.
	req, err := http.NewRequest(http.MethodGet, proxySrv.URL+"/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", issueToken(t, key, issuer, "my-api"))
	resp, err := proxySrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/auth returned %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-Custom-User") != "alice" || resp.Header.Get("X-Auth-Request-Roles") != "reader" {
		t.Fatalf("unexpected identity headers: %#v", resp.Header)
	}
}

func TestEndToEndReverseProxy(t *testing.T) {
	kc, key := mockKeycloak(t)
	issuer := kc.URL + "/realms/demo"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Real-IP") != "" || r.Header.Get("X_Auth_Request_Roles") != "" {
			t.Errorf("untrusted headers leaked to upstream: %#v", r.Header)
		}
		if r.Header.Get("X-Auth-Request-User") != "alice" || r.Header.Get("X-Tenant-ID") != "acme" {
			t.Errorf("missing verified identity headers: %#v", r.Header)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	cfg := config.Config{
		Issuer:              issuer,
		Audience:            "my-api",
		UpstreamURL:         upstream.URL,
		ListenAddr:          ":0",
		CustomClaimHeaders:  map[string]string{"X-Tenant-ID": "tenant_id"},
		JWKSRefreshInterval: time.Minute,
	}
	reg := metrics.New()
	handler, cache, err := buildHandler(cfg, slog.New(slog.DiscardHandler), reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	req, err := http.NewRequest(http.MethodGet, proxySrv.URL+"/api/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", issueToken(t, key, issuer, "my-api"))
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header["X_Auth_Request_Roles"] = []string{"superadmin"}
	resp, err := proxySrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("unexpected reverse-proxy response: %d %q", resp.StatusCode, string(body))
	}
}

func TestEndToEndOIDCBrowserSSOAndMetrics(t *testing.T) {
	kc, _ := mockKeycloak(t)
	issuer := kc.URL + "/realms/demo"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Cookie"), "gocloak_session") {
			t.Errorf("OIDC session cookie leaked to upstream: %q", r.Header.Get("Cookie"))
		}
		_, _ = io.WriteString(w, "hello:"+r.Header.Get("X-Auth-Request-User"))
	}))
	defer upstream.Close()

	cfg := config.Config{
		Issuer:              issuer,
		Audience:            "my-api",
		ClientID:            "my-api",
		UpstreamURL:         upstream.URL,
		ListenAddr:          ":0",
		JWKSRefreshInterval: time.Minute,
		OIDCEnabled:         true,
		OIDCRedirectURL:     "http://localhost/oauth2/callback",
		OIDCCookieSecret:    strings.Repeat("s", 32),
		OIDCCookieSecure:    false,
		OIDCRedirectUnauth:  true,
	}
	reg := metrics.New()
	handler, cache, err := buildHandler(cfg, slog.New(slog.DiscardHandler), reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 1. Start OIDC login.
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, httptest.NewRequest(http.MethodGet, "/oauth2/start?rd=/dashboard", nil))
	loc, _ := url.Parse(startRec.Header().Get("Location"))
	state := loc.Query().Get("state")

	// 2. Callback sets encrypted session cookie.
	cbReq := httptest.NewRequest(http.MethodGet, "/oauth2/callback?code=c1&state="+url.QueryEscape(state), nil)
	for _, c := range startRec.Result().Cookies() {
		cbReq.AddCookie(c)
	}
	cbRec := httptest.NewRecorder()
	handler.ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusFound || cbRec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("callback unexpected: %d %q", cbRec.Code, cbRec.Header().Get("Location"))
	}

	// 3. Subsequent browser request uses encrypted session cookie to reach upstream.
	appReq := httptest.NewRequest(http.MethodGet, "http://proxy.test/dashboard", nil)
	for _, c := range cbRec.Result().Cookies() {
		if c.MaxAge > 0 {
			appReq.AddCookie(c)
		}
	}
	appRec := httptest.NewRecorder()
	handler.ServeHTTP(appRec, appReq)
	if appRec.Code != http.StatusOK || appRec.Body.String() != "hello:alice" {
		t.Fatalf("SSO upstream failed: %d %q", appRec.Code, appRec.Body.String())
	}

	// 4. Metrics endpoint reflects JWKS refresh, OIDC login, and allowed reverse-proxy request.
	mRec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(mRec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(mRec.Body.String(), `gocloak_auth_proxy_oidc_events_total{result="success"} 1`) ||
		!strings.Contains(mRec.Body.String(), `gocloak_auth_proxy_requests_total{mode="reverse_proxy",result="allowed"} 1`) {
		t.Fatalf("unexpected metrics:\n%s", mRec.Body.String())
	}
}

func TestParseCLIArgs(t *testing.T) {
	var out strings.Builder
	exitEarly, err := parseCLIArgs([]string{"--version"}, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exitEarly {
		t.Fatal("expected exitEarly=true for --version")
	}
	if !strings.HasPrefix(out.String(), "gocloak-auth-proxy ") {
		t.Fatalf("unexpected version output: %q", out.String())
	}

	out.Reset()
	exitEarly, err = parseCLIArgs(nil, &out)
	if err != nil || exitEarly {
		t.Fatalf("expected normal startup for empty args, got exitEarly=%v err=%v", exitEarly, err)
	}

	out.Reset()
	if _, err := parseCLIArgs([]string{"--unknown-flag"}, &out); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestCLICheckAndPrintConfig(t *testing.T) {
	t.Setenv("ISSUER", "https://kc.example.test/realms/demo")
	t.Setenv("AUDIENCE", "my-api")
	t.Setenv("CLIENT_ID", "my-app")
	t.Setenv("CLIENT_SECRET", "top-secret-value")

	var out strings.Builder
	act, err := parseCLIAction([]string{"--check-config"}, &out)
	if err != nil || act != cliCheckConfig {
		t.Fatalf("expected cliCheckConfig, got %v err=%v", act, err)
	}
	if err := runCheckConfig(&out); err != nil {
		t.Fatalf("runCheckConfig failed: %v", err)
	}
	if !strings.Contains(out.String(), "configuration valid") {
		t.Fatalf("unexpected check-config output: %q", out.String())
	}

	out.Reset()
	act, err = parseCLIAction([]string{"--print-config"}, &out)
	if err != nil || act != cliPrintConfig {
		t.Fatalf("expected cliPrintConfig, got %v err=%v", act, err)
	}
	if err := runPrintConfig(&out); err != nil {
		t.Fatalf("runPrintConfig failed: %v", err)
	}
	if strings.Contains(out.String(), "top-secret-value") || !strings.Contains(out.String(), "[REDACTED]") {
		t.Fatalf("print-config did not redact secret:\n%s", out.String())
	}
}
