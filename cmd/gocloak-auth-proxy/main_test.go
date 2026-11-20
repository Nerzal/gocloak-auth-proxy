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
	"testing"
	"time"

	"github.com/Nerzal/gocloak-auth-proxy/internal/config"
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/demo/protocol/openid-connect/certs" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	}))
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
	handler, cache, err := buildHandler(cfg, slog.New(slog.DiscardHandler))
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
		if r.Header.Get("X-Auth-Request-User") != "alice" {
			t.Errorf("missing verified user header: %#v", r.Header)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	cfg := config.Config{
		Issuer:              issuer,
		Audience:            "my-api",
		UpstreamURL:         upstream.URL,
		ListenAddr:          ":0",
		JWKSRefreshInterval: time.Minute,
	}
	handler, cache, err := buildHandler(cfg, slog.New(slog.DiscardHandler))
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
