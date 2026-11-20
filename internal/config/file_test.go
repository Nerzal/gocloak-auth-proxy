package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLoadJSONConfigFileAndEnvOverride(t *testing.T) {
	cfgJSON := `{
		"issuer": "https://idp.example.com/realms/demo",
		"audience": "demo-api",
		"upstream_url": "http://127.0.0.1:8081",
		"listen_addr": ":9000",
		"client_id": "demo-client",
		"required_amr": ["mfa", "hwk"],
		"route_rules": [
			"POST:/admin/*=realm:admin,acr:aal2,amr:mfa",
			"GET:/reports/*=client:reader"
		],
		"oidc_enabled": true,
		"oidc_redirect_url": "https://auth.example.com/oauth2/callback",
		"oidc_cookie_secret": "0123456789abcdef0123456789abcdef",
		"oidc_cookie_domain": ".example.com",
		"oidc_allowed_redirect_domains": ["app1.example.com", ".example.com"],
		"keycloak_client_cert_file": "/certs/kc.crt",
		"keycloak_client_key_file": "/certs/kc.key"
	}`
	path := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_FILE", path)
	// ENV overrides JSON
	t.Setenv("LISTEN_ADDR", ":7777")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.ListenAddr != ":7777" {
		t.Errorf("expected ENV override LISTEN_ADDR=:7777, got %q", cfg.ListenAddr)
	}
	if !slices.Equal(cfg.RequiredAMR, []string{"mfa", "hwk"}) {
		t.Errorf("unexpected RequiredAMR: %v", cfg.RequiredAMR)
	}
	if len(cfg.RouteRules) != 2 {
		t.Errorf("expected 2 route rules, got %v", cfg.RouteRules)
	}
	if cfg.OIDCCookieDomain != ".example.com" || len(cfg.OIDCAllowedRedirectDomains) != 2 {
		t.Errorf("unexpected OIDC multi-domain config: domain=%q allowed=%v", cfg.OIDCCookieDomain, cfg.OIDCAllowedRedirectDomains)
	}
	if cfg.KeycloakClientCertFile != "/certs/kc.crt" || cfg.KeycloakClientKeyFile != "/certs/kc.key" {
		t.Errorf("unexpected mTLS config: cert=%q key=%q", cfg.KeycloakClientCertFile, cfg.KeycloakClientKeyFile)
	}
}

func TestLoadJSONConfigFileUnknownFieldAndUnpairedMTLS(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badPath, []byte(`{"issuer":"https://idp.example.com/realms/demo","audience":"a","unknown_key":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_FILE", badPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected error for unknown JSON config field")
	}

	unpairedPath := filepath.Join(t.TempDir(), "unpaired.json")
	if err := os.WriteFile(unpairedPath, []byte(`{"issuer":"https://idp.example.com/realms/demo","audience":"a","upstream_client_cert_file":"/only.crt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_FILE", unpairedPath)
	if _, err := Load(); err == nil {
		t.Fatal("expected error for unpaired UPSTREAM_CLIENT_CERT_FILE without key")
	}
}
