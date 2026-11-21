package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretFilesAndRedactedJSON(t *testing.T) {
	dir := t.TempDir()
	clientSecretFile := filepath.Join(dir, "client-secret")
	cookieSecretFile := filepath.Join(dir, "cookie-secret")
	prevSecretFile := filepath.Join(dir, "cookie-prev")
	redisPassFile := filepath.Join(dir, "redis-pass")

	if err := os.WriteFile(clientSecretFile, []byte("super-secret-client\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cookieSecretFile, []byte("12345678901234567890123456789012\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prevSecretFile, []byte("abcdefghijklmnopqrstuvwxyz123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(redisPassFile, []byte("redis-top-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ISSUER", "https://kc.example.test/realms/demo")
	t.Setenv("AUDIENCE", "my-api")
	t.Setenv("CLIENT_ID", "my-app")
	t.Setenv("CLIENT_SECRET_FILE", clientSecretFile)
	t.Setenv("OIDC_ENABLED", "true")
	t.Setenv("OIDC_REDIRECT_URL", "https://app.example.test/oauth2/callback")
	t.Setenv("OIDC_COOKIE_SECRET_FILE", cookieSecretFile)
	t.Setenv("OIDC_COOKIE_SECRET_PREVIOUS_FILE", prevSecretFile)
	t.Setenv("REDIS_ADDR", "127.0.0.1:6379")
	t.Setenv("REDIS_PASSWORD_FILE", redisPassFile)
	t.Setenv("SHUTDOWN_DRAIN_DELAY", "5s")
	t.Setenv("ACCESS_LOG", "true")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8,127.0.0.1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.ClientSecret != "super-secret-client" {
		t.Fatalf("unexpected ClientSecret: %q", cfg.ClientSecret)
	}
	if cfg.OIDCCookieSecret != "12345678901234567890123456789012" {
		t.Fatalf("unexpected OIDCCookieSecret: %q", cfg.OIDCCookieSecret)
	}
	if cfg.OIDCCookieSecretPrevious != "abcdefghijklmnopqrstuvwxyz123456" {
		t.Fatalf("unexpected OIDCCookieSecretPrevious: %q", cfg.OIDCCookieSecretPrevious)
	}
	if cfg.RedisPassword != "redis-top-secret" {
		t.Fatalf("unexpected RedisPassword: %q", cfg.RedisPassword)
	}

	out, err := cfg.RedactedJSON()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, secret := range []string{"super-secret-client", "12345678901234567890123456789012", "abcdefghijklmnopqrstuvwxyz123456", "redis-top-secret"} {
		if strings.Contains(s, secret) {
			t.Fatalf("RedactedJSON leaked secret %q:\n%s", secret, s)
		}
	}
	if strings.Count(s, "[REDACTED]") != 4 {
		t.Fatalf("expected 4 [REDACTED] entries, got:\n%s", s)
	}
}
