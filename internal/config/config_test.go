package config

import (
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	t.Setenv("ISSUER", "https://keycloak.example/realms/example")
	t.Setenv("AUDIENCE", "service")
	t.Setenv("HEADER_USER", "X-Custom-User")
	t.Setenv("REQUIRED_REALM_ROLES", "reader, writer")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8080" || c.ClockSkew != 30*time.Second || c.JWKSRefreshInterval != 5*time.Minute ||
		c.HeaderUser != "X-Custom-User" || len(c.RequiredRealmRoles) != 2 || c.RequiredRealmRoles[1] != "writer" {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestValidateDoesNotMutateRoleSlices(t *testing.T) {
	realm := make([]string, 1, 4)
	realm[0] = "reader"
	c := Config{
		Issuer:              "https://keycloak.example/realms/example",
		Audience:            "service",
		ListenAddr:          ":8080",
		ClientID:            "app",
		RequiredRealmRoles:  realm,
		RequiredClientRoles: []string{"writer"},
		JWKSRefreshInterval: time.Minute,
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	extended := realm[:2]
	if extended[1] != "" {
		t.Fatalf("Validate mutated backing array of RequiredRealmRoles: %q", extended[1])
	}
}

func TestValidateRejectsInvalidConfiguration(t *testing.T) {
	base := Config{Issuer: "https://keycloak.example/realms/example", Audience: "service", ListenAddr: ":8080", JWKSRefreshInterval: time.Minute}
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"missing issuer", func(c *Config) { c.Issuer = "" }},
		{"issuer credentials", func(c *Config) { c.Issuer = "https://user@example.com" }},
		{"missing audience", func(c *Config) { c.Audience = "" }},
		{"upstream scheme", func(c *Config) { c.UpstreamURL = "file:///etc/passwd" }},
		{"invalid address", func(c *Config) { c.ListenAddr = "8080" }},
		{"clock skew", func(c *Config) { c.ClockSkew = 31 * time.Second }},
		{"refresh interval", func(c *Config) { c.JWKSRefreshInterval = 0 }},
		{"refresh interval too long", func(c *Config) { c.JWKSRefreshInterval = 13 * time.Hour }},
		{"client role without client", func(c *Config) { c.RequiredClientRoles = []string{"admin"} }},
		{"whitespace client id", func(c *Config) { c.ClientID = "  " }},
		{"empty realm role", func(c *Config) { c.RequiredRealmRoles = []string{""} }},
		{"empty client role", func(c *Config) { c.ClientID = "app"; c.RequiredClientRoles = []string{""} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base
			tt.edit(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("expected invalid configuration")
			}
		})
	}
}
