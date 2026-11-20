package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	Issuer              string
	Audience            string
	UpstreamURL         string
	ListenAddr          string
	ClientID            string
	HeaderUser          string
	HeaderEmail         string
	HeaderGroups        string
	HeaderRoles         string
	RequiredRealmRoles  []string
	RequiredClientRoles []string
	JWKSRefreshInterval time.Duration
	ClockSkew           time.Duration
}

func Load() (Config, error) {
	c := Config{
		Issuer:              os.Getenv("ISSUER"),
		Audience:            os.Getenv("AUDIENCE"),
		UpstreamURL:         os.Getenv("UPSTREAM_URL"),
		ListenAddr:          envDefault("LISTEN_ADDR", ":8080"),
		ClientID:            os.Getenv("CLIENT_ID"),
		HeaderUser:          os.Getenv("HEADER_USER"),
		HeaderEmail:         os.Getenv("HEADER_EMAIL"),
		HeaderGroups:        os.Getenv("HEADER_GROUPS"),
		HeaderRoles:         os.Getenv("HEADER_ROLES"),
		RequiredRealmRoles:  roles(os.Getenv("REQUIRED_REALM_ROLES")),
		RequiredClientRoles: roles(os.Getenv("REQUIRED_CLIENT_ROLES")),
	}
	var err error
	if c.JWKSRefreshInterval, err = duration("JWKS_REFRESH_INTERVAL", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if c.ClockSkew, err = duration("CLOCK_SKEW", 30*time.Second); err != nil {
		return Config{}, err
	}
	if err = c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func envDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func duration(name string, fallback time.Duration) (time.Duration, error) {
	if value := os.Getenv(name); value != "" {
		v, err := time.ParseDuration(value)
		if err != nil {
			return 0, fmt.Errorf("invalid %s", name)
		}
		return v, nil
	}
	return fallback, nil
}

func roles(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func (c Config) Validate() error {
	if err := validURL(c.Issuer); err != nil {
		return errors.New("ISSUER must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	if c.Audience == "" || strings.TrimSpace(c.Audience) != c.Audience {
		return errors.New("AUDIENCE is required")
	}
	if c.UpstreamURL != "" {
		if err := validURL(c.UpstreamURL); err != nil {
			return errors.New("UPSTREAM_URL must be an absolute HTTP(S) URL without credentials, query, or fragment")
		}
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return errors.New("invalid LISTEN_ADDR")
	}
	if c.JWKSRefreshInterval < time.Second || c.JWKSRefreshInterval > 12*time.Hour {
		return errors.New("JWKS_REFRESH_INTERVAL must be between 1s and 12h")
	}
	if c.ClockSkew < 0 || c.ClockSkew > 30*time.Second {
		return errors.New("CLOCK_SKEW must be between 0 and 30s")
	}
	if c.ClientID != "" && strings.TrimSpace(c.ClientID) != c.ClientID {
		return errors.New("CLIENT_ID must not contain leading or trailing whitespace")
	}
	if len(c.RequiredClientRoles) > 0 && c.ClientID == "" {
		return errors.New("CLIENT_ID is required for client roles")
	}
	for _, role := range c.RequiredRealmRoles {
		if role == "" {
			return errors.New("role names must not be empty")
		}
	}
	for _, role := range c.RequiredClientRoles {
		if role == "" {
			return errors.New("role names must not be empty")
		}
	}
	return nil
}

func validURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errors.New("invalid URL")
	}
	return nil
}
