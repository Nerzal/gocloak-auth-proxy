package config

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Issuer               string
	Audience             string
	UpstreamURL          string
	ListenAddr           string
	MetricsAddr          string
	LogLevel             string
	ClientID             string
	ClientSecret         string
	HeaderUser           string
	HeaderEmail          string
	HeaderGroups         string
	HeaderRoles          string
	CustomClaimHeaders   map[string]string
	PassAccessToken      bool
	AllowedAlgorithms    []string
	RequiredRealmRoles   []string
	RequiredClientRoles  []string
	RequireAnyRole       bool
	RequiredGroups       []string
	RequireAnyGroup      bool
	RequiredScopes       []string
	RequiredACR          []string
	RequiredAMR          []string
	RequireEmailVerified bool
	RequiredAZP          string
	RequiredOrganization string
	JWKSRefreshInterval  time.Duration
	ClockSkew            time.Duration

	// TLS & Timeouts (Milestone 1 + mTLS)
	KeycloakCAFile          string
	KeycloakClientCertFile  string
	KeycloakClientKeyFile   string
	UpstreamCAFile          string
	UpstreamClientCertFile  string
	UpstreamClientKeyFile   string
	TLSCertFile             string
	TLSKeyFile              string
	ServerReadHeaderTimeout time.Duration
	ServerReadTimeout       time.Duration
	ServerWriteTimeout      time.Duration
	ServerIdleTimeout       time.Duration
	UpstreamHeaderTimeout   time.Duration
	UpstreamRequestTimeout  time.Duration
	DisableUpstreamTimeout  bool

	// Keycloak online & ACLs (Milestone 2)
	IntrospectionEnabled  bool
	IntrospectionCacheTTL time.Duration
	UMAEnabled            bool
	UMAMethodScope        bool
	PublicPaths           []string
	OptionalAuthPaths     []string
	AllowCORSPreflight    bool
	RouteRules            []string

	// OIDC Browser SSO (Milestone 3 + Multi-Domain / Backchannel Logout)
	OIDCEnabled                bool
	OIDCRedirectURL            string
	OIDCPostLogoutURL          string
	OIDCCookieSecret           string
	OIDCCookieName             string
	OIDCCookieDomain           string
	OIDCCookieSecure           bool
	OIDCCookieSameSite         http.SameSite
	OIDCScopes                 []string
	OIDCSessionMaxAge          time.Duration
	OIDCRedirectUnauth         bool
	OIDCAllowedRedirectDomains []string
}

func Load() (Config, error) {
	c := Config{
		ListenAddr:              ":8080",
		LogLevel:                "info",
		JWKSRefreshInterval:     5 * time.Minute,
		ClockSkew:               30 * time.Second,
		ServerReadHeaderTimeout: 5 * time.Second,
		ServerReadTimeout:       15 * time.Second,
		ServerWriteTimeout:      30 * time.Second,
		ServerIdleTimeout:       60 * time.Second,
		UpstreamHeaderTimeout:   15 * time.Second,
		UpstreamRequestTimeout:  25 * time.Second,
		IntrospectionCacheTTL:   15 * time.Second,
		OIDCPostLogoutURL:       "/",
		OIDCCookieSecure:        true,
		OIDCCookieSameSite:      http.SameSiteLaxMode,
		OIDCSessionMaxAge:       24 * time.Hour,
		OIDCRedirectUnauth:      true,
	}
	if path := strings.TrimSpace(os.Getenv("CONFIG_FILE")); path != "" {
		if err := applyConfigFile(path, &c); err != nil {
			return Config{}, err
		}
	}

	overrideStr := func(dst *string, envName string) {
		if v := os.Getenv(envName); v != "" {
			*dst = v
		}
	}
	overrideCSV := func(dst *[]string, envName string) {
		if v := os.Getenv(envName); v != "" {
			*dst = csvList(v)
		}
	}
	overrideBool := func(dst *bool, envName string) error {
		v := strings.TrimSpace(os.Getenv(envName))
		if v == "" {
			return nil
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid %s", envName)
		}
		*dst = b
		return nil
	}
	overrideDur := func(dst *time.Duration, envName string) error {
		v := os.Getenv(envName)
		if v == "" {
			return nil
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid %s", envName)
		}
		*dst = d
		return nil
	}

	overrideStr(&c.Issuer, "ISSUER")
	overrideStr(&c.Audience, "AUDIENCE")
	overrideStr(&c.UpstreamURL, "UPSTREAM_URL")
	overrideStr(&c.ListenAddr, "LISTEN_ADDR")
	overrideStr(&c.MetricsAddr, "METRICS_ADDR")
	overrideStr(&c.LogLevel, "LOG_LEVEL")
	overrideStr(&c.ClientID, "CLIENT_ID")
	overrideStr(&c.ClientSecret, "CLIENT_SECRET")
	overrideStr(&c.HeaderUser, "HEADER_USER")
	overrideStr(&c.HeaderEmail, "HEADER_EMAIL")
	overrideStr(&c.HeaderGroups, "HEADER_GROUPS")
	overrideStr(&c.HeaderRoles, "HEADER_ROLES")
	overrideCSV(&c.AllowedAlgorithms, "ALLOWED_ALGORITHMS")
	overrideCSV(&c.RequiredRealmRoles, "REQUIRED_REALM_ROLES")
	overrideCSV(&c.RequiredClientRoles, "REQUIRED_CLIENT_ROLES")
	overrideCSV(&c.RequiredGroups, "REQUIRED_GROUPS")
	overrideCSV(&c.RequiredScopes, "REQUIRED_SCOPES")
	overrideCSV(&c.RequiredACR, "REQUIRED_ACR")
	overrideCSV(&c.RequiredAMR, "REQUIRED_AMR")
	overrideStr(&c.RequiredAZP, "REQUIRED_AZP")
	overrideStr(&c.RequiredOrganization, "REQUIRED_ORGANIZATION")
	overrideStr(&c.KeycloakCAFile, "KEYCLOAK_CA_FILE")
	overrideStr(&c.KeycloakClientCertFile, "KEYCLOAK_CLIENT_CERT_FILE")
	overrideStr(&c.KeycloakClientKeyFile, "KEYCLOAK_CLIENT_KEY_FILE")
	overrideStr(&c.UpstreamCAFile, "UPSTREAM_CA_FILE")
	overrideStr(&c.UpstreamClientCertFile, "UPSTREAM_CLIENT_CERT_FILE")
	overrideStr(&c.UpstreamClientKeyFile, "UPSTREAM_CLIENT_KEY_FILE")
	overrideStr(&c.TLSCertFile, "TLS_CERT_FILE")
	overrideStr(&c.TLSKeyFile, "TLS_KEY_FILE")
	overrideCSV(&c.PublicPaths, "PUBLIC_PATHS")
	overrideCSV(&c.OptionalAuthPaths, "OPTIONAL_AUTH_PATHS")
	if v := os.Getenv("ROUTE_RULES"); v != "" {
		c.RouteRules = semiList(v)
	}
	overrideStr(&c.OIDCRedirectURL, "OIDC_REDIRECT_URL")
	overrideStr(&c.OIDCPostLogoutURL, "OIDC_POST_LOGOUT_URL")
	overrideStr(&c.OIDCCookieSecret, "OIDC_COOKIE_SECRET")
	overrideStr(&c.OIDCCookieName, "OIDC_COOKIE_NAME")
	overrideStr(&c.OIDCCookieDomain, "OIDC_COOKIE_DOMAIN")
	overrideCSV(&c.OIDCScopes, "OIDC_SCOPES")
	overrideCSV(&c.OIDCAllowedRedirectDomains, "OIDC_ALLOWED_REDIRECT_DOMAINS")

	var err error
	if v := os.Getenv("CUSTOM_CLAIM_HEADERS"); v != "" {
		if c.CustomClaimHeaders, err = parseMapping(v); err != nil {
			return Config{}, err
		}
	}
	if os.Getenv("ROLE_MATCH_MODE") != "" {
		if c.RequireAnyRole, err = parseMatchMode("ROLE_MATCH_MODE"); err != nil {
			return Config{}, err
		}
	}
	if os.Getenv("GROUP_MATCH_MODE") != "" {
		if c.RequireAnyGroup, err = parseMatchMode("GROUP_MATCH_MODE"); err != nil {
			return Config{}, err
		}
	}
	for _, item := range []struct {
		dst *bool
		env string
	}{
		{&c.PassAccessToken, "PASS_ACCESS_TOKEN"},
		{&c.RequireEmailVerified, "REQUIRE_EMAIL_VERIFIED"},
		{&c.IntrospectionEnabled, "INTROSPECTION_ENABLED"},
		{&c.UMAEnabled, "UMA_ENABLED"},
		{&c.UMAMethodScope, "UMA_METHOD_SCOPE"},
		{&c.AllowCORSPreflight, "ALLOW_CORS_PREFLIGHT"},
		{&c.OIDCEnabled, "OIDC_ENABLED"},
		{&c.OIDCCookieSecure, "OIDC_COOKIE_SECURE"},
		{&c.OIDCRedirectUnauth, "OIDC_REDIRECT"},
	} {
		if err = overrideBool(item.dst, item.env); err != nil {
			return Config{}, err
		}
	}
	if v := os.Getenv("OIDC_COOKIE_SAMESITE"); v != "" {
		if c.OIDCCookieSameSite, err = parseSameSite(v); err != nil {
			return Config{}, err
		}
	}
	for _, item := range []struct {
		dst *time.Duration
		env string
	}{
		{&c.JWKSRefreshInterval, "JWKS_REFRESH_INTERVAL"},
		{&c.ClockSkew, "CLOCK_SKEW"},
		{&c.ServerReadHeaderTimeout, "SERVER_READ_HEADER_TIMEOUT"},
		{&c.ServerReadTimeout, "SERVER_READ_TIMEOUT"},
		{&c.ServerWriteTimeout, "SERVER_WRITE_TIMEOUT"},
		{&c.ServerIdleTimeout, "SERVER_IDLE_TIMEOUT"},
		{&c.UpstreamHeaderTimeout, "UPSTREAM_HEADER_TIMEOUT"},
		{&c.IntrospectionCacheTTL, "INTROSPECTION_CACHE_TTL"},
		{&c.OIDCSessionMaxAge, "OIDC_SESSION_MAX_AGE"},
	} {
		if err = overrideDur(item.dst, item.env); err != nil {
			return Config{}, err
		}
	}
	if os.Getenv("UPSTREAM_REQUEST_TIMEOUT") != "" {
		if err = overrideDur(&c.UpstreamRequestTimeout, "UPSTREAM_REQUEST_TIMEOUT"); err != nil {
			return Config{}, err
		}
		c.DisableUpstreamTimeout = (c.UpstreamRequestTimeout == 0)
	}
	if err = c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func csvList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func semiList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseMapping(value string) (map[string]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		h, c, ok := strings.Cut(entry, "=")
		h, c = strings.TrimSpace(h), strings.TrimSpace(c)
		if !ok || h == "" || c == "" {
			return nil, errors.New("CUSTOM_CLAIM_HEADERS entries must be Header-Name=claim_name")
		}
		out[h] = c
	}
	return out, nil
}

func parseMatchMode(name string) (bool, error) {
	return parseMatchModeValue(name, os.Getenv(name))
}

func parseSameSite(value string) (http.SameSite, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return 0, errors.New("OIDC_COOKIE_SAMESITE must be lax, strict, or none")
	}
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
	if c.MetricsAddr != "" {
		if _, _, err := net.SplitHostPort(c.MetricsAddr); err != nil {
			return errors.New("invalid METRICS_ADDR")
		}
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("TLS_CERT_FILE and TLS_KEY_FILE must both be set")
	}
	if (c.KeycloakClientCertFile == "") != (c.KeycloakClientKeyFile == "") {
		return errors.New("KEYCLOAK_CLIENT_CERT_FILE and KEYCLOAK_CLIENT_KEY_FILE must both be set")
	}
	if (c.UpstreamClientCertFile == "") != (c.UpstreamClientKeyFile == "") {
		return errors.New("UPSTREAM_CLIENT_CERT_FILE and UPSTREAM_CLIENT_KEY_FILE must both be set")
	}
	if c.JWKSRefreshInterval < time.Second || c.JWKSRefreshInterval > 12*time.Hour {
		return errors.New("JWKS_REFRESH_INTERVAL must be between 1s and 12h")
	}
	if c.ClockSkew < 0 || c.ClockSkew > 30*time.Second {
		return errors.New("CLOCK_SKEW must be between 0 and 30s")
	}
	if c.ServerReadHeaderTimeout < 0 || c.ServerReadTimeout < 0 || c.ServerWriteTimeout < 0 ||
		c.ServerIdleTimeout < 0 || c.UpstreamHeaderTimeout < 0 || c.UpstreamRequestTimeout < 0 {
		return errors.New("timeouts must not be negative")
	}
	if c.ClientID != "" && strings.TrimSpace(c.ClientID) != c.ClientID {
		return errors.New("CLIENT_ID must not contain leading or trailing whitespace")
	}
	if len(c.RequiredClientRoles) > 0 && c.ClientID == "" {
		return errors.New("CLIENT_ID is required for client roles")
	}
	if c.IntrospectionEnabled {
		if c.ClientID == "" || c.ClientSecret == "" {
			return errors.New("CLIENT_ID and CLIENT_SECRET are required when INTROSPECTION_ENABLED=true")
		}
		if c.IntrospectionCacheTTL < 0 || c.IntrospectionCacheTTL > 5*time.Minute {
			return errors.New("INTROSPECTION_CACHE_TTL must be between 0 and 5m")
		}
	}
	if c.OIDCEnabled {
		if c.ClientID == "" {
			return errors.New("CLIENT_ID is required when OIDC_ENABLED=true")
		}
		if len(c.OIDCCookieSecret) < 32 {
			return errors.New("OIDC_COOKIE_SECRET must be at least 32 characters when OIDC_ENABLED=true")
		}
		if err := validURL(c.OIDCRedirectURL); err != nil {
			return errors.New("OIDC_REDIRECT_URL must be an absolute HTTP(S) URL when OIDC_ENABLED=true")
		}
		if c.OIDCCookieSameSite == http.SameSiteNoneMode && !c.OIDCCookieSecure {
			return errors.New("OIDC_COOKIE_SAMESITE=none requires OIDC_COOKIE_SECURE=true")
		}
		if c.OIDCPostLogoutURL != "" && !validPostLogoutURL(c.OIDCPostLogoutURL) {
			return errors.New("OIDC_POST_LOGOUT_URL must be a safe relative path or absolute HTTP(S) URL")
		}
	}
	if c.UpstreamURL == "" && (c.UMAEnabled || len(c.RouteRules) > 0) {
		return errors.New("UMA_ENABLED and ROUTE_RULES require UPSTREAM_URL (reverse-proxy mode)")
	}
	for _, list := range [][]string{c.RequiredRealmRoles, c.RequiredClientRoles, c.RequiredGroups, c.RequiredScopes, c.RequiredACR, c.RequiredAMR} {
		for _, item := range list {
			if item == "" {
				return errors.New("role, group, scope, ACR, and AMR names must not be empty")
			}
		}
	}
	return nil
}

func validPostLogoutURL(value string) bool {
	if strings.HasPrefix(value, "/") {
		if strings.HasPrefix(value, "//") || strings.HasPrefix(value, "/\\") {
			return false
		}
		for _, r := range value {
			if r < 32 || r == 127 {
				return false
			}
		}
		return true
	}
	return validURL(value) == nil
}

func validURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errors.New("invalid URL")
	}
	return nil
}
