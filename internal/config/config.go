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
	RequireEmailVerified bool
	RequiredAZP          string
	RequiredOrganization string
	JWKSRefreshInterval  time.Duration
	ClockSkew            time.Duration

	// TLS & Timeouts (Milestone 1)
	KeycloakCAFile          string
	UpstreamCAFile          string
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

	// OIDC Browser SSO (Milestone 3)
	OIDCEnabled        bool
	OIDCRedirectURL    string
	OIDCPostLogoutURL  string
	OIDCCookieSecret   string
	OIDCCookieName     string
	OIDCCookieSecure   bool
	OIDCCookieSameSite http.SameSite
	OIDCScopes         []string
	OIDCSessionMaxAge  time.Duration
	OIDCRedirectUnauth bool
}

func Load() (Config, error) {
	c := Config{
		Issuer:               os.Getenv("ISSUER"),
		Audience:             os.Getenv("AUDIENCE"),
		UpstreamURL:          os.Getenv("UPSTREAM_URL"),
		ListenAddr:           envDefault("LISTEN_ADDR", ":8080"),
		MetricsAddr:          os.Getenv("METRICS_ADDR"),
		LogLevel:             envDefault("LOG_LEVEL", "info"),
		ClientID:             os.Getenv("CLIENT_ID"),
		ClientSecret:         os.Getenv("CLIENT_SECRET"),
		HeaderUser:           os.Getenv("HEADER_USER"),
		HeaderEmail:          os.Getenv("HEADER_EMAIL"),
		HeaderGroups:         os.Getenv("HEADER_GROUPS"),
		HeaderRoles:          os.Getenv("HEADER_ROLES"),
		AllowedAlgorithms:    csvList(os.Getenv("ALLOWED_ALGORITHMS")),
		RequiredRealmRoles:   csvList(os.Getenv("REQUIRED_REALM_ROLES")),
		RequiredClientRoles:  csvList(os.Getenv("REQUIRED_CLIENT_ROLES")),
		RequiredGroups:       csvList(os.Getenv("REQUIRED_GROUPS")),
		RequiredScopes:       csvList(os.Getenv("REQUIRED_SCOPES")),
		RequiredACR:          csvList(os.Getenv("REQUIRED_ACR")),
		RequiredAZP:          os.Getenv("REQUIRED_AZP"),
		RequiredOrganization: os.Getenv("REQUIRED_ORGANIZATION"),
		KeycloakCAFile:       os.Getenv("KEYCLOAK_CA_FILE"),
		UpstreamCAFile:       os.Getenv("UPSTREAM_CA_FILE"),
		TLSCertFile:          os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:           os.Getenv("TLS_KEY_FILE"),
		PublicPaths:          csvList(os.Getenv("PUBLIC_PATHS")),
		OptionalAuthPaths:    csvList(os.Getenv("OPTIONAL_AUTH_PATHS")),
		RouteRules:           semiList(os.Getenv("ROUTE_RULES")),
		OIDCRedirectURL:      os.Getenv("OIDC_REDIRECT_URL"),
		OIDCPostLogoutURL:    envDefault("OIDC_POST_LOGOUT_URL", "/"),
		OIDCCookieSecret:     os.Getenv("OIDC_COOKIE_SECRET"),
		OIDCCookieName:       os.Getenv("OIDC_COOKIE_NAME"),
		OIDCScopes:           csvList(os.Getenv("OIDC_SCOPES")),
	}
	var err error
	if c.CustomClaimHeaders, err = parseMapping(os.Getenv("CUSTOM_CLAIM_HEADERS")); err != nil {
		return Config{}, err
	}
	if c.RequireAnyRole, err = parseMatchMode("ROLE_MATCH_MODE"); err != nil {
		return Config{}, err
	}
	if c.RequireAnyGroup, err = parseMatchMode("GROUP_MATCH_MODE"); err != nil {
		return Config{}, err
	}
	if c.PassAccessToken, err = envBool("PASS_ACCESS_TOKEN", false); err != nil {
		return Config{}, err
	}
	if c.RequireEmailVerified, err = envBool("REQUIRE_EMAIL_VERIFIED", false); err != nil {
		return Config{}, err
	}
	if c.IntrospectionEnabled, err = envBool("INTROSPECTION_ENABLED", false); err != nil {
		return Config{}, err
	}
	if c.UMAEnabled, err = envBool("UMA_ENABLED", false); err != nil {
		return Config{}, err
	}
	if c.UMAMethodScope, err = envBool("UMA_METHOD_SCOPE", false); err != nil {
		return Config{}, err
	}
	if c.AllowCORSPreflight, err = envBool("ALLOW_CORS_PREFLIGHT", false); err != nil {
		return Config{}, err
	}
	if c.OIDCEnabled, err = envBool("OIDC_ENABLED", false); err != nil {
		return Config{}, err
	}
	if c.OIDCCookieSecure, err = envBool("OIDC_COOKIE_SECURE", true); err != nil {
		return Config{}, err
	}
	if c.OIDCRedirectUnauth, err = envBool("OIDC_REDIRECT", true); err != nil {
		return Config{}, err
	}
	if c.OIDCCookieSameSite, err = parseSameSite(os.Getenv("OIDC_COOKIE_SAMESITE")); err != nil {
		return Config{}, err
	}
	if c.JWKSRefreshInterval, err = duration("JWKS_REFRESH_INTERVAL", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if c.ClockSkew, err = duration("CLOCK_SKEW", 30*time.Second); err != nil {
		return Config{}, err
	}
	if c.ServerReadHeaderTimeout, err = duration("SERVER_READ_HEADER_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if c.ServerReadTimeout, err = duration("SERVER_READ_TIMEOUT", 15*time.Second); err != nil {
		return Config{}, err
	}
	if c.ServerWriteTimeout, err = duration("SERVER_WRITE_TIMEOUT", 30*time.Second); err != nil {
		return Config{}, err
	}
	if c.ServerIdleTimeout, err = duration("SERVER_IDLE_TIMEOUT", 60*time.Second); err != nil {
		return Config{}, err
	}
	if c.UpstreamHeaderTimeout, err = duration("UPSTREAM_HEADER_TIMEOUT", 15*time.Second); err != nil {
		return Config{}, err
	}
	if os.Getenv("UPSTREAM_REQUEST_TIMEOUT") != "" {
		v, err := duration("UPSTREAM_REQUEST_TIMEOUT", 25*time.Second)
		if err != nil {
			return Config{}, err
		}
		c.UpstreamRequestTimeout = v
		if v == 0 {
			c.DisableUpstreamTimeout = true
		}
	} else {
		c.UpstreamRequestTimeout = 25 * time.Second
	}
	if c.IntrospectionCacheTTL, err = duration("INTROSPECTION_CACHE_TTL", 15*time.Second); err != nil {
		return Config{}, err
	}
	if c.OIDCSessionMaxAge, err = duration("OIDC_SESSION_MAX_AGE", 24*time.Hour); err != nil {
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

func envBool(name string, fallback bool) (bool, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid %s", name)
	}
	return b, nil
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
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "all":
		return false, nil
	case "any":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be 'all' or 'any'", name)
	}
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
	for _, list := range [][]string{c.RequiredRealmRoles, c.RequiredClientRoles, c.RequiredGroups, c.RequiredScopes, c.RequiredACR} {
		for _, item := range list {
			if item == "" {
				return errors.New("role, group, scope, and ACR names must not be empty")
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
