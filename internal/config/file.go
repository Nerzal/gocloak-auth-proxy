package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type fileConfig struct {
	Issuer               *string           `json:"issuer"`
	Audience             *string           `json:"audience"`
	UpstreamURL          *string           `json:"upstream_url"`
	ListenAddr           *string           `json:"listen_addr"`
	MetricsAddr          *string           `json:"metrics_addr"`
	LogLevel             *string           `json:"log_level"`
	ClientID             *string           `json:"client_id"`
	ClientSecret         *string           `json:"client_secret"`
	HeaderUser           *string           `json:"header_user"`
	HeaderEmail          *string           `json:"header_email"`
	HeaderGroups         *string           `json:"header_groups"`
	HeaderRoles          *string           `json:"header_roles"`
	CustomClaimHeaders   map[string]string `json:"custom_claim_headers"`
	PassAccessToken      *bool             `json:"pass_access_token"`
	AllowedAlgorithms    []string          `json:"allowed_algorithms"`
	RequiredRealmRoles   []string          `json:"required_realm_roles"`
	RequiredClientRoles  []string          `json:"required_client_roles"`
	RoleMatchMode        *string           `json:"role_match_mode"`
	RequiredGroups       []string          `json:"required_groups"`
	GroupMatchMode       *string           `json:"group_match_mode"`
	RequiredScopes       []string          `json:"required_scopes"`
	RequiredACR          []string          `json:"required_acr"`
	RequiredAMR          []string          `json:"required_amr"`
	RequireEmailVerified *bool             `json:"require_email_verified"`
	RequiredAZP          *string           `json:"required_azp"`
	RequiredOrganization *string           `json:"required_organization"`
	JWKSRefreshInterval  *string           `json:"jwks_refresh_interval"`
	ClockSkew            *string           `json:"clock_skew"`

	KeycloakCAFile          *string `json:"keycloak_ca_file"`
	KeycloakClientCertFile  *string `json:"keycloak_client_cert_file"`
	KeycloakClientKeyFile   *string `json:"keycloak_client_key_file"`
	UpstreamCAFile          *string `json:"upstream_ca_file"`
	UpstreamClientCertFile  *string `json:"upstream_client_cert_file"`
	UpstreamClientKeyFile   *string `json:"upstream_client_key_file"`
	TLSCertFile             *string `json:"tls_cert_file"`
	TLSKeyFile              *string `json:"tls_key_file"`
	ServerReadHeaderTimeout *string `json:"server_read_header_timeout"`
	ServerReadTimeout       *string `json:"server_read_timeout"`
	ServerWriteTimeout      *string `json:"server_write_timeout"`
	ServerIdleTimeout       *string `json:"server_idle_timeout"`
	UpstreamHeaderTimeout   *string `json:"upstream_header_timeout"`
	UpstreamRequestTimeout  *string `json:"upstream_request_timeout"`

	IntrospectionEnabled  *bool    `json:"introspection_enabled"`
	IntrospectionCacheTTL *string  `json:"introspection_cache_ttl"`
	UMAEnabled            *bool    `json:"uma_enabled"`
	UMAMethodScope        *bool    `json:"uma_method_scope"`
	PublicPaths           []string `json:"public_paths"`
	OptionalAuthPaths     []string `json:"optional_auth_paths"`
	AllowCORSPreflight    *bool    `json:"allow_cors_preflight"`
	RouteRules            []string `json:"route_rules"`

	OIDCEnabled                *bool    `json:"oidc_enabled"`
	OIDCRedirectURL            *string  `json:"oidc_redirect_url"`
	OIDCPostLogoutURL          *string  `json:"oidc_post_logout_url"`
	OIDCCookieSecret           *string  `json:"oidc_cookie_secret"`
	OIDCCookieName             *string  `json:"oidc_cookie_name"`
	OIDCCookieDomain           *string  `json:"oidc_cookie_domain"`
	OIDCCookieSecure           *bool    `json:"oidc_cookie_secure"`
	OIDCCookieSameSite         *string  `json:"oidc_cookie_samesite"`
	OIDCScopes                 []string `json:"oidc_scopes"`
	OIDCSessionMaxAge          *string  `json:"oidc_session_max_age"`
	OIDCRedirectUnauth         *bool    `json:"oidc_redirect"`
	OIDCAllowedRedirectDomains []string `json:"oidc_allowed_redirect_domains"`
}

func applyConfigFile(path string, c *Config) error {
	// #nosec G304 -- CONFIG_FILE is explicitly configured by the operator at startup.
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read CONFIG_FILE: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var fc fileConfig
	if err := dec.Decode(&fc); err != nil {
		return fmt.Errorf("parse CONFIG_FILE: %w", err)
	}
	setStr := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	setBool := func(dst *bool, src *bool) {
		if src != nil {
			*dst = *src
		}
	}
	setDur := func(dst *time.Duration, src *string, name string) error {
		if src == nil || *src == "" {
			return nil
		}
		v, err := time.ParseDuration(*src)
		if err != nil {
			return fmt.Errorf("invalid %s in CONFIG_FILE", name)
		}
		*dst = v
		return nil
	}

	setStr(&c.Issuer, fc.Issuer)
	setStr(&c.Audience, fc.Audience)
	setStr(&c.UpstreamURL, fc.UpstreamURL)
	setStr(&c.ListenAddr, fc.ListenAddr)
	setStr(&c.MetricsAddr, fc.MetricsAddr)
	setStr(&c.LogLevel, fc.LogLevel)
	setStr(&c.ClientID, fc.ClientID)
	setStr(&c.ClientSecret, fc.ClientSecret)
	setStr(&c.HeaderUser, fc.HeaderUser)
	setStr(&c.HeaderEmail, fc.HeaderEmail)
	setStr(&c.HeaderGroups, fc.HeaderGroups)
	setStr(&c.HeaderRoles, fc.HeaderRoles)
	if fc.CustomClaimHeaders != nil {
		c.CustomClaimHeaders = fc.CustomClaimHeaders
	}
	setBool(&c.PassAccessToken, fc.PassAccessToken)
	if fc.AllowedAlgorithms != nil {
		c.AllowedAlgorithms = fc.AllowedAlgorithms
	}
	if fc.RequiredRealmRoles != nil {
		c.RequiredRealmRoles = fc.RequiredRealmRoles
	}
	if fc.RequiredClientRoles != nil {
		c.RequiredClientRoles = fc.RequiredClientRoles
	}
	if fc.RoleMatchMode != nil {
		anyMode, err := parseMatchModeValue("role_match_mode", *fc.RoleMatchMode)
		if err != nil {
			return err
		}
		c.RequireAnyRole = anyMode
	}
	if fc.RequiredGroups != nil {
		c.RequiredGroups = fc.RequiredGroups
	}
	if fc.GroupMatchMode != nil {
		anyMode, err := parseMatchModeValue("group_match_mode", *fc.GroupMatchMode)
		if err != nil {
			return err
		}
		c.RequireAnyGroup = anyMode
	}
	if fc.RequiredScopes != nil {
		c.RequiredScopes = fc.RequiredScopes
	}
	if fc.RequiredACR != nil {
		c.RequiredACR = fc.RequiredACR
	}
	if fc.RequiredAMR != nil {
		c.RequiredAMR = fc.RequiredAMR
	}
	setBool(&c.RequireEmailVerified, fc.RequireEmailVerified)
	setStr(&c.RequiredAZP, fc.RequiredAZP)
	setStr(&c.RequiredOrganization, fc.RequiredOrganization)
	if err := setDur(&c.JWKSRefreshInterval, fc.JWKSRefreshInterval, "jwks_refresh_interval"); err != nil {
		return err
	}
	if err := setDur(&c.ClockSkew, fc.ClockSkew, "clock_skew"); err != nil {
		return err
	}

	setStr(&c.KeycloakCAFile, fc.KeycloakCAFile)
	setStr(&c.KeycloakClientCertFile, fc.KeycloakClientCertFile)
	setStr(&c.KeycloakClientKeyFile, fc.KeycloakClientKeyFile)
	setStr(&c.UpstreamCAFile, fc.UpstreamCAFile)
	setStr(&c.UpstreamClientCertFile, fc.UpstreamClientCertFile)
	setStr(&c.UpstreamClientKeyFile, fc.UpstreamClientKeyFile)
	setStr(&c.TLSCertFile, fc.TLSCertFile)
	setStr(&c.TLSKeyFile, fc.TLSKeyFile)
	if err := setDur(&c.ServerReadHeaderTimeout, fc.ServerReadHeaderTimeout, "server_read_header_timeout"); err != nil {
		return err
	}
	if err := setDur(&c.ServerReadTimeout, fc.ServerReadTimeout, "server_read_timeout"); err != nil {
		return err
	}
	if err := setDur(&c.ServerWriteTimeout, fc.ServerWriteTimeout, "server_write_timeout"); err != nil {
		return err
	}
	if err := setDur(&c.ServerIdleTimeout, fc.ServerIdleTimeout, "server_idle_timeout"); err != nil {
		return err
	}
	if err := setDur(&c.UpstreamHeaderTimeout, fc.UpstreamHeaderTimeout, "upstream_header_timeout"); err != nil {
		return err
	}
	if fc.UpstreamRequestTimeout != nil && *fc.UpstreamRequestTimeout != "" {
		v, err := time.ParseDuration(*fc.UpstreamRequestTimeout)
		if err != nil {
			return errors.New("invalid upstream_request_timeout in CONFIG_FILE")
		}
		c.UpstreamRequestTimeout = v
		c.DisableUpstreamTimeout = (v == 0)
	}

	setBool(&c.IntrospectionEnabled, fc.IntrospectionEnabled)
	if err := setDur(&c.IntrospectionCacheTTL, fc.IntrospectionCacheTTL, "introspection_cache_ttl"); err != nil {
		return err
	}
	setBool(&c.UMAEnabled, fc.UMAEnabled)
	setBool(&c.UMAMethodScope, fc.UMAMethodScope)
	if fc.PublicPaths != nil {
		c.PublicPaths = fc.PublicPaths
	}
	if fc.OptionalAuthPaths != nil {
		c.OptionalAuthPaths = fc.OptionalAuthPaths
	}
	setBool(&c.AllowCORSPreflight, fc.AllowCORSPreflight)
	if fc.RouteRules != nil {
		c.RouteRules = fc.RouteRules
	}

	setBool(&c.OIDCEnabled, fc.OIDCEnabled)
	setStr(&c.OIDCRedirectURL, fc.OIDCRedirectURL)
	setStr(&c.OIDCPostLogoutURL, fc.OIDCPostLogoutURL)
	setStr(&c.OIDCCookieSecret, fc.OIDCCookieSecret)
	setStr(&c.OIDCCookieName, fc.OIDCCookieName)
	setStr(&c.OIDCCookieDomain, fc.OIDCCookieDomain)
	setBool(&c.OIDCCookieSecure, fc.OIDCCookieSecure)
	if fc.OIDCCookieSameSite != nil {
		ss, err := parseSameSite(*fc.OIDCCookieSameSite)
		if err != nil {
			return err
		}
		c.OIDCCookieSameSite = ss
	}
	if fc.OIDCScopes != nil {
		c.OIDCScopes = fc.OIDCScopes
	}
	if err := setDur(&c.OIDCSessionMaxAge, fc.OIDCSessionMaxAge, "oidc_session_max_age"); err != nil {
		return err
	}
	setBool(&c.OIDCRedirectUnauth, fc.OIDCRedirectUnauth)
	if fc.OIDCAllowedRedirectDomains != nil {
		c.OIDCAllowedRedirectDomains = fc.OIDCAllowedRedirectDomains
	}
	return nil
}

func parseMatchModeValue(name, raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "all":
		return false, nil
	case "any":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be 'all' or 'any'", name)
	}
}
