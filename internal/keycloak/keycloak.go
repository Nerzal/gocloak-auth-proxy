// Package keycloak integrates with Keycloak online endpoints (token
// introspection and UMA 2.0 authorization) via gocloak.
package keycloak

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
	"github.com/Nerzal/gocloak/v14"
)

const (
	requestTimeout       = 5 * time.Second
	maxIntrospectEntries = 10000
)

// ParseIssuer extracts the Keycloak base URL and realm name from a realm issuer URL.
func ParseIssuer(issuer string) (baseURL, realm string, err error) {
	u, err := url.Parse(issuer)
	if err != nil || u == nil || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" {
		return "", "", errors.New("invalid Keycloak issuer URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (!strings.EqualFold(u.Hostname(), "localhost") && (ip == nil || !ip.IsLoopback())) {
			return "", "", errors.New("keycloak issuer must use HTTPS")
		}
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) < 3 || parts[len(parts)-2] != "realms" || parts[len(parts)-1] == "" {
		return "", "", errors.New("keycloak issuer must end in /realms/<realm>")
	}
	realm = parts[len(parts)-1]
	u.Path = strings.Join(parts[:len(parts)-2], "/")
	return strings.TrimRight(u.String(), "/"), realm, nil
}

func newTransport(tlsCfg *tls.Config) *http.Transport {
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsCfg,
	}
}

func newClient(baseURL string, transport *http.Transport) *gocloak.GoCloak {
	client := gocloak.NewClient(baseURL)
	client.RestyClient().SetTransport(transport)
	client.RestyClient().GetClient().CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not allowed")
	}
	return client
}

type cacheEntry struct {
	active  bool
	expires time.Time
}

// Introspector checks token active status against Keycloak's introspection
// endpoint with a bounded, SHA-256-keyed short-lived cache.
type Introspector struct {
	baseURL      string
	realm        string
	clientID     string
	clientSecret string
	cacheTTL     time.Duration
	transport    *http.Transport
	onResult     func(result string)

	mu      sync.RWMutex
	entries map[[32]byte]cacheEntry
}

// NewIntrospector constructs an online token introspector.
func NewIntrospector(issuer, clientID, clientSecret string, cacheTTL time.Duration, tlsCfg *tls.Config, onResult func(string)) (*Introspector, error) {
	baseURL, realm, err := ParseIssuer(issuer)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		return nil, errors.New("CLIENT_ID and CLIENT_SECRET are required for token introspection")
	}
	if cacheTTL < 0 || cacheTTL > 5*time.Minute {
		return nil, errors.New("introspection cache TTL must be between 0 and 5m")
	}
	return &Introspector{
		baseURL:      baseURL,
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		cacheTTL:     cacheTTL,
		transport:    newTransport(tlsCfg),
		onResult:     onResult,
		entries:      make(map[[32]byte]cacheEntry),
	}, nil
}

// Active reports whether rawToken is currently active in Keycloak.
// Any network or protocol error fails closed (returns false, error).
func (i *Introspector) Active(ctx context.Context, rawToken string) (bool, error) {
	key := sha256.Sum256([]byte(rawToken))
	if i.cacheTTL > 0 {
		i.mu.RLock()
		entry, ok := i.entries[key]
		i.mu.RUnlock()
		if ok && time.Now().Before(entry.expires) {
			i.record("cache_hit")
			return entry.active, nil
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	client := newClient(i.baseURL, i.transport)
	res, err := client.RetrospectToken(reqCtx, rawToken, i.clientID, i.clientSecret, i.realm)
	if err != nil || res == nil || res.Active == nil {
		i.record("error")
		return false, errors.New("token introspection failed")
	}
	active := *res.Active
	if active {
		i.record("active")
	} else {
		i.record("inactive")
	}
	if i.cacheTTL > 0 {
		i.store(key, active)
	}
	return active, nil
}

func (i *Introspector) store(key [32]byte, active bool) {
	now := time.Now()
	i.mu.Lock()
	defer i.mu.Unlock()
	if len(i.entries) >= maxIntrospectEntries {
		for k, e := range i.entries {
			if !now.Before(e.expires) {
				delete(i.entries, k)
			}
		}
		if len(i.entries) >= maxIntrospectEntries {
			// Drop map to bound memory under high-cardinality token floods.
			i.entries = make(map[[32]byte]cacheEntry)
		}
	}
	i.entries[key] = cacheEntry{active: active, expires: now.Add(i.cacheTTL)}
}

func (i *Introspector) record(result string) {
	if i.onResult != nil {
		i.onResult(result)
	}
}

// UMAAuthorizer enforces Keycloak Authorization Services (UMA 2.0) policies
// per request URI and optional HTTP method scope.
type UMAAuthorizer struct {
	baseURL     string
	realm       string
	audience    string
	methodScope bool
	transport   *http.Transport
	onResult    func(result string)
}

// NewUMAAuthorizer constructs a Keycloak UMA 2.0 authorizer.
func NewUMAAuthorizer(issuer, audience string, methodScope bool, tlsCfg *tls.Config, onResult func(string)) (*UMAAuthorizer, error) {
	baseURL, realm, err := ParseIssuer(issuer)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(audience) == "" {
		return nil, errors.New("UMA audience (CLIENT_ID or AUDIENCE) is required")
	}
	return &UMAAuthorizer{
		baseURL:     baseURL,
		realm:       realm,
		audience:    audience,
		methodScope: methodScope,
		transport:   newTransport(tlsCfg),
		onResult:    onResult,
	}, nil
}

// Authorize evaluates whether rawToken is permitted to access method + path in Keycloak UMA.
func (u *UMAAuthorizer) Authorize(ctx context.Context, rawToken, method, reqPath string) error {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	perm := reqPath
	if u.methodScope {
		perm = reqPath + "#method:" + method
	}
	grantType := "urn:ietf:params:oauth:grant-type:uma-ticket"
	resFormat := "uri"
	matchURI := true
	aud := u.audience
	client := newClient(u.baseURL, u.transport)
	perms, err := client.GetRequestingPartyPermissions(reqCtx, rawToken, u.realm, gocloak.RequestingPartyTokenOptions{
		GrantType:                     &grantType,
		Audience:                      &aud,
		Permissions:                   []string{perm},
		PermissionResourceFormat:      &resFormat,
		PermissionResourceMatchingURI: &matchURI,
	})
	if err != nil {
		var apiErr *gocloak.APIError
		if errors.As(err, &apiErr) && apiErr.Code == http.StatusForbidden {
			u.record("denied")
			return auth.ErrForbidden
		}
		u.record("error")
		return auth.ErrForbidden
	}
	if perms == nil || len(*perms) == 0 {
		u.record("denied")
		return auth.ErrForbidden
	}
	u.record("allowed")
	return nil
}

func (u *UMAAuthorizer) record(result string) {
	if u.onResult != nil {
		u.onResult(result)
	}
}
