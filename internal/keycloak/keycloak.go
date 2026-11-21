// Package keycloak integrates with Keycloak online endpoints (token
// introspection and UMA 2.0 authorization) via gocloak.
package keycloak

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
	"github.com/Nerzal/gocloak/v15"
)

const (
	requestTimeout       = 5 * time.Second
	maxResponseBytes     = 1 << 20
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

type boundedTransport struct {
	base     *http.Transport
	maxBytes int64
}

func (t *boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	originalBody := resp.Body
	defer func() { _ = originalBody.Close() }()
	if resp.ContentLength > t.maxBytes {
		return nil, errors.New("keycloak response too large")
	}
	body, err := io.ReadAll(io.LimitReader(originalBody, t.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read keycloak response: %w", err)
	}
	if int64(len(body)) > t.maxBytes {
		return nil, errors.New("keycloak response too large")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// NewBoundedTransport returns a TLS 1.2+ HTTP RoundTripper that bounds
// response bodies to maxBytes (defaulting to 1 MiB).
func NewBoundedTransport(tlsCfg *tls.Config, maxBytes int64) http.RoundTripper {
	if maxBytes <= 0 {
		maxBytes = maxResponseBytes
	}
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
	}
	base := &http.Transport{
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
	return &boundedTransport{base: base, maxBytes: maxBytes}
}

func newClient(baseURL string, transport http.RoundTripper) *gocloak.GoCloak {
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

type introspectFlight struct {
	done   chan struct{}
	active bool
	err    error
}

// Introspector checks token active status against Keycloak's introspection
// endpoint with a bounded, SHA-256-keyed short-lived cache and singleflight
// coalescing for concurrent lookups of the same token.
type Introspector struct {
	client       *gocloak.GoCloak
	realm        string
	clientID     string
	clientSecret string
	cacheTTL     time.Duration
	onResult     func(result string)

	mu       sync.RWMutex
	entries  map[[32]byte]cacheEntry
	inflight map[[32]byte]*introspectFlight
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
		client:       newClient(baseURL, NewBoundedTransport(tlsCfg, maxResponseBytes)),
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		cacheTTL:     cacheTTL,
		onResult:     onResult,
		entries:      make(map[[32]byte]cacheEntry),
		inflight:     make(map[[32]byte]*introspectFlight),
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

	i.mu.Lock()
	if i.cacheTTL > 0 {
		if entry, ok := i.entries[key]; ok && time.Now().Before(entry.expires) {
			i.mu.Unlock()
			i.record("cache_hit")
			return entry.active, nil
		}
	}
	if fl, ok := i.inflight[key]; ok {
		i.mu.Unlock()
		select {
		case <-ctx.Done():
			return false, errors.New("token introspection canceled")
		case <-fl.done:
			return fl.active, fl.err
		}
	}
	fl := &introspectFlight{done: make(chan struct{})}
	i.inflight[key] = fl
	i.mu.Unlock()

	fetchCtx := context.WithoutCancel(ctx)
	go func() {
		reqCtx, cancel := context.WithTimeout(fetchCtx, requestTimeout)
		defer cancel()
		res, err := i.client.RetrospectToken(reqCtx, rawToken, i.clientID, i.clientSecret, i.realm)
		var active bool
		var retErr error
		if err != nil || res == nil {
			i.record("error")
			retErr = errors.New("token introspection failed")
		} else {
			active = res.Active
			if active {
				i.record("active")
			} else {
				i.record("inactive")
			}
		}

		i.mu.Lock()
		fl.active = active
		fl.err = retErr
		delete(i.inflight, key)
		if retErr == nil && i.cacheTTL > 0 {
			i.storeLocked(key, active)
		}
		close(fl.done)
		i.mu.Unlock()
	}()

	select {
	case <-ctx.Done():
		return false, errors.New("token introspection canceled")
	case <-fl.done:
		return fl.active, fl.err
	}
}

func (i *Introspector) storeLocked(key [32]byte, active bool) {
	now := time.Now()
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
	client      *gocloak.GoCloak
	realm       string
	audience    string
	methodScope bool
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
		client:      newClient(baseURL, NewBoundedTransport(tlsCfg, maxResponseBytes)),
		realm:       realm,
		audience:    audience,
		methodScope: methodScope,
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
	perms, err := u.client.GetRequestingPartyPermissions(reqCtx, rawToken, u.realm, gocloak.RequestingPartyTokenOptions{
		GrantType:                     "urn:ietf:params:oauth:grant-type:uma-ticket",
		Audience:                      u.audience,
		Permissions:                   []string{perm},
		PermissionResourceFormat:      "uri",
		PermissionResourceMatchingURI: true,
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
	if len(perms) == 0 {
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
