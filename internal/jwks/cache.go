// Package jwks maintains a snapshot of a Keycloak realm's signing keys.
package jwks

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nerzal/gocloak/v15"
)

const (
	fetchTimeout       = 5 * time.Second
	maxResponseBytes   = 1 << 20
	unknownKidCooldown = 30 * time.Second
	maxSnapshotAge     = 24 * time.Hour
	minSnapshotAge     = time.Minute
	initialRetryDelay  = time.Second
	maxRetryDelay      = 30 * time.Second
	failureLogCooldown = 30 * time.Second
)

type signingKey struct {
	alg string
	key any
}

type snapshot struct {
	keys    map[string]signingKey
	expires time.Time
}

type flight struct {
	done chan struct{}
	err  error
}

// Options configures optional JWKS cache dependencies.
type Options struct {
	Logger    *slog.Logger
	TLSConfig *tls.Config
	OnRefresh func(ok bool)
}

// Cache holds an immutable, atomically replaced set of public signing keys.
type Cache struct {
	baseURL         string
	realm           string
	interval        time.Duration
	maxAge          time.Duration
	transport       *boundedTransport
	logger          *slog.Logger
	onRefresh       func(ok bool)
	current         atomic.Pointer[snapshot]
	mu              sync.Mutex
	inflight        *flight
	lastOnDemand    time.Time
	lastOnDemandErr error
}

// New validates a Keycloak realm issuer with default TLS settings.
func New(issuer string, refreshInterval time.Duration, logger *slog.Logger) (*Cache, error) {
	return NewWithOptions(issuer, refreshInterval, Options{Logger: logger})
}

// NewWithOptions validates a Keycloak realm issuer and configures custom TLS
// and refresh callbacks. Plain HTTP is permitted only for localhost and
// loopback IPs, for local development.
func NewWithOptions(issuer string, refreshInterval time.Duration, opts Options) (*Cache, error) {
	if refreshInterval <= 0 || refreshInterval > maxSnapshotAge/2 {
		return nil, errors.New("JWKS refresh interval must be between zero and 12 hours")
	}
	u, err := url.Parse(issuer)
	if err != nil || u == nil || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" ||
		u.Opaque != "" || u.RawPath != "" || strings.Contains(u.EscapedPath(), "%") {
		return nil, errors.New("invalid Keycloak issuer URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (!strings.EqualFold(u.Hostname(), "localhost") && (ip == nil || !ip.IsLoopback())) {
			return nil, errors.New("keycloak issuer must use HTTPS")
		}
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) < 3 || parts[len(parts)-2] != "realms" || parts[len(parts)-1] == "" {
		return nil, errors.New("keycloak issuer must end in /realms/<realm>")
	}
	for _, part := range parts[1:] {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("invalid Keycloak issuer path")
		}
	}
	realm := parts[len(parts)-1]
	u.Path = strings.Join(parts[:len(parts)-2], "/")
	base := strings.TrimRight(u.String(), "/")
	certURL := issuer + "/protocol/openid-connect/certs"
	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: fetchTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsCfg,
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	maxAge := maxSnapshotAge
	if refreshInterval < maxSnapshotAge/2 {
		maxAge = max(refreshInterval*2, minSnapshotAge)
	}
	return &Cache{
		baseURL:   base,
		realm:     realm,
		interval:  refreshInterval,
		maxAge:    maxAge,
		transport: &boundedTransport{base: transport, target: certURL},
		logger:    logger,
		onRefresh: opts.OnRefresh,
	}, nil
}

// Ready reports whether a nonexpired usable signing-key snapshot was loaded.
// Snapshots expire after twice the refresh interval, bounded to one minute
// through 24 hours, even if refreshes continue to fail.
func (c *Cache) Ready() bool { return c.usable() != nil }

func (c *Cache) usable() *snapshot {
	s := c.current.Load()
	if s == nil || !time.Now().Before(s.expires) {
		return nil
	}
	return s
}

func supportedAlgorithm(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
		return true
	}
	return false
}

// Key returns an immutable public verification key when both kid and algorithm
// match. Callers must treat the returned key as read-only. Unknown kids trigger
// a coalesced, rate-limited refresh, including on the initial lookup.
func (c *Cache) Key(ctx context.Context, kid, alg string) (any, error) {
	if kid == "" || len(kid) > 256 || !supportedAlgorithm(alg) {
		return nil, errors.New("invalid key ID or unsupported signing algorithm")
	}
	if s := c.usable(); s != nil {
		if k, ok := s.keys[kid]; ok {
			if k.alg != alg {
				return nil, errors.New("signing algorithm does not match key")
			}
			return k.key, nil
		}
	}
	if err := c.refresh(ctx, true); err != nil {
		return nil, err
	}
	if s := c.usable(); s != nil {
		if k, ok := s.keys[kid]; ok && k.alg == alg {
			return k.key, nil
		}
	}
	return nil, errors.New("unknown signing key or algorithm mismatch")
}

// Refresh fetches immediately, coalescing concurrent fetches. It is suitable
// for startup readiness checks and does not apply the unknown-kid cooldown.
func (c *Cache) Refresh(ctx context.Context) error { return c.refresh(ctx, false) }

func (c *Cache) refresh(ctx context.Context, onDemand bool) error {
	c.mu.Lock()
	if pending := c.inflight; pending != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return errors.New("JWKS refresh canceled")
		case <-pending.done:
			return pending.err
		}
	}
	if onDemand && !c.lastOnDemand.IsZero() && time.Since(c.lastOnDemand) < unknownKidCooldown {
		err := c.lastOnDemandErr
		c.mu.Unlock()
		return err
	}
	pending := &flight{done: make(chan struct{})}
	c.inflight = pending
	if onDemand {
		c.lastOnDemand = time.Now()
	}
	c.mu.Unlock()

	if onDemand {
		// Detach the shared on-demand fetch from the first caller's cancellation
		// so a client disconnect cannot abort refreshes for other waiters or
		// poison the unknown-kid cooldown.
		fetchCtx := context.WithoutCancel(ctx)
		go func() {
			err := c.fetch(fetchCtx)
			c.mu.Lock()
			c.lastOnDemandErr = err
			pending.err = err
			c.inflight = nil
			close(pending.done)
			c.mu.Unlock()
		}()
		select {
		case <-ctx.Done():
			return errors.New("JWKS refresh canceled")
		case <-pending.done:
			return pending.err
		}
	}

	err := c.fetch(ctx)
	c.mu.Lock()
	pending.err = err
	c.inflight = nil
	close(pending.done)
	c.mu.Unlock()
	return err
}

func (c *Cache) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	client := gocloak.NewClient(c.baseURL, gocloak.SetDirectBodyRead())
	// GetCerts otherwise retains a per-client cache and timer for ten minutes.
	client.Config.CertsInvalidateTime = 0
	client.RestyClient().SetTransport(c.transport)
	client.RestyClient().GetClient().CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("JWKS redirects are not allowed")
	}
	certs, err := client.GetCerts(ctx, c.realm)
	if err != nil {
		if c.onRefresh != nil {
			c.onRefresh(false)
		}
		return errors.New("JWKS refresh failed")
	}
	keys, err := parseKeys(certs.Keys)
	if err != nil {
		if c.onRefresh != nil {
			c.onRefresh(false)
		}
		return err
	}
	c.current.Store(&snapshot{keys: keys, expires: time.Now().Add(c.maxAge)})
	if c.onRefresh != nil {
		c.onRefresh(true)
	}
	return nil
}

func parseKeys(rawKeys []gocloak.CertResponseKey) (map[string]signingKey, error) {
	keys := make(map[string]signingKey)
	seen := make(map[string]struct{})
	for _, raw := range rawKeys {
		if kid := raw.Kid; kid != "" {
			if _, exists := seen[kid]; exists {
				return nil, errors.New("duplicate JWKS key ID")
			}
			seen[kid] = struct{}{}
		}
		kid, k, ok := parseKey(raw)
		if !ok {
			continue
		}
		keys[kid] = k
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable signing keys")
	}
	return keys, nil
}

// Run refreshes periodically until ctx is cancelled. While no usable snapshot
// is available or after a refresh failure, it retries with bounded exponential
// backoff before resuming the configured refresh interval.
func (c *Cache) Run(ctx context.Context) {
	baseRetry := min(initialRetryDelay, c.interval)
	maxRetry := min(maxRetryDelay, c.interval)
	delay := c.interval
	retryDelay := baseRetry
	if !c.Ready() {
		delay = baseRetry
	}
	var lastFailureLog time.Time

	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := c.Refresh(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				if lastFailureLog.IsZero() || time.Since(lastFailureLog) >= failureLogCooldown {
					c.logger.Warn("periodic JWKS refresh failed", "ready", c.Ready())
					lastFailureLog = time.Now()
				}
				delay = retryDelay
				retryDelay = min(retryDelay*2, maxRetry)
			} else {
				delay = c.interval
				retryDelay = baseRetry
			}
			timer.Reset(delay)
		}
	}
}

// boundedTransport permits only the configured endpoint and limits decoded
// response bytes before the SDK buffers or unmarshals them.
type boundedTransport struct {
	base   *http.Transport
	target string
}

func (t *boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || req.URL.String() != t.target {
		return nil, errors.New("disallowed JWKS request")
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	originalBody := resp.Body
	defer func() { _ = originalBody.Close() }()
	if resp.ContentLength > maxResponseBytes {
		return nil, errors.New("JWKS response too large")
	}
	body, err := io.ReadAll(io.LimitReader(originalBody, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JWKS response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("JWKS response too large")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

func decode(s string, max int) ([]byte, bool) {
	if len(s) == 0 || len(s) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil && len(b) > 0 && len(b) <= max
}

func parseKey(raw gocloak.CertResponseKey) (string, signingKey, bool) {
	kid, alg, use := raw.Kid, raw.Alg, raw.Use
	if kid == "" || len(kid) > 256 || (use != "" && use != "sig") {
		return "", signingKey{}, false
	}
	if len(raw.KeyOps) > 0 && (len(raw.KeyOps) != 1 || raw.KeyOps[0] != "verify") {
		return "", signingKey{}, false
	}
	switch raw.Kty {
	case "RSA":
		if alg == "" {
			alg = "RS256"
		}
		switch alg {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		default:
			return "", signingKey{}, false
		}
		n, ok := decode(raw.N, 1024)
		if !ok || n[0] == 0 {
			break
		}
		e, ok := decode(raw.E, 4)
		if !ok || e[0] == 0 {
			break
		}
		modulus, exponent := new(big.Int).SetBytes(n), new(big.Int).SetBytes(e)
		if modulus.BitLen() < 2048 || modulus.BitLen() > 8192 || modulus.Bit(0) == 0 ||
			!exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() > 1<<31-1 || exponent.Bit(0) == 0 {
			break
		}
		return kid, signingKey{alg, &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}}, true
	case "EC":
		var curve elliptic.Curve
		var coordSize int
		var expectedAlg string
		switch raw.Crv {
		case "P-256":
			curve, coordSize, expectedAlg = elliptic.P256(), 32, "ES256"
		case "P-384":
			curve, coordSize, expectedAlg = elliptic.P384(), 48, "ES384"
		case "P-521":
			curve, coordSize, expectedAlg = elliptic.P521(), 66, "ES512"
		default:
			return "", signingKey{}, false
		}
		if alg != "" && alg != expectedAlg {
			break
		}
		x, okX := decode(raw.X, coordSize)
		y, okY := decode(raw.Y, coordSize)
		if !okX || !okY || len(x) != coordSize || len(y) != coordSize {
			break
		}
		point := make([]byte, 1+2*coordSize)
		point[0] = 4
		copy(point[1:1+coordSize], x)
		copy(point[1+coordSize:], y)
		key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			break
		}
		return kid, signingKey{expectedAlg, key}, true
	case "OKP":
		if raw.Crv != "Ed25519" || (alg != "" && alg != "EdDSA") {
			break
		}
		x, ok := decode(raw.X, ed25519.PublicKeySize)
		if !ok || len(x) != ed25519.PublicKeySize {
			break
		}
		return kid, signingKey{"EdDSA", ed25519.PublicKey(x)}, true
	}
	return "", signingKey{}, false
}
