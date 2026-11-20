// Package proxy provides authenticated forward-auth and reverse-proxy handlers.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
)

const (
	upstreamHeaderTimeout  = 15 * time.Second
	upstreamRequestTimeout = 25 * time.Second
)

// Verifier authenticates the incoming Authorization header.
type Verifier interface {
	Verify(context.Context, string) (auth.Identity, error)
}

// HeaderNames controls where verified identity attributes are written.
// Empty names use the corresponding X-Auth-Request-* default.
type HeaderNames struct {
	User, Email, Groups, Roles string
}

func (h HeaderNames) normalized() (HeaderNames, error) {
	names := []*string{&h.User, &h.Email, &h.Groups, &h.Roles}
	defaults := []string{"X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Groups", "X-Auth-Request-Roles"}
	seen := make(map[string]bool, len(names))
	for i, name := range names {
		if *name == "" {
			*name = defaults[i]
		}
		norm := normalizeHeaderKey(*name)
		if !validHeaderName(*name) || forbiddenHeader(norm) || seen[norm] {
			return HeaderNames{}, fmt.Errorf("invalid or duplicate identity header %q", *name)
		}
		seen[norm] = true
	}
	return h, nil
}

func normByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	if b == '_' {
		return '-'
	}
	return b
}

func normalizeHeaderKey(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = normByte(s[i])
	}
	return string(b)
}

func headerEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if normByte(a[i]) != normByte(b[i]) {
			return false
		}
	}
	return true
}

func headerHasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if normByte(s[i]) != normByte(prefix[i]) {
			return false
		}
	}
	return true
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

func forbiddenHeader(name string) bool {
	if strings.HasPrefix(name, "x-forwarded-") {
		return true
	}
	switch name {
	case "authorization", "proxy-authorization", "forwarded", "x-real-ip", "host", "connection", "proxy-connection",
		"keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "content-length",
		"cookie", "set-cookie", "expect", "x-content-type-options", "x-frame-options", "referrer-policy":
		return true
	}
	return false
}

// scrubHeaders removes client-provided identity headers, forwarding metadata,
// and bearer credentials in a single pass, treating hyphens and underscores
// equivalently to prevent WSGI/CGI-style header aliasing.
func scrubHeaders(headers http.Header, names HeaderNames) {
	for key := range headers {
		if headerHasPrefixFold(key, "x-auth-request-") ||
			headerHasPrefixFold(key, "x-forwarded-") ||
			headerEqualFold(key, "forwarded") ||
			headerEqualFold(key, "x-real-ip") ||
			headerEqualFold(key, "authorization") ||
			headerEqualFold(key, names.User) ||
			headerEqualFold(key, names.Email) ||
			headerEqualFold(key, names.Groups) ||
			headerEqualFold(key, names.Roles) {
			delete(headers, key)
		}
	}
}

func validValue(value string) bool {
	if strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func identityValues(identity auth.Identity) ([4]string, bool) {
	if identity.User == "" || !validValue(identity.User) || !validValue(identity.Email) {
		return [4]string{}, false
	}
	// Commas are the list separator and must not be interpreted as extra claims.
	for _, list := range [2][]string{identity.Groups, identity.Roles} {
		for _, value := range list {
			if value == "" || !validValue(value) || strings.Contains(value, ",") {
				return [4]string{}, false
			}
		}
	}
	return [4]string{
		identity.User,
		identity.Email,
		strings.Join(identity.Groups, ","),
		strings.Join(identity.Roles, ","),
	}, true
}

func inject(headers http.Header, names HeaderNames, values [4]string) {
	headers.Set(names.User, values[0])
	headers.Set(names.Email, values[1])
	headers.Set(names.Groups, values[2])
	headers.Set(names.Roles, values[3])
}

func securityHeaders(headers http.Header) {
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("Referrer-Policy", "no-referrer")
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func authenticate(w http.ResponseWriter, r *http.Request, verifier Verifier, names HeaderNames) ([4]string, bool) {
	securityHeaders(w.Header())
	authHeaders := r.Header.Values("Authorization")
	scrubHeaders(r.Header, names)
	if len(authHeaders) != 1 {
		writeUnauthorized(w)
		return [4]string{}, false
	}
	identity, err := verifier.Verify(r.Context(), authHeaders[0])
	if err != nil {
		if errors.Is(err, auth.ErrForbidden) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		} else {
			writeUnauthorized(w)
		}
		return [4]string{}, false
	}
	values, ok := identityValues(identity)
	if !ok {
		writeUnauthorized(w)
		return [4]string{}, false
	}
	return values, true
}

// NewForwardAuth returns a handler which exposes verified identity in response headers.
func NewForwardAuth(verifier Verifier, headers HeaderNames) (http.Handler, error) {
	if verifier == nil {
		return nil, errors.New("verifier is required")
	}
	names, err := headers.normalized()
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Vary", "Authorization")
		values, ok := authenticate(w, r, verifier, names)
		if !ok {
			return
		}
		inject(w.Header(), names, values)
		w.WriteHeader(http.StatusOK)
	}), nil
}

type bufferPool struct{ pool sync.Pool }

func (p *bufferPool) Get() []byte {
	if b := p.pool.Get(); b != nil {
		return *b.(*[]byte)
	}
	return make([]byte, 32*1024)
}

func (p *bufferPool) Put(b []byte) {
	if cap(b) == 32*1024 {
		b = b[:cap(b)]
		p.pool.Put(&b)
	}
}

func classifyProxyError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "client_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "upstream_timeout"
	}
	var certErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	var tlsErr *tls.RecordHeaderError
	if errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &certInvalid) || errors.As(err, &tlsErr) {
		return "upstream_tls_error"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "upstream_timeout"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "upstream_dial_error"
	}
	return "upstream_error"
}

// NewReverseProxy forwards authenticated requests only to the configured upstream.
// A nil logger discards upstream diagnostics.
func NewReverseProxy(verifier Verifier, upstream string, headers HeaderNames, logger *slog.Logger) (http.Handler, error) {
	if verifier == nil {
		return nil, errors.New("verifier is required")
	}
	names, err := headers.normalized()
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(upstream)
	if err != nil || target == nil || (target.Scheme != "http" && target.Scheme != "https") ||
		target.Host == "" || target.Hostname() == "" || target.User != nil || strings.Contains(upstream, "#") || target.Opaque != "" {
		return nil, errors.New("upstream must be an absolute HTTP(S) URL without userinfo or fragment")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: upstreamHeaderTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	type identityKey struct{}
	reverse := &httputil.ReverseProxy{
		Transport:  transport,
		BufferPool: &bufferPool{},
		ErrorLog:   log.New(io.Discard, "", 0),
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(target)
			scrubHeaders(req.Out.Header, names)
			inject(req.Out.Header, names, req.In.Context().Value(identityKey{}).([4]string))
		},
		ModifyResponse: func(response *http.Response) error {
			// The handler has already set these headers on the client response.
			response.Header.Del("X-Content-Type-Options")
			response.Header.Del("X-Frame-Options")
			response.Header.Del("Referrer-Policy")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			logger.Warn("upstream request failed", "category", classifyProxyError(err))
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values, ok := authenticate(w, r, verifier, names)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), upstreamRequestTimeout)
		defer cancel()
		reverse.ServeHTTP(w, r.WithContext(context.WithValue(ctx, identityKey{}, values)))
	}), nil
}
