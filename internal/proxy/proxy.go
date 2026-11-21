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
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Nerzal/gocloak-auth-proxy/internal/acl"
	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
	"github.com/Nerzal/gocloak-auth-proxy/internal/metrics"
)

const (
	defaultUpstreamHeaderTimeout  = 15 * time.Second
	defaultUpstreamRequestTimeout = 25 * time.Second
)

// Pre-allocated read-only header value slices to eliminate per-request allocations.
var (
	hdrNoStore       = []string{"no-store"}
	hdrVaryAuth      = []string{"Authorization"}
	hdrNoSniff       = []string{"nosniff"}
	hdrDeny          = []string{"DENY"}
	hdrNoRef         = []string{"no-referrer"}
	hdrHSTS          = []string{"max-age=31536000; includeSubDomains"}
	hdrWWWAuthBearer = []string{"Bearer"}
)

// Verifier authenticates the incoming Authorization header.
type Verifier interface {
	Verify(context.Context, string) (auth.Identity, error)
}

// Authorizer enforces external per-request authorization (e.g. Keycloak UMA 2.0).
type Authorizer interface {
	Authorize(ctx context.Context, rawToken, method, reqPath string) error
}

// SessionResolver resolves browser OIDC sessions from encrypted cookies.
type SessionResolver interface {
	ResolveBearer(w http.ResponseWriter, r *http.Request) (string, bool)
	ShouldRedirect(r *http.Request) bool
	RedirectToLogin(w http.ResponseWriter, r *http.Request)
	StripCookies(headers http.Header)
}

// HeaderNames controls where verified identity attributes are written.
// Empty names use the corresponding X-Auth-Request-* default.
type HeaderNames struct {
	User, Email, Groups, Roles string
}

// Options configures optional proxy capabilities across Milestones 1-3.
type Options struct {
	Headers                HeaderNames
	ExtraHeaders           []string
	PassAccessToken        bool
	ACL                    *acl.Policy
	UMA                    Authorizer
	Session                SessionResolver
	TLSConfig              *tls.Config
	UpstreamHeaderTimeout  time.Duration
	UpstreamRequestTimeout time.Duration // 0 disables per-request timeout (for SSE/WebSockets)
	DisableRequestTimeout  bool
	Logger                 *slog.Logger
	Metrics                *metrics.Registry
	TrustedProxies         []string
	AccessLog              bool
}

type extraHeaderPair struct {
	orig  string
	canon string
}

func (h HeaderNames) normalized(extra []string) (HeaderNames, []extraHeaderPair, []string, error) {
	names := []*string{&h.User, &h.Email, &h.Groups, &h.Roles}
	defaults := []string{"X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Groups", "X-Auth-Request-Roles"}
	seen := make(map[string]bool, len(names)+len(extra))
	var customScrub []string
	for i, name := range names {
		if *name == "" {
			*name = defaults[i]
		}
		norm := normalizeHeaderKey(*name)
		if !validHeaderName(*name) || forbiddenHeader(norm) || seen[norm] {
			return HeaderNames{}, nil, nil, fmt.Errorf("invalid or duplicate identity header %q", *name)
		}
		seen[norm] = true
		*name = textproto.CanonicalMIMEHeaderKey(*name)
		if !strings.HasPrefix(norm, "x-auth-request-") {
			customScrub = append(customScrub, *name)
		}
	}
	cleanExtra := make([]extraHeaderPair, 0, len(extra))
	for _, name := range extra {
		norm := normalizeHeaderKey(name)
		if !validHeaderName(name) || forbiddenHeader(norm) || seen[norm] {
			return HeaderNames{}, nil, nil, fmt.Errorf("invalid or duplicate custom claim header %q", name)
		}
		seen[norm] = true
		canon := textproto.CanonicalMIMEHeaderKey(name)
		cleanExtra = append(cleanExtra, extraHeaderPair{orig: name, canon: canon})
		if !strings.HasPrefix(norm, "x-auth-request-") {
			customScrub = append(customScrub, canon)
		}
	}
	return h, cleanExtra, customScrub, nil
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
	case "authorization", "proxy-authorization", "forwarded", "x-real-ip", "x-auth-request-access-token", "host", "connection", "proxy-connection",
		"keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "content-length",
		"cookie", "set-cookie", "expect", "x-content-type-options", "x-frame-options", "referrer-policy":
		return true
	}
	return false
}

// scrubHeaders removes client-provided identity headers, forwarding metadata,
// and bearer credentials in a single pass, treating hyphens and underscores
// equivalently to prevent WSGI/CGI-style header aliasing.
func scrubHeaders(headers http.Header, customScrub []string) {
	for key := range headers {
		if headerHasPrefixFold(key, "x-auth-request-") ||
			headerHasPrefixFold(key, "x-forwarded-") ||
			headerEqualFold(key, "forwarded") ||
			headerEqualFold(key, "x-real-ip") ||
			headerEqualFold(key, "authorization") {
			delete(headers, key)
			continue
		}
		for _, custom := range customScrub {
			if headerEqualFold(key, custom) {
				delete(headers, key)
				break
			}
		}
	}
}

func validValue(value string) bool {
	if len(value) == 0 {
		return true
	}
	if value[0] <= ' ' || value[len(value)-1] <= ' ' {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b < 0x20 || b == 0x7f {
			return false
		}
		if b >= 0x80 {
			if strings.TrimSpace(value) != value {
				return false
			}
			for _, r := range value[i:] {
				if unicode.IsControl(r) {
					return false
				}
			}
			return true
		}
	}
	return true
}

func joinComma(list []string) string {
	switch len(list) {
	case 0:
		return ""
	case 1:
		return list[0]
	default:
		return strings.Join(list, ",")
	}
}

type verifiedPayload struct {
	values    [4]string
	extra     map[string]string
	rawToken  string
	cleanPath string
	anon      bool
}

func identityValues(identity auth.Identity, extraNames []extraHeaderPair) (verifiedPayload, bool) {
	if identity.User == "" || !validValue(identity.User) || !validValue(identity.Email) {
		return verifiedPayload{}, false
	}
	// Commas are the list separator and must not be interpreted as extra claims.
	for _, list := range [2][]string{identity.Groups, identity.Roles} {
		for _, value := range list {
			if value == "" || !validValue(value) || strings.IndexByte(value, ',') >= 0 {
				return verifiedPayload{}, false
			}
		}
	}
	var extra map[string]string
	if len(extraNames) > 0 && len(identity.Extra) > 0 {
		extra = make(map[string]string, len(identity.Extra))
		for _, pair := range extraNames {
			if val, ok := identity.Extra[pair.orig]; ok {
				if !validValue(val) {
					return verifiedPayload{}, false
				}
				extra[pair.canon] = val
			}
		}
	}
	return verifiedPayload{
		values: [4]string{
			identity.User,
			identity.Email,
			joinComma(identity.Groups),
			joinComma(identity.Roles),
		},
		extra:    extra,
		rawToken: identity.RawToken,
	}, true
}

func inject(headers http.Header, names HeaderNames, payload verifiedPayload, passToken bool, forwardAuth bool) {
	if payload.anon {
		return
	}
	// Single 4-element backing array avoids 4 separate []string slice allocations.
	vals := payload.values
	headers[names.User] = vals[0:1:1]
	headers[names.Email] = vals[1:2:2]
	headers[names.Groups] = vals[2:3:3]
	headers[names.Roles] = vals[3:4:4]
	for k, v := range payload.extra {
		headers[k] = []string{v}
	}
	if passToken && payload.rawToken != "" {
		if forwardAuth {
			headers["X-Auth-Request-Access-Token"] = []string{payload.rawToken}
		} else {
			headers["Authorization"] = []string{"Bearer " + payload.rawToken}
		}
	}
}

func securityHeaders(headers http.Header, isTLS bool) {
	headers["X-Content-Type-Options"] = hdrNoSniff
	headers["X-Frame-Options"] = hdrDeny
	headers["Referrer-Policy"] = hdrNoRef
	if isTLS {
		headers["Strict-Transport-Security"] = hdrHSTS
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header()["Www-Authenticate"] = hdrWWWAuthBearer
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func authenticate(w http.ResponseWriter, r *http.Request, verifier Verifier, extra []extraHeaderPair, customScrub []string, opts Options, mode string) (verifiedPayload, bool) {
	securityHeaders(w.Header(), r.TLS != nil)
	var cleanPath string
	if opts.ACL != nil || opts.UMA != nil {
		var pathOK bool
		cleanPath, pathOK = acl.NormalizeRequestPath(r)
		if !pathOK {
			scrubHeaders(r.Header, customScrub)
			opts.Metrics.RecordRequest(mode, "forbidden")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return verifiedPayload{}, false
		}
	}
	authMode := opts.ACL.AuthModeForPath(r, cleanPath)
	if authMode == acl.ModePublic {
		scrubHeaders(r.Header, customScrub)
		opts.Metrics.RecordRequest(mode, "public")
		return verifiedPayload{anon: true, cleanPath: cleanPath}, true
	}

	authHeaders := r.Header["Authorization"]
	scrubHeaders(r.Header, customScrub)

	var bearer string
	switch len(authHeaders) {
	case 0:
		if opts.Session != nil {
			if resolved, ok := opts.Session.ResolveBearer(w, r); ok {
				bearer = resolved
			}
		}
		if bearer == "" {
			if authMode == acl.ModeOptional {
				opts.Metrics.RecordRequest(mode, "public")
				return verifiedPayload{anon: true, cleanPath: cleanPath}, true
			}
			opts.Metrics.RecordRequest(mode, "unauthorized")
			if opts.Session != nil && opts.Session.ShouldRedirect(r) {
				opts.Session.RedirectToLogin(w, r)
				return verifiedPayload{}, false
			}
			writeUnauthorized(w)
			return verifiedPayload{}, false
		}
	case 1:
		bearer = authHeaders[0]
	default:
		opts.Metrics.RecordRequest(mode, "unauthorized")
		writeUnauthorized(w)
		return verifiedPayload{}, false
	}

	identity, err := verifier.Verify(r.Context(), bearer)
	if err != nil {
		if opts.Logger != nil && opts.Logger.Enabled(r.Context(), slog.LevelDebug) {
			opts.Logger.Debug("authentication rejected",
				"mode", mode,
				"reason", auth.Reason(err),
				"trace_id", ExtractTraceID(r),
			)
		}
		if errors.Is(err, auth.ErrForbidden) {
			opts.Metrics.RecordRequest(mode, "forbidden")
			http.Error(w, "Forbidden", http.StatusForbidden)
		} else {
			opts.Metrics.RecordRequest(mode, "unauthorized")
			if len(authHeaders) == 0 && opts.Session != nil && opts.Session.ShouldRedirect(r) {
				opts.Session.RedirectToLogin(w, r)
				return verifiedPayload{}, false
			}
			writeUnauthorized(w)
		}
		return verifiedPayload{}, false
	}

	if err := opts.ACL.AuthorizePath(r.Method, cleanPath, identity); err != nil {
		opts.Metrics.RecordRequest(mode, "forbidden")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return verifiedPayload{}, false
	}

	if opts.UMA != nil {
		if err := opts.UMA.Authorize(r.Context(), identity.RawToken, r.Method, cleanPath); err != nil {
			opts.Metrics.RecordRequest(mode, "forbidden")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return verifiedPayload{}, false
		}
	}

	payload, ok := identityValues(identity, extra)
	if !ok {
		opts.Metrics.RecordRequest(mode, "unauthorized")
		writeUnauthorized(w)
		return verifiedPayload{}, false
	}
	payload.cleanPath = cleanPath
	opts.Metrics.RecordRequest(mode, "allowed")
	return payload, true
}

// NewForwardAuth returns a handler which exposes verified identity in response headers.
func NewForwardAuth(verifier Verifier, headers HeaderNames) (http.Handler, error) {
	return NewForwardAuthWithOptions(verifier, Options{Headers: headers})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.wroteHeader && (code < 100 || code >= 200 || code == http.StatusSwitchingProtocols) {
		sr.status = code
		sr.wroteHeader = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Unwrap() http.ResponseWriter {
	return sr.ResponseWriter
}

func logAccess(logger *slog.Logger, mode string, r *http.Request, status int, d time.Duration) {
	if logger == nil {
		return
	}
	logger.Info("http request",
		"mode", mode,
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"duration_ms", float64(d.Microseconds())/1000.0,
		"trace_id", ExtractTraceID(r),
	)
}

// NewForwardAuthWithOptions returns a forward-auth handler with extended policy options.
func NewForwardAuthWithOptions(verifier Verifier, opts Options) (http.Handler, error) {
	if verifier == nil {
		return nil, errors.New("verifier is required")
	}
	names, extra, customScrub, err := opts.Headers.normalized(opts.ExtraHeaders)
	if err != nil {
		return nil, err
	}
	if _, err := parseTrustedProxies(opts.TrustedProxies); err != nil {
		return nil, err
	}
	trackTime := opts.Metrics != nil || opts.AccessLog
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var start time.Time
		if trackTime {
			start = time.Now()
		}
		rw := w
		var sr *statusRecorder
		if opts.AccessLog {
			sr = &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			rw = sr
		}
		h := rw.Header()
		h["Cache-Control"] = hdrNoStore
		if len(h["Vary"]) == 0 {
			h["Vary"] = hdrVaryAuth
		} else {
			h.Add("Vary", "Authorization")
		}
		payload, ok := authenticate(rw, r, verifier, extra, customScrub, opts, "forward_auth")
		if ok {
			inject(h, names, payload, opts.PassAccessToken, true)
			rw.WriteHeader(http.StatusOK)
		}
		if trackTime {
			d := time.Since(start)
			opts.Metrics.RecordDuration("forward_auth", d)
			if opts.AccessLog {
				logAccess(opts.Logger, "forward_auth", r, sr.status, d)
			}
		}
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
	return NewReverseProxyWithOptions(verifier, upstream, Options{Headers: headers, Logger: logger})
}

// NewReverseProxyWithOptions forwards authenticated requests with full policy,
// TLS, streaming timeout, UMA, OIDC session, and metrics support.
func NewReverseProxyWithOptions(verifier Verifier, upstream string, opts Options) (http.Handler, error) {
	if verifier == nil {
		return nil, errors.New("verifier is required")
	}
	names, extra, customScrub, err := opts.Headers.normalized(opts.ExtraHeaders)
	if err != nil {
		return nil, err
	}
	trustedProxies, err := parseTrustedProxies(opts.TrustedProxies)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(upstream)
	if err != nil || target == nil || (target.Scheme != "http" && target.Scheme != "https") ||
		target.Host == "" || target.Hostname() == "" || target.User != nil || strings.Contains(upstream, "#") || target.Opaque != "" {
		return nil, errors.New("upstream must be an absolute HTTP(S) URL without userinfo or fragment")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
	}
	headerTimeout := opts.UpstreamHeaderTimeout
	if headerTimeout <= 0 {
		headerTimeout = defaultUpstreamHeaderTimeout
	}
	reqTimeout := opts.UpstreamRequestTimeout
	if !opts.DisableRequestTimeout && reqTimeout <= 0 {
		reqTimeout = defaultUpstreamRequestTimeout
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   512,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: headerTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsCfg,
	}
	type identityKey struct{}
	type reverseState struct {
		payload   verifiedPayload
		forwarded forwardedMeta
		hasFwd    bool
	}
	reverse := &httputil.ReverseProxy{
		Transport:  transport,
		BufferPool: &bufferPool{},
		ErrorLog:   log.New(io.Discard, "", 0),
		Rewrite: func(req *httputil.ProxyRequest) {
			st := req.In.Context().Value(identityKey{}).(reverseState)
			if st.payload.cleanPath != "" {
				req.Out.URL.Path = st.payload.cleanPath
				req.Out.URL.RawPath = ""
			}
			req.SetURL(target)
			scrubHeaders(req.Out.Header, customScrub)
			if st.hasFwd {
				req.Out.Header["X-Forwarded-For"] = []string{st.forwarded.xff}
				req.Out.Header["X-Forwarded-Proto"] = []string{st.forwarded.proto}
				if st.forwarded.host != "" {
					req.Out.Header["X-Forwarded-Host"] = []string{st.forwarded.host}
				}
			}
			if opts.Session != nil {
				opts.Session.StripCookies(req.Out.Header)
			}
			inject(req.Out.Header, names, st.payload, opts.PassAccessToken, false)
		},
		ModifyResponse: func(response *http.Response) error {
			// The handler has already set these headers on the client response.
			delete(response.Header, "X-Content-Type-Options")
			delete(response.Header, "X-Frame-Options")
			delete(response.Header, "Referrer-Policy")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			opts.Metrics.RecordRequest("reverse_proxy", "bad_gateway")
			if traceID := ExtractTraceID(r); traceID != "" {
				logger.Warn("upstream request failed", "category", classifyProxyError(err), "trace_id", traceID)
			} else {
				logger.Warn("upstream request failed", "category", classifyProxyError(err))
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	trackTime := opts.Metrics != nil || opts.AccessLog
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var start time.Time
		if trackTime {
			start = time.Now()
		}
		rw := w
		var sr *statusRecorder
		if opts.AccessLog {
			sr = &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			rw = sr
		}
		fwd, hasFwd := extractTrustedForwarded(r, trustedProxies)
		payload, ok := authenticate(rw, r, verifier, extra, customScrub, opts, "reverse_proxy")
		if ok {
			ctx := r.Context()
			var cancel context.CancelFunc
			if !opts.DisableRequestTimeout && reqTimeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, reqTimeout)
				defer cancel()
			}
			reverse.ServeHTTP(rw, r.WithContext(context.WithValue(ctx, identityKey{}, reverseState{
				payload:   payload,
				forwarded: fwd,
				hasFwd:    hasFwd,
			})))
		}
		if trackTime {
			d := time.Since(start)
			opts.Metrics.RecordDuration("reverse_proxy", d)
			if opts.AccessLog {
				logAccess(logger, "reverse_proxy", r, sr.status, d)
			}
		}
	}), nil
}

// ExtractTraceID parses a W3C Trace Context traceparent header
// (version-traceid-parentid-flags, e.g. 00-<32-hex>-<16-hex>-<2-hex>) and
// returns the 32-char lowercase hex trace ID, or "" if absent/invalid.
func ExtractTraceID(r *http.Request) string {
	if r == nil {
		return ""
	}
	tp := strings.TrimSpace(r.Header.Get("Traceparent"))
	if len(tp) != 55 || tp[2] != '-' || tp[35] != '-' || tp[52] != '-' {
		return ""
	}
	if !isLowerHex(tp[0:2]) || tp[0:2] == "ff" {
		return ""
	}
	traceID := tp[3:35]
	parentID := tp[36:52]
	flags := tp[53:55]
	if !isLowerHex(traceID) || !isLowerHex(parentID) || !isLowerHex(flags) {
		return ""
	}
	if allZeros(traceID) || allZeros(parentID) {
		return ""
	}
	return traceID
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func allZeros(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}
