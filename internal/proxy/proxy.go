// Package proxy provides authenticated forward-auth and reverse-proxy handlers.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
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
		lower := strings.ToLower(*name)
		if !validHeaderName(*name) || forbiddenHeader(lower) || seen[lower] {
			return HeaderNames{}, fmt.Errorf("invalid or duplicate identity header %q", *name)
		}
		seen[lower] = true
	}
	return h, nil
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
	case "authorization", "proxy-authorization", "forwarded", "host", "connection", "proxy-connection",
		"keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "content-length",
		"cookie", "set-cookie", "expect", "x-content-type-options", "x-frame-options", "referrer-policy":
		return true
	}
	return false
}

func scrubIdentity(headers http.Header, names HeaderNames) {
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-auth-request-") ||
			strings.EqualFold(key, names.User) || strings.EqualFold(key, names.Email) ||
			strings.EqualFold(key, names.Groups) || strings.EqualFold(key, names.Roles) {
			delete(headers, key)
		}
	}
}

// scrubUntrusted removes client-provided forwarding metadata and bearer credentials.
func scrubUntrusted(headers http.Header) {
	for key := range headers {
		if strings.EqualFold(key, "Forwarded") || strings.HasPrefix(strings.ToLower(key), "x-forwarded-") ||
			strings.EqualFold(key, "Authorization") {
			delete(headers, key)
		}
	}
}

func validValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 32 || value[i] == 127 {
			return false
		}
	}
	return true
}

func identityValues(identity auth.Identity) ([4]string, bool) {
	values := [4]string{identity.User, identity.Email, strings.Join(identity.Groups, ","), strings.Join(identity.Roles, ",")}
	for _, value := range values {
		if !validValue(value) {
			return values, false
		}
	}
	// Commas are the list separator and must not be interpreted as extra claims.
	for _, list := range [][]string{identity.Groups, identity.Roles} {
		for _, value := range list {
			if strings.Contains(value, ",") {
				return values, false
			}
		}
	}
	return values, true
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

func authenticate(w http.ResponseWriter, r *http.Request, verifier Verifier, names HeaderNames) ([4]string, bool) {
	securityHeaders(w.Header())
	authorization := r.Header.Get("Authorization")
	scrubIdentity(r.Header, names)
	scrubUntrusted(r.Header)
	identity, err := verifier.Verify(r.Context(), authorization)
	if err != nil {
		if errors.Is(err, auth.ErrForbidden) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		return [4]string{}, false
	}
	values, ok := identityValues(identity)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

// NewReverseProxy forwards authenticated requests only to the configured upstream.
func NewReverseProxy(verifier Verifier, upstream string, headers HeaderNames) (http.Handler, error) {
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
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	type identityKey struct{}
	reverse := &httputil.ReverseProxy{
		Transport:  transport,
		BufferPool: &bufferPool{},
		ErrorLog:   log.New(io.Discard, "", 0),
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(target)
			scrubIdentity(req.Out.Header, names)
			scrubUntrusted(req.Out.Header)
			inject(req.Out.Header, names, req.In.Context().Value(identityKey{}).([4]string))
		},
		ModifyResponse: func(response *http.Response) error {
			// The handler has already set these headers on the client response.
			response.Header.Del("X-Content-Type-Options")
			response.Header.Del("X-Frame-Options")
			response.Header.Del("Referrer-Policy")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values, ok := authenticate(w, r, verifier, names)
		if !ok {
			return
		}
		reverse.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, values)))
	}), nil
}
