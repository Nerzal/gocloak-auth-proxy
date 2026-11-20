package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nerzal/gocloak-auth-proxy/internal/acl"
	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
	"github.com/Nerzal/gocloak-auth-proxy/internal/metrics"
)

type verifierFunc func(context.Context, string) (auth.Identity, error)

func (v verifierFunc) Verify(ctx context.Context, authorization string) (auth.Identity, error) {
	return v(ctx, authorization)
}

func verified(_ context.Context, _ string) (auth.Identity, error) {
	return auth.Identity{User: "alice", Email: "alice@example.test", Groups: []string{"team", "staff"}, Roles: []string{"admin"}}, nil
}

func TestForwardAuth(t *testing.T) {
	headers := HeaderNames{User: "X-Remote-User", Email: "X-Remote-Email"}
	req := httptest.NewRequest("GET", "http://proxy.test/auth", nil)
	req.Header.Set("Authorization", "******")
	req.Header["x-auth-request-user"] = []string{"attacker"}
	req.Header["X_Auth_Request_Roles"] = []string{"superadmin"}
	req.Header["x-remote-user"] = []string{"attacker"}
	req.Header["X_Remote_User"] = []string{"attacker"}
	req.Header.Set("X-Forwarded-User", "attacker")
	req.Header["X_Forwarded_User"] = []string{"attacker"}
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header["X_Real_IP"] = []string{"1.2.3.4"}
	verifier := verifierFunc(func(_ context.Context, authorization string) (auth.Identity, error) {
		if authorization != "******" {
			t.Errorf("authorization = %q", authorization)
		}
		for key := range req.Header {
			norm := normalizeHeaderKey(key)
			if norm == "x-remote-user" || norm == "x-real-ip" || strings.HasPrefix(norm, "x-auth-request-") || strings.HasPrefix(norm, "x-forwarded-") {
				t.Errorf("spoofed header %q survived before verification", key)
			}
		}
		return verified(context.Background(), "")
	})
	handler, err := NewForwardAuth(verifier, headers)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Remote-User") != "alice" ||
		rec.Header().Get("X-Remote-Email") != "alice@example.test" ||
		rec.Header().Get("X-Auth-Request-Groups") != "team,staff" ||
		rec.Header().Get("X-Auth-Request-Roles") != "admin" {
		t.Fatalf("unexpected response: %d %#v", rec.Code, rec.Header())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Vary") != "Authorization" {
		t.Fatalf("missing cache/vary headers: %#v", rec.Header())
	}
	checkSecurity(t, rec.Header())
}

func checkSecurity(t *testing.T, headers http.Header) {
	t.Helper()
	for name, want := range map[string]string{
		"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
	} {
		if values := headers.Values(name); len(values) != 1 || values[0] != want {
			t.Errorf("%s = %q, want %q", name, values, want)
		}
	}
}

func TestForwardAuthFailures(t *testing.T) {
	tests := []struct {
		name   string
		id     auth.Identity
		err    error
		status int
	}{
		{"unauthorized", auth.Identity{}, errors.New("secret validation details"), http.StatusUnauthorized},
		{"forbidden", auth.Identity{}, fmt.Errorf("secret: %w", auth.ErrForbidden), http.StatusForbidden},
		{"header injection", auth.Identity{User: "alice\r\nX-Admin: true"}, nil, http.StatusUnauthorized},
		{"empty user", auth.Identity{Email: "a@b.test"}, nil, http.StatusUnauthorized},
		{"surrounding whitespace user", auth.Identity{User: " alice "}, nil, http.StatusUnauthorized},
		{"surrounding whitespace role", auth.Identity{User: "alice", Roles: []string{" admin "}}, nil, http.StatusUnauthorized},
		{"empty role element", auth.Identity{User: "alice", Roles: []string{""}}, nil, http.StatusUnauthorized},
		{"group ambiguity", auth.Identity{User: "alice", Groups: []string{"users,admin"}}, nil, http.StatusUnauthorized},
		{"role control", auth.Identity{User: "alice", Roles: []string{"admin\x00"}}, nil, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := NewForwardAuth(verifierFunc(func(context.Context, string) (auth.Identity, error) {
				return tt.id, tt.err
			}), HeaderNames{})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "http://proxy.test/", nil)
			req.Header.Set("Authorization", "Bearer token")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.status || strings.Contains(rec.Body.String(), "secret") || rec.Header().Get("X-Auth-Request-User") != "" {
				t.Fatalf("unexpected response %d %q %#v", rec.Code, rec.Body.String(), rec.Header())
			}
			if tt.status == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("missing WWW-Authenticate: Bearer header on 401")
			}
			checkSecurity(t, rec.Header())
		})
	}

	t.Run("multiple authorization headers", func(t *testing.T) {
		handler, err := NewForwardAuth(verifierFunc(verified), HeaderNames{})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("GET", "http://proxy.test/", nil)
		req.Header.Add("Authorization", "Bearer one")
		req.Header.Add("Authorization", "Bearer two")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("expected 401 with WWW-Authenticate, got %d %#v", rec.Code, rec.Header())
		}
	})

	t.Run("http round-trip rejects surrounding whitespace role", func(t *testing.T) {
		handler, err := NewForwardAuth(verifierFunc(func(context.Context, string) (auth.Identity, error) {
			return auth.Identity{User: "alice", Roles: []string{" admin "}}, nil
		}), HeaderNames{})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(handler)
		defer srv.Close()
		req, err := http.NewRequest("GET", srv.URL+"/auth", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer token")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("expected 401 with WWW-Authenticate, got %d %#v", resp.StatusCode, resp.Header)
		}
		if resp.Header.Get("X-Auth-Request-Roles") != "" {
			t.Fatalf("unexpected roles header: %q", resp.Header.Get("X-Auth-Request-Roles"))
		}
	})
}

func TestHeaderNamesValidation(t *testing.T) {
	for _, name := range []string{"bad header", "x-header\r\n", "Authorization", "X-Forwarded-Host", "X_Forwarded_Host", "X-Real-IP", "X_Real_IP", "Host", "X-Frame-Options"} {
		if _, err := NewForwardAuth(verifierFunc(verified), HeaderNames{User: name}); err == nil {
			t.Errorf("accepted header %q", name)
		}
	}
	if _, err := NewForwardAuth(verifierFunc(verified), HeaderNames{User: "X-Same", Email: "x-same"}); err == nil {
		t.Error("accepted duplicate header names")
	}
	if _, err := NewForwardAuth(verifierFunc(verified), HeaderNames{User: "X-Same", Email: "X_Same"}); err == nil {
		t.Error("accepted underscore-aliased duplicate header names")
	}
	if _, err := NewForwardAuth(nil, HeaderNames{}); err == nil {
		t.Error("accepted nil verifier")
	}
}

func TestReverseProxy(t *testing.T) {
	var expectedHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != expectedHost {
			t.Errorf("upstream host = %q, want %q", r.Host, expectedHost)
		}
		if r.URL.Path != "/base/resource" || r.URL.RawQuery != "fixed=1&request=2" {
			t.Errorf("unexpected URL %s", r.URL.String())
		}
		for _, name := range []string{
			"Authorization", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Custom",
			"X-Auth-Request-Spoof", "X_Auth_Request_Roles", "X_Forwarded_User", "X-Real-IP", "X_Real_IP", "X_Remote_User",
		} {
			if value := r.Header.Get(name); value != "" {
				t.Errorf("upstream received %s: %q", name, value)
			}
		}
		if r.Header.Get("X-Remote-User") != "alice" || r.Header.Get("X-Auth-Request-Groups") != "team,staff" {
			t.Errorf("incorrect identity: %#v", r.Header)
		}
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Content-Type-Options", "bad")
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	expectedHost = strings.TrimPrefix(upstream.URL, "http://")
	handler, err := NewReverseProxy(verifierFunc(verified), upstream.URL+"/base?fixed=1", HeaderNames{User: "X-Remote-User"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://evil.test/resource?request=2", nil)
	req.Header.Set("Authorization", "******")
	req.Header.Set("Forwarded", "host=evil.test")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Forwarded-Host", "evil.test")
	req.Header.Set("X-Forwarded-Custom", "spoof")
	req.Header["X_Forwarded_User"] = []string{"spoof"}
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header["X_Real_IP"] = []string{"1.2.3.4"}
	req.Header.Set("X-Auth-Request-Spoof", "spoof")
	req.Header["X_Auth_Request_Roles"] = []string{"superadmin"}
	req.Header.Set("X-Remote-User", "attacker")
	req.Header["X_Remote_User"] = []string{"attacker"}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "upstream" {
		t.Fatalf("unexpected response: %d %q", rec.Code, rec.Body.String())
	}
	checkSecurity(t, rec.Header())
}

func TestReverseProxyValidationAndErrors(t *testing.T) {
	for _, upstream := range []string{"", "/relative", "//host/path", "ftp://host", "https://user" + "@" + "host/path", "https://host/path#fragment", "https://host/path#", "http:///missing", "http://host:invalid"} {
		if _, err := NewReverseProxy(verifierFunc(verified), upstream, HeaderNames{}, nil); err == nil {
			t.Errorf("accepted upstream %q", upstream)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler, err := NewReverseProxy(verifierFunc(verified), server.URL, HeaderNames{}, logger)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://proxy.test/secret-path", nil)
	req.Header.Set("Authorization", "Bearer top-secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), server.URL) {
		t.Fatalf("unexpected error %d %q", rec.Code, rec.Body.String())
	}
	logged := logs.String()
	if !strings.Contains(logged, `"category":"upstream_dial_error"`) {
		t.Fatalf("expected structured upstream_dial_error log, got: %s", logged)
	}
	if strings.Contains(logged, "top-secret-token") || strings.Contains(logged, "secret-path") || strings.Contains(logged, server.URL) {
		t.Fatalf("leaked sensitive request/upstream details in log: %s", logged)
	}
	checkSecurity(t, rec.Header())
}

func BenchmarkForwardAuth(b *testing.B) {
	handler, err := NewForwardAuth(verifierFunc(verified), HeaderNames{})
	if err != nil {
		b.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://proxy.test/auth", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		req.Header.Set("Authorization", "Bearer benchmark-token")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
}

type umaFunc func(context.Context, string, string, string) error

func (f umaFunc) Authorize(ctx context.Context, rawToken, method, reqPath string) error {
	return f(ctx, rawToken, method, reqPath)
}

type stubSession struct {
	bearer   string
	redirect bool
}

func (s stubSession) ResolveBearer(_ http.ResponseWriter, _ *http.Request) (string, bool) {
	return s.bearer, s.bearer != ""
}
func (s stubSession) ShouldRedirect(_ *http.Request) bool { return s.redirect }
func (s stubSession) RedirectToLogin(w http.ResponseWriter, _ *http.Request) {
	http.Redirect(w, httptest.NewRequest("GET", "/", nil), "/oauth2/start", http.StatusFound)
}
func (s stubSession) StripCookies(headers http.Header) { headers.Del("Cookie") }

func TestProxyExtendedFeatures(t *testing.T) {
	policy, err := acl.New([]string{"/public/*"}, []string{"/optional/*"}, true, []string{"POST:/admin/*=realm:admin"})
	if err != nil {
		t.Fatal(err)
	}
	reg := metrics.New()
	ver := verifierFunc(func(_ context.Context, _ string) (auth.Identity, error) {
		return auth.Identity{
			User:       "alice",
			Email:      "alice@example.test",
			Roles:      []string{"reader"},
			RealmRoles: []string{"reader"},
			Extra:      map[string]string{"X-Tenant-ID": "t-1"},
			RawToken:   "verified-jwt",
		}, nil
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Echo-User", r.Header.Get("X-Auth-Request-User"))
		w.Header().Set("Echo-Tenant", r.Header.Get("X-Tenant-ID"))
		w.Header().Set("Echo-Auth", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h, err := NewReverseProxyWithOptions(ver, upstream.URL, Options{
		ExtraHeaders:    []string{"X-Tenant-ID"},
		PassAccessToken: true,
		ACL:             policy,
		UMA: umaFunc(func(_ context.Context, _, _, p string) error {
			if p == "/uma-denied" {
				return auth.ErrForbidden
			}
			return nil
		}),
		Session: stubSession{redirect: true},
		Metrics: reg,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Public path bypasses auth and scrubs spoofed custom header.
	pubReq := httptest.NewRequest(http.MethodGet, "http://proxy.test/public/doc", nil)
	pubReq.Header.Set("X-Tenant-ID", "spoofed")
	pubRec := httptest.NewRecorder()
	h.ServeHTTP(pubRec, pubReq)
	if pubRec.Code != http.StatusOK || pubRec.Header().Get("Echo-Tenant") != "" || pubRec.Header().Get("Echo-User") != "" {
		t.Fatalf("public path failed: %d %#v", pubRec.Code, pubRec.Header())
	}

	// 2. Optional path without token allows anonymous.
	optRec := httptest.NewRecorder()
	h.ServeHTTP(optRec, httptest.NewRequest(http.MethodGet, "http://proxy.test/optional/feed", nil))
	if optRec.Code != http.StatusOK || optRec.Header().Get("Echo-User") != "" {
		t.Fatalf("optional anonymous failed: %d", optRec.Code)
	}

	// 3. Authenticated request injects custom header and passes access token.
	authReq := httptest.NewRequest(http.MethodGet, "http://proxy.test/private", nil)
	authReq.Header.Set("Authorization", "Bearer verified-jwt")
	authReq.Header["X_Tenant_ID"] = []string{"spoofed"}
	authRec := httptest.NewRecorder()
	h.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusOK || authRec.Header().Get("Echo-Tenant") != "t-1" || authRec.Header().Get("Echo-Auth") != "Bearer verified-jwt" {
		t.Fatalf("authenticated request failed: %d %#v", authRec.Code, authRec.Header())
	}

	// 4. Route ACL denies POST /admin/x for reader.
	aclReq := httptest.NewRequest(http.MethodPost, "http://proxy.test/admin/x", nil)
	aclReq.Header.Set("Authorization", "Bearer verified-jwt")
	aclRec := httptest.NewRecorder()
	h.ServeHTTP(aclRec, aclReq)
	if aclRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from route ACL, got %d", aclRec.Code)
	}

	// 5. UMA denies /uma-denied.
	umaReq := httptest.NewRequest(http.MethodGet, "http://proxy.test/uma-denied", nil)
	umaReq.Header.Set("Authorization", "Bearer verified-jwt")
	umaRec := httptest.NewRecorder()
	h.ServeHTTP(umaRec, umaReq)
	if umaRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from UMA, got %d", umaRec.Code)
	}

	// 6. Unauthenticated browser request redirects to OIDC login.
	redirRec := httptest.NewRecorder()
	h.ServeHTTP(redirRec, httptest.NewRequest(http.MethodGet, "http://proxy.test/dashboard", nil))
	if redirRec.Code != http.StatusFound || redirRec.Header().Get("Location") != "/oauth2/start" {
		t.Fatalf("expected 302 to /oauth2/start, got %d %q", redirRec.Code, redirRec.Header().Get("Location"))
	}
}

func TestExtractTraceID(t *testing.T) {
	valid := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/", nil)
	req.Header.Set("traceparent", valid)
	if got := ExtractTraceID(req); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("ExtractTraceID = %q, want 4bf92f3577b34da6a3ce929d0e0e4736", got)
	}
	for _, bad := range []string{
		"",
		"not-a-traceparent",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
	} {
		r := httptest.NewRequest(http.MethodGet, "http://proxy.test/", nil)
		r.Header.Set("traceparent", bad)
		if got := ExtractTraceID(r); got != "" {
			t.Errorf("ExtractTraceID(%q) = %q, want empty", bad, got)
		}
	}
}
