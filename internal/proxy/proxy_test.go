package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
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
	req.Header["x-remote-user"] = []string{"attacker"}
	req.Header.Set("X-Forwarded-User", "attacker")
	verifier := verifierFunc(func(_ context.Context, authorization string) (auth.Identity, error) {
		if authorization != "******" {
			t.Errorf("authorization = %q", authorization)
		}
		for key := range req.Header {
			if strings.EqualFold(key, "X-Remote-User") || strings.HasPrefix(strings.ToLower(key), "x-auth-request-") || strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
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
		{"group ambiguity", auth.Identity{Groups: []string{"users,admin"}}, nil, http.StatusUnauthorized},
		{"role control", auth.Identity{Roles: []string{"admin\x00"}}, nil, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := NewForwardAuth(verifierFunc(func(context.Context, string) (auth.Identity, error) {
				return tt.id, tt.err
			}), HeaderNames{})
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest("GET", "http://proxy.test/", nil))
			if rec.Code != tt.status || strings.Contains(rec.Body.String(), "secret") || rec.Header().Get("X-Auth-Request-User") != "" {
				t.Fatalf("unexpected response %d %q %#v", rec.Code, rec.Body.String(), rec.Header())
			}
			checkSecurity(t, rec.Header())
		})
	}
}

func TestHeaderNamesValidation(t *testing.T) {
	for _, name := range []string{"bad header", "x-header\r\n", "Authorization", "X-Forwarded-Host", "Host", "X-Frame-Options"} {
		if _, err := NewForwardAuth(verifierFunc(verified), HeaderNames{User: name}); err == nil {
			t.Errorf("accepted header %q", name)
		}
	}
	if _, err := NewForwardAuth(verifierFunc(verified), HeaderNames{User: "X-Same", Email: "x-same"}); err == nil {
		t.Error("accepted duplicate header names")
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
		for _, name := range []string{"Authorization", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Custom", "X-Auth-Request-Spoof"} {
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
	handler, err := NewReverseProxy(verifierFunc(verified), upstream.URL+"/base?fixed=1", HeaderNames{User: "X-Remote-User"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://evil.test/resource?request=2", nil)
	req.Header.Set("Authorization", "******")
	req.Header.Set("Forwarded", "host=evil.test")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Forwarded-Host", "evil.test")
	req.Header.Set("X-Forwarded-Custom", "spoof")
	req.Header.Set("X-Auth-Request-Spoof", "spoof")
	req.Header.Set("X-Remote-User", "attacker")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "upstream" {
		t.Fatalf("unexpected response: %d %q", rec.Code, rec.Body.String())
	}
	checkSecurity(t, rec.Header())
}

func TestReverseProxyValidationAndErrors(t *testing.T) {
	for _, upstream := range []string{"", "/relative", "//host/path", "ftp://host", "https://user" + "@" + "host/path", "https://host/path#fragment", "https://host/path#", "http:///missing", "http://host:invalid"} {
		if _, err := NewReverseProxy(verifierFunc(verified), upstream, HeaderNames{}); err == nil {
			t.Errorf("accepted upstream %q", upstream)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	handler, err := NewReverseProxy(verifierFunc(verified), server.URL, HeaderNames{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "http://proxy.test/", nil))
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), server.URL) {
		t.Fatalf("unexpected error %d %q", rec.Code, rec.Body.String())
	}
	checkSecurity(t, rec.Header())
}

func BenchmarkForwardAuth(b *testing.B) {
	handler, err := NewForwardAuth(verifierFunc(verified), HeaderNames{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://proxy.test/", nil))
	}
}
