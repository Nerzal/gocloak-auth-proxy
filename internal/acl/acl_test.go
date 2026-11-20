package acl

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
)

func TestPolicyModesAndTraversal(t *testing.T) {
	p, err := New([]string{"/public/*", "/status"}, []string{"/catalog/*"}, true, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/public/logo.png", nil)
	if mode, ok := p.AuthMode(req); !ok || mode != ModePublic {
		t.Fatalf("got mode=%v ok=%v, want ModePublic", mode, ok)
	}

	req = httptest.NewRequest(http.MethodGet, "/status", nil)
	if mode, ok := p.AuthMode(req); !ok || mode != ModePublic {
		t.Fatalf("got mode=%v ok=%v, want ModePublic", mode, ok)
	}

	req = httptest.NewRequest(http.MethodGet, "/catalog/items", nil)
	if mode, ok := p.AuthMode(req); !ok || mode != ModeOptional {
		t.Fatalf("got mode=%v ok=%v, want ModeOptional", mode, ok)
	}

	// Traversal must be rejected (fail closed).
	req = httptest.NewRequest(http.MethodGet, "/public/../admin", nil)
	if _, ok := p.AuthMode(req); ok {
		t.Fatal("accepted path traversal in AuthMode")
	}

	// CORS preflight allowed when headers are present.
	preflight := httptest.NewRequest(http.MethodOptions, "/api/private", nil)
	preflight.Header.Set("Origin", "https://app.example")
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	if mode, ok := p.AuthMode(preflight); !ok || mode != ModePublic {
		t.Fatalf("expected CORS preflight to be public, got %v %v", mode, ok)
	}

	// Plain OPTIONS without preflight headers still requires auth.
	plainOpt := httptest.NewRequest(http.MethodOptions, "/api/private", nil)
	if mode, ok := p.AuthMode(plainOpt); !ok || mode != ModeRequired {
		t.Fatalf("expected plain OPTIONS to require auth, got %v %v", mode, ok)
	}
}

func TestRouteRules(t *testing.T) {
	p, err := New(nil, nil, false, []string{
		"POST:/admin/*=realm:admin,client:writer",
		"/reports/*=realm:auditor",
	})
	if err != nil {
		t.Fatal(err)
	}

	adminID := auth.Identity{User: "alice", RealmRoles: []string{"admin"}, ClientRoles: []string{"writer"}}
	readerID := auth.Identity{User: "bob", RealmRoles: []string{"reader"}}

	if err := p.Authorize(httptest.NewRequest(http.MethodPost, "/admin/users", nil), adminID); err != nil {
		t.Fatalf("expected admin POST allowed: %v", err)
	}
	if err := p.Authorize(httptest.NewRequest(http.MethodPost, "/admin/users", nil), readerID); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("expected reader POST forbidden, got %v", err)
	}
	// GET /admin/users does not match POST:/admin/*.
	if err := p.Authorize(httptest.NewRequest(http.MethodGet, "/admin/users", nil), readerID); err != nil {
		t.Fatalf("unexpected error on non-matching method: %v", err)
	}
	if err := p.Authorize(httptest.NewRequest(http.MethodGet, "/reports/q1", nil), readerID); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("expected /reports forbidden for reader, got %v", err)
	}
}

func TestInvalidPolicyConfig(t *testing.T) {
	if _, err := New([]string{"relative"}, nil, false, nil); err == nil {
		t.Error("accepted relative public path")
	}
	if _, err := New(nil, []string{"/a/../b"}, false, nil); err == nil {
		t.Error("accepted traversal in optional path")
	}
	for _, bad := range []string{"invalid", "/admin=noroleprefix", "GET:relative=realm:a", "/admin="} {
		if _, err := New(nil, nil, false, []string{bad}); err == nil {
			t.Errorf("accepted invalid route rule %q", bad)
		}
	}
}

func TestEncodedPathTraversalRejected(t *testing.T) {
	p, err := New([]string{"/public/*"}, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"/admin%2fsecret", "/public/%2e%2e/admin", "/public%5cadmin", "/api/public%23method:GET"} {
		req := httptest.NewRequest(http.MethodGet, "http://proxy.test"+raw, nil)
		if _, ok := p.AuthMode(req); ok {
			t.Errorf("accepted encoded path %q", raw)
		}
	}
}

func TestRouteStepUpACRandAMR(t *testing.T) {
	p, err := New(nil, nil, false, []string{
		"POST:/admin/*=realm:admin,acr:aal2,amr:mfa",
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://proxy.test/admin/keys", nil)
	if err := p.Authorize(req, auth.Identity{RealmRoles: []string{"admin"}, ACR: "aal2", AMR: []string{"pwd", "mfa"}}); err != nil {
		t.Fatalf("expected step-up identity to be allowed, got %v", err)
	}
	if err := p.Authorize(req, auth.Identity{RealmRoles: []string{"admin"}, ACR: "aal1", AMR: []string{"pwd", "mfa"}}); err == nil {
		t.Fatal("expected wrong ACR to be denied")
	}
	if err := p.Authorize(req, auth.Identity{RealmRoles: []string{"admin"}, ACR: "aal2", AMR: []string{"pwd"}}); err == nil {
		t.Fatal("expected missing AMR to be denied")
	}
}

func BenchmarkPolicy(b *testing.B) {
	p, err := New([]string{"/public/*", "/status"}, []string{"/catalog/*"}, true, []string{
		"POST:/admin/*=realm:admin,client:writer",
		"/reports/*=realm:auditor",
	})
	if err != nil {
		b.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://proxy.test/admin/users", nil)
	id := auth.Identity{User: "alice", RealmRoles: []string{"admin"}, ClientRoles: []string{"writer"}}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		cleanPath, ok := NormalizeRequestPath(req)
		if !ok {
			b.Fatal("unexpected path rejection")
		}
		_ = p.AuthModeForPath(req, cleanPath)
		if err := p.AuthorizePath(req.Method, cleanPath, id); err != nil {
			b.Fatal(err)
		}
	}
}
