package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nerzal/gocloak-auth-proxy/internal/auth"
)

func TestIntrospectorActiveInactiveAndCache(t *testing.T) {
	var calls atomic.Int32
	var active atomic.Bool
	active.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/demo/protocol/openid-connect/token/introspect" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": active.Load()})
	}))
	defer srv.Close()

	intro, err := NewIntrospector(srv.URL+"/realms/demo", "client", "secret", time.Minute, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := intro.Active(context.Background(), "token-1")
	if err != nil || !ok {
		t.Fatalf("expected active=true, got %v %v", ok, err)
	}
	// Second call hits cache.
	ok, err = intro.Active(context.Background(), "token-1")
	if err != nil || !ok || calls.Load() != 1 {
		t.Fatalf("expected cache hit (calls=1), got ok=%v err=%v calls=%d", ok, err, calls.Load())
	}

	// Inactive token returns false.
	active.Store(false)
	ok, err = intro.Active(context.Background(), "token-2")
	if err != nil || ok {
		t.Fatalf("expected active=false, got %v %v", ok, err)
	}
}

func TestUMAAuthorizer(t *testing.T) {
	var allow atomic.Bool
	allow.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/demo/protocol/openid-connect/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("permission") != "/api/orders#method:POST" {
			t.Errorf("unexpected UMA permission: %q", r.FormValue("permission"))
		}
		if !allow.Load() {
			http.Error(w, `{"error":"access_denied"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{"rsid": "1", "rsname": "orders", "scopes": []string{"method:POST"}}})
	}))
	defer srv.Close()

	uma, err := NewUMAAuthorizer(srv.URL+"/realms/demo", "my-api", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := uma.Authorize(context.Background(), "raw-token", http.MethodPost, "/api/orders"); err != nil {
		t.Fatalf("expected UMA allow, got %v", err)
	}

	allow.Store(false)
	if err := uma.Authorize(context.Background(), "raw-token", http.MethodPost, "/api/orders"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("expected ErrForbidden on UMA deny, got %v", err)
	}
}

func BenchmarkIntrospectorCacheHit(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true})
	}))
	defer srv.Close()

	intro, err := NewIntrospector(srv.URL+"/realms/demo", "client", "secret", time.Minute, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	if ok, err := intro.Active(context.Background(), "cached-token"); err != nil || !ok {
		b.Fatalf("warmup failed: ok=%v err=%v", ok, err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if ok, err := intro.Active(context.Background(), "cached-token"); err != nil || !ok {
				b.Errorf("Active failed: ok=%v err=%v", ok, err)
				return
			}
		}
	})
}
