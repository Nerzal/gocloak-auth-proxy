package jwks

import (
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testKeys(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{"kid": "rsa", "kty": "RSA", "alg": "RS256", "use": "sig", "n": enc(r.N.Bytes()), "e": enc([]byte{1, 0, 1})},
		map[string]any{"kid": "ec", "kty": "EC", "alg": "ES256", "crv": "P-256", "x": enc(e.X.FillBytes(make([]byte, 32))), "y": enc(e.Y.FillBytes(make([]byte, 32)))}
}

func serverCache(t *testing.T, handler http.HandlerFunc, interval time.Duration) (*Cache, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cache, err := New(server.URL+"/prefix/realms/example", interval)
	if err != nil {
		t.Fatal(err)
	}
	return cache, server
}

func TestIssuerValidation(t *testing.T) {
	for _, issuer := range []string{
		"http://example.com/realms/r", "https://user@example.com/realms/r",
		"https://example.com/realms/r?x=1", "https://example.com/realms/r#x",
		"https://example.com/realms/r/", "https://example.com/realms/%2F",
		"https://example.com/a/../realms/r", "https://example.com/other/r",
	} {
		if _, err := New(issuer, time.Minute); err == nil {
			t.Errorf("accepted issuer %q", issuer)
		}
	}
	for _, issuer := range []string{"https://example.com/auth/realms/r", "http://localhost:8080/realms/r", "http://[::1]:8080/realms/r"} {
		if _, err := New(issuer, time.Minute); err != nil {
			t.Errorf("rejected issuer %q: %v", issuer, err)
		}
	}
	if _, err := New("https://example.com/realms/r", 0); err == nil {
		t.Error("accepted zero refresh interval")
	}
	if _, err := New("https://example.com/realms/r", 12*time.Hour+time.Second); err == nil {
		t.Error("accepted refresh interval beyond snapshot lifetime budget")
	}
	if c, err := New("https://example.com/realms/r", 12*time.Hour); err != nil || c.maxAge != 24*time.Hour {
		t.Fatal("expected 12-hour refresh interval and 24-hour snapshot lifetime")
	}
}

func TestKeyParsingAndImmutableSnapshots(t *testing.T) {
	r, e := testKeys(t)
	cache, _ := serverCache(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/prefix/realms/example/protocol/openid-connect/certs" {
			t.Errorf("unexpected path: %s", req.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{r, e}})
	}, time.Minute)
	if cache.Ready() {
		t.Fatal("unexpected initial readiness")
	}
	key, err := cache.Key(context.Background(), "rsa", "RS256")
	if err != nil || !cache.Ready() {
		t.Fatalf("initial fetch: %v", err)
	}
	key.(*rsa.PublicKey).N.SetInt64(1)
	key, err = cache.Key(context.Background(), "rsa", "RS256")
	if err != nil || key.(*rsa.PublicKey).N.BitLen() != 2048 {
		t.Fatalf("snapshot was mutated: %v", err)
	}
	key, err = cache.Key(context.Background(), "ec", "ES256")
	if err != nil {
		t.Fatal(err)
	}
	key.(*ecdsa.PublicKey).X.SetInt64(0)
	key, err = cache.Key(context.Background(), "ec", "ES256")
	if err != nil || key.(*ecdsa.PublicKey).X.Sign() == 0 {
		t.Fatalf("EC snapshot was mutated: %v", err)
	}
	for _, tc := range [][2]string{{"rsa", "ES256"}, {"ec", "RS256"}, {"rsa", "none"}, {"", "RS256"}, {strings.Repeat("a", 257), "RS256"}} {
		if _, err := cache.Key(context.Background(), tc[0], tc[1]); err == nil {
			t.Errorf("accepted key %+v", tc)
		}
	}
}

func TestInvalidKeysAndDuplicateIDs(t *testing.T) {
	r, e := testKeys(t)
	testCases := []struct {
		name string
		keys []any
	}{
		{"duplicate", []any{r, r}},
		{"duplicate unusable", []any{r, map[string]any{"kid": "rsa", "kty": "oct"}}},
		{"small RSA", []any{map[string]any{"kid": "x", "kty": "RSA", "n": "AQ", "e": "Aw"}}},
		{"unsupported alg", []any{map[string]any{"kid": "x", "kty": "RSA", "alg": "HS256"}}},
		{"invalid EC", []any{map[string]any{"kid": "x", "kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ"}}},
		{"wrong use", []any{map[string]any{"kid": "x", "kty": "EC", "use": "enc"}}},
	}
	e["key_ops"] = []string{"sign", "verify"}
	testCases = append(testCases, struct {
		name string
		keys []any
	}{"unsafe key ops", []any{e}})
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cache, _ := serverCache(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": tc.keys})
			}, time.Minute)
			if err := cache.Refresh(context.Background()); err == nil || cache.Ready() {
				t.Fatalf("accepted invalid JWKS: %v", err)
			}
		})
	}
}

func TestRefreshCoalescingCooldownAndExpiry(t *testing.T) {
	r, _ := testKeys(t)
	var count atomic.Int32
	var fail atomic.Bool
	started, release := make(chan struct{}), make(chan struct{})
	cache, _ := serverCache(t, func(w http.ResponseWriter, _ *http.Request) {
		n := count.Add(1)
		if n == 1 {
			close(started)
			<-release
		}
		if fail.Load() {
			http.Error(w, "sensitive server detail", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{r}})
	}, time.Minute)
	const concurrent = 20
	var wg sync.WaitGroup
	wg.Add(concurrent)
	for range concurrent {
		go func() {
			defer wg.Done()
			_, _ = cache.Key(context.Background(), "missing", "RS256")
		}()
	}
	<-started
	close(release)
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("expected one coalesced fetch, got %d", count.Load())
	}
	if _, err := cache.Key(context.Background(), "other", "RS256"); err == nil || count.Load() != 1 {
		t.Fatal("unknown kid cooldown failed")
	}
	fail.Store(true)
	if err := cache.Refresh(context.Background()); err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("expected generic refresh error, got %v", err)
	}
	if !cache.Ready() {
		t.Fatal("refresh failure discarded fresh snapshot")
	}
	old := cache.current.Load()
	cache.current.Store(&snapshot{keys: old.keys, expires: time.Now().Add(-time.Second)})
	if cache.Ready() {
		t.Fatal("expired snapshot is ready")
	}
	if _, err := cache.Key(context.Background(), "rsa", "RS256"); err == nil {
		t.Fatal("accepted expired snapshot")
	}
}

func TestBoundedRequestsAndRedirects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"large", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, strings.Repeat(" ", maxResponseBytes+1))
		}},
		{"compressed large", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = gz.Write([]byte(strings.Repeat(" ", maxResponseBytes+1)))
			_ = gz.Close()
		}},
		{"redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/other", http.StatusFound) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, _ := serverCache(t, tc.handler, time.Minute)
			if err := cache.Refresh(context.Background()); err == nil || cache.Ready() {
				t.Fatalf("unexpected success: %v", err)
			}
		})
	}
}

func TestRotationAndRequestCancellation(t *testing.T) {
	r, e := testKeys(t)
	var rotate atomic.Bool
	var block atomic.Bool
	started := make(chan struct{})
	cache, _ := serverCache(t, func(w http.ResponseWriter, req *http.Request) {
		if block.Load() {
			close(started)
			<-req.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if rotate.Load() {
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{e}})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{r}})
		}
	}, time.Minute)
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotate.Store(true)
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Key(context.Background(), "ec", "ES256"); err != nil {
		t.Fatal("rotated key unavailable")
	}
	if _, err := cache.Key(context.Background(), "rsa", "RS256"); err == nil {
		t.Fatal("removed key still accepted")
	}
	block.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cache.Refresh(ctx) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled fetch succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled fetch did not return")
	}
}

func TestCancellationAndBackgroundRefresh(t *testing.T) {
	r, _ := testKeys(t)
	var count atomic.Int32
	cache, _ := serverCache(t, func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{r}})
	}, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { cache.Run(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for !cache.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
	if !cache.Ready() || count.Load() == 0 {
		t.Fatal("background refresh did not run")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := cache.Refresh(canceled); err == nil {
		t.Fatal("canceled refresh succeeded")
	}
}
