package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type staticReady bool

func (s staticReady) Ready() bool { return bool(s) }

func TestDrainableAndMultiReadiness(t *testing.T) {
	multi := MultiReadiness{staticReady(true), staticReady(true)}
	if !multi.Ready() {
		t.Fatal("expected MultiReadiness to be ready when all sources are ready")
	}
	if (MultiReadiness{staticReady(true), staticReady(false)}).Ready() {
		t.Fatal("expected MultiReadiness to be not ready when one source is not ready")
	}

	drainable := NewDrainable(multi)
	h := New(drainable)

	// Initially ready.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 before drain, got %d", rec.Code)
	}

	// Flip draining: /readyz returns 503 while /healthz remains 200.
	drainable.SetDraining(true)
	recReady := httptest.NewRecorder()
	h.ServeHTTP(recReady, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recReady.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when draining, got %d", recReady.Code)
	}
	recLive := httptest.NewRecorder()
	h.ServeHTTP(recLive, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recLive.Code != http.StatusOK {
		t.Fatalf("expected /healthz 200 during drain, got %d", recLive.Code)
	}
}
