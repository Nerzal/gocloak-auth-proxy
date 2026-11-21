// Package health provides liveness and readiness endpoints.
package health

import (
	"net/http"
	"sync/atomic"
)

// Readiness reports whether the service is ready to receive traffic.
type Readiness interface {
	Ready() bool
}

// Drainable wraps a Readiness source so graceful shutdown can immediately flip
// /readyz to 503 while /healthz stays 200 during the Kubernetes drain window.
type Drainable struct {
	inner    Readiness
	draining atomic.Bool
}

// NewDrainable wraps inner with an atomic draining flag.
func NewDrainable(inner Readiness) *Drainable {
	return &Drainable{inner: inner}
}

// SetDraining marks the service as draining (true) or active (false).
func (d *Drainable) SetDraining(draining bool) {
	if d != nil {
		d.draining.Store(draining)
	}
}

// Ready reports false when draining or when the underlying readiness is false.
func (d *Drainable) Ready() bool {
	if d == nil || d.draining.Load() || d.inner == nil {
		return false
	}
	return d.inner.Ready()
}

// MultiReadiness reports ready when all configured readiness sources are ready.
type MultiReadiness []Readiness

// Ready returns true iff at least one source is configured and all are ready.
func (m MultiReadiness) Ready() bool {
	if len(m) == 0 {
		return false
	}
	for _, r := range m {
		if r == nil || !r.Ready() {
			return false
		}
	}
	return true
}

// New serves /healthz and /readyz. A nil readiness dependency is not ready.
func New(readiness Readiness) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/readyz" && (readiness == nil || !readiness.Ready()) {
			http.Error(w, "Not Ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("OK\n"))
		}
	})
}
