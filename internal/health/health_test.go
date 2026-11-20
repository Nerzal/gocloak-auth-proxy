package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type readiness bool

func (r readiness) Ready() bool { return bool(r) }

func TestHealth(t *testing.T) {
	tests := []struct {
		path, method string
		ready        Readiness
		status       int
	}{
		{"/healthz", "GET", readiness(false), http.StatusOK},
		{"/readyz", "GET", readiness(true), http.StatusOK},
		{"/readyz", "GET", readiness(false), http.StatusServiceUnavailable},
		{"/readyz", "GET", nil, http.StatusServiceUnavailable},
		{"/healthz", "HEAD", readiness(false), http.StatusOK},
		{"/readyz", "POST", readiness(true), http.StatusMethodNotAllowed},
		{"/missing", "GET", readiness(true), http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.method+tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			New(tt.ready).ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Error("missing security headers")
			}
			if tt.method == "HEAD" && rec.Body.Len() != 0 {
				t.Error("HEAD included a response body")
			}
		})
	}
}
