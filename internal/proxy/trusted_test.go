package proxy

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTrustedProxiesAndAccessLog(t *testing.T) {
	var seenXFF, seenProto, seenHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenXFF = r.Header.Get("X-Forwarded-For")
		seenProto = r.Header.Get("X-Forwarded-Proto")
		seenHost = r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	h, err := NewReverseProxyWithOptions(verifierFunc(verified), upstream.URL, Options{
		TrustedProxies: []string{"10.0.0.0/8"},
		AccessLog:      true,
		Logger:         logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Request from trusted CIDR preserves X-Forwarded-* and appends remote IP.
	req1 := httptest.NewRequest(http.MethodGet, "http://proxy.test/api/data", nil)
	req1.RemoteAddr = "10.1.2.3:54321"
	req1.Header.Set("Authorization", "Bearer super-secret-jwt")
	req1.Header.Set("X-Forwarded-For", "203.0.113.9")
	req1.Header.Set("X-Forwarded-Proto", "https")
	req1.Header.Set("X-Forwarded-Host", "app.example.test")
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec1.Code)
	}
	if seenXFF != "203.0.113.9, 10.1.2.3" || seenProto != "https" || seenHost != "app.example.test" {
		t.Fatalf("unexpected trusted forwarded headers: xff=%q proto=%q host=%q", seenXFF, seenProto, seenHost)
	}

	// 2. Request from untrusted IP strips all X-Forwarded-* headers.
	req2 := httptest.NewRequest(http.MethodGet, "http://proxy.test/api/data", nil)
	req2.RemoteAddr = "198.51.100.7:12345"
	req2.Header.Set("Authorization", "Bearer super-secret-jwt")
	req2.Header.Set("X-Forwarded-For", "1.2.3.4")
	req2.Header.Set("X-Forwarded-Proto", "https")
	req2.Header.Set("X-Forwarded-Host", "spoofed.test")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}
	if seenXFF != "" || seenProto != "" || seenHost != "" {
		t.Fatalf("untrusted forwarded headers leaked: xff=%q proto=%q host=%q", seenXFF, seenProto, seenHost)
	}

	// 3. Access log recorded method/path/status without leaking bearer token.
	logged := logBuf.String()
	if !strings.Contains(logged, `"msg":"http request"`) || !strings.Contains(logged, `"/api/data"`) {
		t.Fatalf("missing access log entry:\n%s", logged)
	}
	if strings.Contains(logged, "super-secret-jwt") {
		t.Fatalf("access log leaked bearer token:\n%s", logged)
	}
}
