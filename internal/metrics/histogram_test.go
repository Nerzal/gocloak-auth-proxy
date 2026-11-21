package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLatencyHistograms(t *testing.T) {
	reg := New()
	reg.RecordDuration("forward_auth", 800*time.Microsecond)
	reg.RecordDuration("forward_auth", 3*time.Millisecond)
	reg.RecordDuration("reverse_proxy", 20*time.Millisecond)

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		`# TYPE gocloak_auth_proxy_request_duration_seconds histogram`,
		`gocloak_auth_proxy_request_duration_seconds_bucket{mode="forward_auth",le="0.001"} 1`,
		`gocloak_auth_proxy_request_duration_seconds_bucket{mode="forward_auth",le="0.005"} 2`,
		`gocloak_auth_proxy_request_duration_seconds_bucket{mode="forward_auth",le="+Inf"} 2`,
		`gocloak_auth_proxy_request_duration_seconds_count{mode="forward_auth"} 2`,
		`gocloak_auth_proxy_request_duration_seconds_bucket{mode="reverse_proxy",le="0.025"} 1`,
		`gocloak_auth_proxy_request_duration_seconds_count{mode="reverse_proxy"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing metric line %q in:\n%s", want, body)
		}
	}
}
