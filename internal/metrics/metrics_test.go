package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistryAndHandler(t *testing.T) {
	var nilReg *Registry
	nilReg.RecordRequest("forward_auth", "allowed")
	nilReg.RecordJWKSRefresh(true)
	nilReg.SetJWKSReady(false)
	nilReg.RecordIntrospection("active")
	nilReg.RecordUMA("allowed")
	nilReg.RecordOIDC("success")

	reg := New()
	reg.RecordRequest("forward_auth", "allowed")
	reg.RecordRequest("forward_auth", "unauthorized")
	reg.RecordRequest("reverse_proxy", "bad_gateway")
	reg.RecordJWKSRefresh(true)
	reg.RecordJWKSRefresh(false)
	reg.RecordIntrospection("active")
	reg.RecordIntrospection("cache_hit")
	reg.RecordUMA("denied")
	reg.RecordOIDC("started")
	reg.RecordOIDC("refreshed")

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`gocloak_auth_proxy_requests_total{mode="forward_auth",result="allowed"} 1`,
		`gocloak_auth_proxy_requests_total{mode="reverse_proxy",result="bad_gateway"} 1`,
		`gocloak_auth_proxy_jwks_refresh_total{result="success"} 1`,
		`gocloak_auth_proxy_jwks_refresh_total{result="error"} 1`,
		`gocloak_auth_proxy_jwks_ready 1`,
		`gocloak_auth_proxy_introspection_total{result="cache_hit"} 1`,
		`gocloak_auth_proxy_uma_total{result="denied"} 1`,
		`gocloak_auth_proxy_oidc_events_total{result="refreshed"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in metrics output:\n%s", want, body)
		}
	}

	postRec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(postRec, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", postRec.Code)
	}

	headRec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(headRec, httptest.NewRequest(http.MethodHead, "/metrics", nil))
	if headRec.Code != http.StatusOK || headRec.Body.Len() != 0 {
		t.Fatalf("HEAD unexpected: %d len=%d", headRec.Code, headRec.Body.Len())
	}
}
