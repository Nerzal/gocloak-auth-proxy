package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactsSensitiveAttributes(t *testing.T) {
	var out bytes.Buffer
	logger := New(&out)
	logger.Info("request",
		"authorization", "private-value",
		"client_secret", "another-private-value",
		"jwt_claim", "raw-jwt-value",
		"reason", "failed with Bearer eyJhbGciOiJSUzI1NiJ9.secret",
		"status", 401,
	)
	got := out.String()
	for _, leaked := range []string{"private-value", "raw-jwt-value", "eyJhbGciOiJSUzI1NiJ9"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("leaked %q in output: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") || !strings.Contains(got, `"status":401`) {
		t.Fatalf("unexpected output: %s", got)
	}
}
