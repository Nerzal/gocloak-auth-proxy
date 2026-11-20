package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactsSensitiveAttributes(t *testing.T) {
	var out bytes.Buffer
	logger := New(&out)
	logger.Info("request", "authorization", "private-value", "client_secret", "another-private-value", "status", 401)
	if strings.Contains(out.String(), "private-value") || !strings.Contains(out.String(), "[REDACTED]") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}
