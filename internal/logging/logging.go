package logging

import (
	"io"
	"log/slog"
	"strings"
)

func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: redact}))
}

func redact(_ []string, a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	for _, sensitive := range []string{"token", "authorization", "cookie", "secret", "password", "email", "bearer", "jwt", "credential", "session"} {
		if strings.Contains(key, sensitive) {
			return slog.String(a.Key, "[REDACTED]")
		}
	}
	if a.Value.Kind() == slog.KindString && strings.Contains(strings.ToLower(a.Value.String()), "bearer ") {
		return slog.String(a.Key, "[REDACTED]")
	}
	return a
}
