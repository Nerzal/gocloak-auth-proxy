package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: redact}))
}

func NewWithLevel(w io.Writer, level string) (*slog.Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		lvl = slog.LevelInfo
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       lvl,
		ReplaceAttr: redact,
	})), nil
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
