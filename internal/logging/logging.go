// Package logging provides structured JSON logs with secret redaction.
package logging

import (
	"io"
	"log/slog"
	"regexp"
	"strings"
)

const Redacted = "[REDACTED]"

var (
	secretKey = regexp.MustCompile(`(?i)(pass(word)?|secret|token|api[_-]?key|cookie|authorization|credential)`)
	secretVal = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`),
		regexp.MustCompile(`(?i)\b(api[_-]?key|token|secret|password|passwd|session)=[^\s&"']+`),
		regexp.MustCompile(`(?i)\b(authorization|cookie|x-api-key):\s*[^\r\n]+`),
		regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`),
	}
)

// Redact masks credentials embedded in free text.
func Redact(s string) string {
	for _, re := range secretVal {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			if strings.HasPrefix(m, "://") {
				return "://" + Redacted + "@"
			}
			if i := strings.IndexAny(m, "=: "); i > 0 {
				return m[:i+1] + Redacted
			}
			return Redacted
		})
	}
	return s
}

// New returns a JSON logger writing to w. Level is debug|info|warn|error.
func New(w io.Writer, level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l, ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if secretKey.MatchString(a.Key) {
			return slog.String(a.Key, Redacted)
		}
		if a.Value.Kind() == slog.KindString {
			return slog.String(a.Key, Redact(a.Value.String()))
		}
		return a
	}}))
}
