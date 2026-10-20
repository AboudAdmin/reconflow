package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedaction(t *testing.T) {
	cases := map[string]string{
		"Authorization: Bearer abc.def-123":     "abc.def-123",
		"GET /x?api_key=SECRET123&b=1":          "SECRET123",
		"https://user:hunter2@example.com/path": "hunter2",
		"cookie: session=deadbeef; other=1":     "deadbeef",
		"token=tok_live_999":                    "tok_live_999",
		"header X-API-Key: k-12345 end":         "k-12345",
	}
	for in, secret := range cases {
		if out := Redact(in); strings.Contains(out, secret) || !strings.Contains(out, Redacted) {
			t.Errorf("Redact(%q) = %q", in, out)
		}
	}
	if Redact("plain text without secrets") != "plain text without secrets" {
		t.Error("benign text altered")
	}
}

func TestLoggerRedactsKeysAndValues(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, "info")
	l.Info("exec", "api_key", "AAA111", "args", "-H Authorization: Bearer ZZZ999", "stage", "httpx")
	l.Debug("hidden")
	out := b.String()
	if strings.Contains(out, "AAA111") || strings.Contains(out, "ZZZ999") || strings.Contains(out, "hidden") || !strings.Contains(out, `"stage":"httpx"`) {
		t.Errorf("log output: %s", out)
	}
}
