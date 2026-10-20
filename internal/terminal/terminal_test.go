package terminal

import (
	"strings"
	"testing"
	"time"

	"reconflow/internal/model"
)

func snap() model.Snapshot {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return model.Snapshot{Target: "example.com", RunID: "run-1", Started: t0,
		Counts: map[string]int{"subdomain": 7, "service": 3},
		Stages: []model.StageState{
			{ID: "a", Title: "Subdomain discovery", Status: model.Success, Output: 7},
			{ID: "b", Title: "HTTP probing", Status: model.Running, Started: t0, Retries: 1},
			{ID: "c", Title: "Crawling", Status: model.Queued},
			{ID: "d", Title: "JavaScript analysis", Status: model.Failed, Detail: "tool exited 2"},
		},
		Events: []model.Event{{Text: "found a.example.com"}}, Errors: []string{"httpx: boom"}}
}

func TestPlainFallbackHasNoEscapesOrUnicode(t *testing.T) {
	out := Render(snap(), Options{Width: 80}, time.Date(2026, 1, 1, 0, 2, 14, 0, time.UTC))
	if strings.Contains(out, "\x1b") {
		t.Fatal("plain output contains ANSI escapes")
	}
	for _, r := range out {
		if r > 127 {
			t.Fatalf("plain output contains non-ASCII %q", r)
		}
	}
	for _, w := range []string{"Target: example.com", "Run:    run-1", "Elapsed: 00:02:14", "Completed stages: 2/4", "Subdomains: 7", "Live services: 3",
		"[DONE]", "[RUNNING]", "[QUEUED]", "[FAILED]", "tool exited 2", "found a.example.com", "httpx: boom", "(retries: 1)"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

func TestColorAndUnicodeAndClip(t *testing.T) {
	out := Render(snap(), Options{Color: true, Unicode: true, Width: 40}, time.Now())
	if !strings.Contains(out, "\x1b[32m") || !strings.Contains(out, "▸") {
		t.Fatal("color/unicode mode not applied")
	}
	for _, l := range strings.Split(out, "\n") {
		plain := l
		for strings.Contains(plain, "\x1b[") {
			i := strings.Index(plain, "\x1b[")
			j := strings.IndexByte(plain[i:], 'm')
			plain = plain[:i] + plain[i+j+1:]
		}
		if n := len([]rune(plain)); n > 40 {
			t.Errorf("line exceeds width (%d): %q", n, plain)
		}
	}
}
