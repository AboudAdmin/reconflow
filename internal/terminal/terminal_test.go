package terminal

import (
	"bytes"
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
	for _, w := range []string{"Target: example.com", "Run: run-1", "Elapsed: 00:02:14", "2/4", "Subdomains: 7", "Live services: 3", "Activity: + found a.example.com",
		"[DONE]", "[RUNNING]", "[QUEUED]", "[FAILED]", "tool exited 2", "httpx: boom", "(retries: 1)"} {
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

func TestHeaderOnceWithVersion(t *testing.T) {
	h := Header(Options{Width: 80, Version: "1.2.3"})
	if !strings.Contains(h, "v1.2.3") || !strings.Contains(h, "recon that separates") {
		t.Fatalf("banner/version missing:\n%s", h)
	}
	if strings.Contains(Render(snap(), Options{Width: 80}, time.Now()), "recon that separates") {
		t.Fatal("banner must not be part of the live frame")
	}
}

func TestBarProgress(t *testing.T) {
	if got := Bar(1, 4, 8, false); got != "[##------] 1/4  25%" {
		t.Fatalf("got %q", got)
	}
}

func TestTTYSkipsUnchangedFramesAndRedrawsInPlace(t *testing.T) {
	tr := model.NewTracker("example.com", "r1", []*model.StageState{{ID: "a", Title: "A", Status: model.Running}})
	var buf bytes.Buffer
	u := New(&buf, tr, Options{Width: 80}, true, time.Hour)
	fixed := time.Now()
	u.now = func() time.Time { return fixed }
	u.draw()
	n := buf.Len()
	u.draw() // nothing changed: must write nothing
	if buf.Len() != n {
		t.Fatal("identical frame was redrawn")
	}
	tr.Event("found x")
	u.draw()
	out := buf.String()[n:]
	if !strings.Contains(out, "\x1b[") || !strings.Contains(out, "A\r") || !strings.Contains(out, "found x") {
		t.Fatalf("expected in-place redraw, got %q", out)
	}
	if strings.Contains(out, "\x1b[2J") {
		t.Fatal("must not clear the whole screen")
	}
}

func TestWrappedRowsAfterResize(t *testing.T) {
	if got := wrapped([]int{50, 10, 0}, 40); got != 4 { // 2 + 1 + 1
		t.Fatalf("got %d", got)
	}
}

func TestPlainModePrintsTransitionsOnce(t *testing.T) {
	tr := model.NewTracker("example.com", "r1", []*model.StageState{{ID: "a", Title: "A", Status: model.Queued}})
	var buf bytes.Buffer
	u := New(&buf, tr, Options{Width: 80}, false, time.Hour)
	tr.Stage("a", func(s *model.StageState) { s.Status = model.Running })
	tr.Event("hello")
	u.tick()
	u.tick()
	if c := strings.Count(buf.String(), "A: running"); c != 1 {
		t.Fatalf("transition printed %d times:\n%s", c, buf.String())
	}
	if strings.Contains(buf.String(), "\x1b") || strings.Count(buf.String(), "hello") != 1 {
		t.Fatalf("bad plain output:\n%s", buf.String())
	}
}
