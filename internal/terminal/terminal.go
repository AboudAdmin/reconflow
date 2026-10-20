// Package terminal renders the live run view from a model.Tracker snapshot.
// Rendering is a pure function (Render) so the plain-text fallback is testable.
package terminal

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"reconflow/internal/model"
)

type Options struct {
	Color, Unicode bool
	Width          int
}

const (
	reset  = "\x1b[0m"
	dim    = "\x1b[2m"
	bold   = "\x1b[1m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
	gray   = "\x1b[90m"
)

var tags = map[model.Status]struct {
	text, color string
}{
	model.Success:   {"DONE", green},
	model.Running:   {"RUNNING", cyan},
	model.Queued:    {"QUEUED", gray},
	model.Skipped:   {"SKIPPED", gray},
	model.Failed:    {"FAILED", red},
	model.Partial:   {"PARTIAL", yellow},
	model.Cancelled: {"CANCELLED", yellow},
}

func Elapsed(d time.Duration) string {
	s := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", s/3600, s%3600/60, s%60)
}

func clip(s string, w int) string {
	if w > 0 && utf8.RuneCountInString(s) > w {
		r := []rune(s)
		return string(r[:w-1]) + "…"
	}
	return s
}

// Render builds the full screen. now is injected for deterministic tests.
func Render(s model.Snapshot, o Options, now time.Time) string {
	if o.Width < 40 {
		o.Width = 80
	}
	col := func(c, t string) string {
		if o.Color {
			return c + t + reset
		}
		return t
	}
	var b strings.Builder
	line := func(c, t string) { b.WriteString(col(c, clip(t, o.Width-1)) + "\n") }
	rule := "-"
	if o.Unicode {
		rule = "━"
	}
	line(bold+cyan, "RECONFLOW")
	line(gray, strings.Repeat(rule, minInt(o.Width-1, 60)))
	line("", "Target: "+s.Target)
	line("", "Run:    "+s.RunID)
	if s.Note != "" {
		line(yellow, s.Note)
	}
	b.WriteString("\n")
	done, running, retries := 0, 0, 0
	cur := []string{}
	for _, st := range s.Stages {
		if st.Status.Terminal() {
			done++
		}
		if st.Status == model.Running {
			running++
			cur = append(cur, st.Title)
		}
		retries += st.Retries
	}
	curStage := "-"
	if len(cur) > 0 {
		curStage = strings.Join(cur, ", ")
	}
	line("", "Elapsed: "+Elapsed(now.Sub(s.Started)))
	line("", "Stage:   "+curStage)
	line("", fmt.Sprintf("Completed stages: %d/%d   Active tool processes: %d   Retries: %d", done, len(s.Stages), running, retries))
	b.WriteString("\n")
	c := s.Counts
	line("", fmt.Sprintf("Subdomains: %d   DNS observations: %d   Live services: %d", c["subdomain"], c["dns"], c["service"]))
	line("", fmt.Sprintf("URL candidates: %d   JS contents analyzed: %d   JS candidates: %d", c["url"], c["js"], c["js_candidates"]))
	if c["new"] > 0 || c["changed"] > 0 {
		line("", fmt.Sprintf("New: %d   Changed: %d", c["new"], c["changed"]))
	}
	b.WriteString("\n")
	for _, st := range s.Stages {
		t := tags[st.Status]
		tag := "[" + t.text + "]"
		pad := strings.Repeat(" ", maxInt(1, 12-len(tag)))
		extra := ""
		switch {
		case st.Status == model.Running:
			extra = "  " + Elapsed(now.Sub(st.Started))
		case st.Status.Terminal() && st.Status != model.Skipped && st.Status != model.Cancelled:
			extra = fmt.Sprintf("  %d records", st.Output)
		}
		if st.Retries > 0 {
			extra += fmt.Sprintf("  (retries: %d)", st.Retries)
		}
		if st.Detail != "" && (st.Status == model.Failed || st.Status == model.Partial || st.Status == model.Skipped) {
			extra += "  - " + st.Detail
		}
		b.WriteString(col(t.color, tag) + pad + clip(st.Title+extra, o.Width-14) + "\n")
	}
	if len(s.Events) > 0 {
		b.WriteString("\n")
		line(gray, "Recent events:")
		mark := "+"
		if o.Unicode {
			mark = "▸"
		}
		ev := s.Events
		if len(ev) > 5 {
			ev = ev[len(ev)-5:]
		}
		for _, e := range ev {
			line("", mark+" "+e.Text)
		}
	}
	if len(s.Errors) > 0 {
		b.WriteString("\n")
		line(red, "Errors:")
		er := s.Errors
		if len(er) > 3 {
			er = er[len(er)-3:]
		}
		for _, e := range er {
			line(red, "! "+e)
		}
	}
	if len(s.Reports) > 0 {
		b.WriteString("\n")
		for _, r := range s.Reports {
			line("", "Report: "+r)
		}
	}
	return b.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Detect decides color/unicode/tty support from config ("auto|always|never") and environment.
func Detect(out *os.File, colorCfg, uniCfg string) (opts Options, tty bool) {
	if st, err := out.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		tty = enableVT(out)
	}
	dumb := os.Getenv("TERM") == "dumb"
	switch colorCfg {
	case "always":
		opts.Color = true
	case "auto":
		opts.Color = tty && os.Getenv("NO_COLOR") == "" && !dumb
	}
	switch uniCfg {
	case "always":
		opts.Unicode = true
	case "auto":
		l := strings.ToUpper(os.Getenv("LC_ALL") + os.Getenv("LC_CTYPE") + os.Getenv("LANG"))
		opts.Unicode = tty && !dumb && (strings.Contains(l, "UTF-8") || strings.Contains(l, "UTF8") || os.Getenv("WT_SESSION") != "")
	}
	opts.Width = 80
	if w, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && w >= 40 {
		opts.Width = minInt(w, 160)
	}
	return
}

// UI redraws on a throttle (TTY) or prints transitions as lines (non-TTY).
type UI struct {
	out     io.Writer
	tr      *model.Tracker
	opts    Options
	tty     bool
	every   time.Duration
	stop    chan struct{}
	wg      sync.WaitGroup
	lines   int
	printed int
	last    map[string]model.Status
}

func New(out io.Writer, tr *model.Tracker, o Options, tty bool, every time.Duration) *UI {
	return &UI{out: out, tr: tr, opts: o, tty: tty, every: every, stop: make(chan struct{}), last: map[string]model.Status{}}
}

func (u *UI) Start() {
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		t := time.NewTicker(u.every)
		defer t.Stop()
		for {
			select {
			case <-u.stop:
				return
			case <-t.C:
				u.tick(false)
			}
		}
	}()
}

func (u *UI) tick(final bool) {
	if u.tty {
		// Throttled by the ticker; redrawn even when idle so the elapsed clock advances.
		screen := Render(u.tr.Snapshot(), u.opts, time.Now())
		if u.lines > 0 {
			fmt.Fprintf(u.out, "\x1b[%dA\x1b[J", u.lines)
		}
		fmt.Fprint(u.out, screen)
		u.lines = strings.Count(screen, "\n")
		return
	}
	s := u.tr.Snapshot()
	ids := make([]string, 0)
	for _, st := range s.Stages {
		ids = append(ids, st.ID)
		if u.last[st.ID] != st.Status && st.Status != model.Queued {
			fmt.Fprintf(u.out, "[%s] %s: %s %s\n", time.Now().Format("15:04:05"), st.Title, st.Status, st.Detail)
		}
		u.last[st.ID] = st.Status
	}
	sort.Strings(ids)
	if n := s.EvTotal - u.printed; n > 0 {
		ev := s.Events
		if n > len(ev) {
			n = len(ev)
		}
		for _, e := range ev[len(ev)-n:] {
			fmt.Fprintf(u.out, "[%s] + %s\n", e.Time.Format("15:04:05"), e.Text)
		}
		u.printed = s.EvTotal
	}
}

// Stop halts redraws and prints the final frame.
func (u *UI) Stop() {
	close(u.stop)
	u.wg.Wait()
	u.tick(true)
}
