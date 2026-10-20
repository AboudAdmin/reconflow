// Package terminal renders the live run view from a model.Tracker snapshot.
// Rendering is a pure function (Render) so the plain-text fallback is testable.
package terminal

import (
	"fmt"
	"io"
	"os"
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
	Version        string
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
		return string(r[:w-3]) + "..." // ASCII so plain terminals stay clean
	}
	return s
}

// Render builds the live frame (no banner; see Header). now is injected for deterministic tests.
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
	line(bold, "Target: "+s.Target+"   Run: "+s.RunID+"   Elapsed: "+Elapsed(now.Sub(s.Started)))
	if s.Note != "" {
		line(yellow, s.Note)
	}
	line("", "Progress "+Bar(done, len(s.Stages), minInt(28, o.Width-30), o.Unicode))
	line("", fmt.Sprintf("Stage: %s   Active: %d   Retries: %d", curStage, running, retries))
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
	b.WriteString("\n")
	c := s.Counts
	counters := fmt.Sprintf("Subdomains: %d   DNS: %d   Live services: %d   URLs: %d   JS analyzed: %d   JS candidates: %d",
		c["subdomain"], c["dns"], c["service"], c["url"], c["js"], c["js_candidates"])
	if c["new"] > 0 || c["changed"] > 0 {
		counters += fmt.Sprintf("   New: %d   Changed: %d", c["new"], c["changed"])
	}
	line("", counters)
	if n := len(s.Events); n > 0 {
		mark := "+"
		if o.Unicode {
			mark = "▸"
		}
		line(gray, "Activity: "+mark+" "+s.Events[n-1].Text)
	}
	if len(s.Errors) > 0 {
		er := s.Errors
		if len(er) > 3 {
			er = er[len(er)-3:]
		}
		for _, e := range er {
			line(red, "! "+e)
		}
	}
	for _, r := range s.Reports {
		line("", "Report: "+r)
	}
	return b.String()
}

// Header is the one-time startup banner.
func Header(o Options) string {
	if o.Width < 40 {
		o.Width = 80
	}
	ver := ""
	if o.Version != "" {
		ver = " v" + o.Version
	}
	var b strings.Builder
	if o.Width >= 50 {
		for _, l := range Banner {
			b.WriteString(Paint(o, bold+cyan, l) + "\n")
		}
		b.WriteString(Paint(o, gray, "recon that separates signal from noise"+ver) + "\n\n")
	} else {
		b.WriteString(Paint(o, bold+cyan, "RECONFLOW"+ver) + "\n\n")
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

// UI redraws in place on a throttle (TTY) or prints transitions as lines (non-TTY).
type UI struct {
	out     io.Writer
	tr      *model.Tracker
	opts    Options
	tty     bool
	every   time.Duration
	now     func() time.Time
	stop    chan struct{}
	wg      sync.WaitGroup
	prev    string // last frame drawn; identical frames are skipped
	rows    []int  // visible width of each drawn line, to count wrapped rows after a resize
	printed int
	last    map[string]model.Status
}

func New(out io.Writer, tr *model.Tracker, o Options, tty bool, every time.Duration) *UI {
	return &UI{out: out, tr: tr, opts: o, tty: tty, every: every, now: time.Now, stop: make(chan struct{}), last: map[string]model.Status{}}
}

func (u *UI) Start() {
	fmt.Fprint(u.out, Header(u.opts))
	if u.tty {
		fmt.Fprint(u.out, "\x1b[?25l") // hide the cursor while redrawing
	}
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
				u.tick()
			}
		}
	}()
}

func (u *UI) tick() {
	if u.tty {
		u.draw()
		return
	}
	s := u.tr.Snapshot()
	for _, st := range s.Stages {
		if u.last[st.ID] != st.Status && st.Status != model.Queued {
			fmt.Fprintf(u.out, "[%s] %s: %s %s\n", u.now().Format("15:04:05"), st.Title, st.Status, st.Detail)
		}
		u.last[st.ID] = st.Status
	}
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

// draw repaints the live frame in place. Flicker root cause: every tick erased the region
// (cursor-up + clear-to-end) and reprinted it even when nothing changed, and the cursor-up
// count ignored wrapped lines after a resize. Now identical frames are skipped, lines are
// overwritten (erase-to-EOL, never a blank frame) and wrapped rows are counted.
func (u *UI) draw() {
	o := u.opts
	var h int
	if f, ok := u.out.(*os.File); ok {
		if w, rows := size(f); w >= 40 {
			o.Width, h = minInt(w, 160), rows
		}
	}
	lines := strings.Split(strings.TrimSuffix(Render(u.tr.Snapshot(), o, u.now()), "\n"), "\n")
	// shortcut: a terminal shorter than the frame drops the tail lines (errors/reports); the final summary still lists failures.
	if h > 2 && len(lines) > h-1 {
		lines = lines[:h-1]
	}
	screen := strings.Join(lines, "\n")
	if screen == u.prev {
		return
	}
	var b strings.Builder
	if up := wrapped(u.rows, o.Width); up > 0 {
		fmt.Fprintf(&b, "\x1b[%dA\r", up)
	}
	u.rows = u.rows[:0]
	for _, l := range lines {
		b.WriteString(l + "\x1b[K\n")
		u.rows = append(u.rows, visLen(l))
	}
	b.WriteString("\x1b[J") // drop leftovers when the frame got shorter
	fmt.Fprint(u.out, b.String())
	u.prev = screen
}

// wrapped is the number of terminal rows the drawn lines occupy at width w.
func wrapped(widths []int, w int) int {
	n := 0
	for _, l := range widths {
		n += maxInt(1, (l+w-1)/maxInt(w, 1))
	}
	return n
}

// visLen counts printable runes, skipping ANSI SGR sequences.
func visLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case esc:
			esc = r != 'm'
		case r == '\x1b':
			esc = true
		default:
			n++
		}
	}
	return n
}

// Stop halts redraws, prints the final frame and restores the cursor.
func (u *UI) Stop() {
	close(u.stop)
	u.wg.Wait()
	u.tick()
	if u.tty {
		fmt.Fprint(u.out, "\x1b[?25h")
	}
}

// Banner is plain ASCII so it survives any terminal and log capture.
var Banner = []string{
	` ___                    ___ _`,
	`| _ \___ __ ___ _ _    | __| |_____ __ __`,
	`|   / -_) _/ _ \ ' \   | _|| / _ \ V  V /`,
	`|_|_\___\__\___/_||_|  |_| |_\___/\_/\_/`,
}

// Bar renders "[#####-----] 2/4 50%" (or block characters with unicode).
func Bar(done, total, width int, unicode bool) string {
	if total <= 0 {
		return ""
	}
	fill := done * width / total
	on, off := "#", "-"
	if unicode {
		on, off = "█", "░"
	}
	return fmt.Sprintf("[%s%s] %d/%d  %d%%", strings.Repeat(on, fill), strings.Repeat(off, width-fill), done, total, done*100/total)
}

// Paint wraps text in a color when the terminal supports it.
func Paint(o Options, color, text string) string {
	if !o.Color {
		return text
	}
	return color + text + reset
}

// Colors for callers that print their own summaries.
const (
	Green, Yellow, Red, Cyan, Gray, Bold = green, yellow, red, cyan, gray, bold
)

// StatusColor maps a status word to its color.
func StatusColor(status string) string {
	if t, ok := tags[model.Status(status)]; ok {
		return t.color
	}
	return ""
}

// Table prints rows aligned to the widest cell per column (cells are never wrapped).
func Table(w io.Writer, o Options, header []string, rows [][]string, colorCol int) {
	width := make([]int, len(header))
	for i, h := range header {
		width[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		for i, c := range r {
			width[i] = maxInt(width[i], utf8.RuneCountInString(c))
		}
	}
	cell := func(i int, c string, paint string) string {
		pad := strings.Repeat(" ", width[i]-utf8.RuneCountInString(c))
		if paint != "" {
			c = Paint(o, paint, c)
		}
		return c + pad
	}
	var hb strings.Builder
	for i, h := range header {
		hb.WriteString(cell(i, h, bold) + "  ")
	}
	fmt.Fprintln(w, strings.TrimRight(hb.String(), " "))
	for _, r := range rows {
		var rb strings.Builder
		for i, c := range r {
			p := ""
			if i == colorCol {
				p = StatusColor(strings.ToLower(c))
			}
			rb.WriteString(cell(i, c, p) + "  ")
		}
		fmt.Fprintln(w, strings.TrimRight(rb.String(), " "))
	}
}
