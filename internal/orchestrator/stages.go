package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"reconflow/internal/adapters"
	"reconflow/internal/jsintel"
	"reconflow/internal/logging"
	"reconflow/internal/model"
	"reconflow/internal/normalize"
	"reconflow/internal/runner"
	"reconflow/internal/scheduler"
	"reconflow/internal/storage"
)

// stageResult is what a stage run reports; finish() turns it into a persisted
// stage row + checkpoint and a scheduler outcome.
type stageResult struct {
	status    model.Status
	inputs    int
	outputs   int
	dropped   int
	exit      int
	detail    string
	artifact  string
	retryable bool
}

func (s *state) runStage(ctx context.Context, d StageDef, attempt int) scheduler.Outcome {
	started := time.Now().UTC()
	var r stageResult
	if d.ID == "js" {
		r = s.runJS(ctx)
	} else {
		r = s.runTool(ctx, d, attempt)
	}
	return s.finish(d, started, attempt, r)
}

func (s *state) finish(d StageDef, started time.Time, attempt int, r stageResult) scheduler.Outcome {
	row := storage.Stage{Run: s.run.ID, ID: d.ID, Tool: d.ID, Status: string(r.status), Passive: s.o.Cfg.IsPassive(d.ID),
		Started: started, Finished: time.Now().UTC(), Inputs: r.inputs, Outputs: r.outputs, Dropped: r.dropped, Retries: attempt,
		ExitCode: r.exit, Error: logging.Redact(r.detail), Artifact: r.artifact, Comparable: r.status == model.Success}
	if d.Adapter != nil {
		row.Tool = d.Adapter.Binary
		if info := s.tools[d.ID]; info.Version != "" {
			row.Tool += " " + info.Version
		}
	}
	if r.status == model.Success || r.status == model.Partial || r.status == model.Failed {
		row.Error = logging.Redact(r.detail)
	}
	cp := storage.Checkpoint{Stage: d.ID, State: "interrupted"}
	if r.status == model.Success {
		cp.State = "done"
		if r.artifact != "" {
			cp.ArtifactSHA, _ = fileSHA(r.artifact)
		}
	}
	if err := s.o.DB.FinishStage(row, cp); err != nil {
		s.log.Error("persist stage result", "stage", d.ID, "err", err.Error())
		r.status, r.detail, r.retryable = model.Failed, "database error: "+err.Error(), false
	}
	if r.status == model.Failed || r.status == model.Partial {
		msg := d.ID + ": " + r.detail
		s.o.DB.AddError(s.run.ID, d.ID, logging.Redact(msg))
		s.tr.AddError(logging.Redact(msg))
	}
	s.log.Info("stage finished", "stage", d.ID, "status", r.status, "outputs", r.outputs, "dropped", r.dropped, "detail", r.detail)
	s.tr.Stage(d.ID, func(ss *model.StageState) {
		ss.Status, ss.Output, ss.Detail, ss.Finished = r.status, r.outputs, r.detail, time.Now()
	})
	var err error
	if r.status != model.Success {
		err = errors.New(r.detail)
	}
	return scheduler.Outcome{Status: r.status, Err: err, Retryable: r.retryable}
}

// ---------------------------------------------------------------- inputs

func (s *state) hostInputs() ([]string, int, error) {
	ents, err := s.o.DB.RunEntities(s.run.ID)
	if err != nil {
		return nil, 0, err
	}
	hosts := []string{s.o.Target}
	for _, e := range ents {
		if e.Kind == model.KindSubdomain {
			hosts = append(hosts, e.Key)
		}
	}
	// Hosts whose DNS answer is a special-purpose address are never probed
	// unless the scope explicitly authorises that address.
	blocked := map[string]bool{}
	for _, e := range ents {
		if e.Kind != model.KindDNS {
			continue
		}
		for _, k := range []string{"a", "aaaa"} {
			for _, v := range anyStrings(e.Attrs[k]) {
				if ip, err := netip.ParseAddr(v); err == nil {
					if ok, _ := s.o.Scope.AllowConnect(e.Key, ip); !ok {
						blocked[e.Key] = true
					}
				}
			}
		}
	}
	var out []string
	dropped := 0
	for _, h := range sortedUnique(hosts) {
		if ok, _ := s.o.Scope.AllowHost(h); !ok || blocked[h] {
			dropped++
			if blocked[h] {
				s.tr.Event("not probing " + h + ": resolves to a special-purpose address outside scope")
			}
			continue
		}
		out = append(out, h)
	}
	return out, dropped, nil
}

func anyStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		var o []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				o = append(o, s)
			}
		}
		return o
	}
	return nil
}

func (s *state) serviceInputs() ([]string, error) {
	ents, err := s.o.DB.RunEntities(s.run.ID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.Kind == model.KindService {
			if ok, _ := s.o.Scope.AllowURL(e.Key); ok {
				out = append(out, e.Key)
			}
		}
	}
	return sortedUnique(out), nil
}

func (s *state) writeInput(stage string, lines []string) (string, error) {
	p := filepath.Join(s.lay.RunDir(s.run.ID), "inputs", stage+".txt")
	return p, os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// ---------------------------------------------------------------- tool stages

type batcher struct {
	s        *state
	stage    string
	buf      []model.Obs
	last     time.Time
	persist  int
	err      error
	newTotal int
}

func (b *batcher) add(o model.Obs) {
	b.buf = append(b.buf, o)
	if len(b.buf) >= 200 || time.Since(b.last) > time.Second {
		b.flush()
	}
}

func (b *batcher) flush() {
	b.last = time.Now()
	if len(b.buf) == 0 || b.err != nil {
		return
	}
	n, err := b.s.o.DB.Persist(b.s.run.ID, b.s.run.TargetID, b.buf)
	if err != nil {
		b.err = err
		return
	}
	b.persist += len(b.buf)
	b.newTotal += n
	if n > 0 {
		b.s.tr.Event(fmt.Sprintf("%s: +%d new %s (e.g. %s)", b.stage, n, b.buf[0].Kind, b.buf[0].Key))
	}
	b.buf = b.buf[:0]
	b.s.refreshCounts()
}

func (s *state) refreshCounts() {
	c, err := s.o.DB.Counts(s.run.ID)
	if err != nil {
		return
	}
	s.tr.With(func(t *model.Tracker) {
		for _, k := range []string{model.KindSubdomain, model.KindDNS, model.KindService, model.KindURL} {
			t.Counts[k] = c[k]
		}
	})
}

func (s *state) inScope(o model.Obs) bool {
	switch o.Kind {
	case model.KindSubdomain, model.KindDNS:
		ok, _ := s.o.Scope.AllowHost(o.Key)
		return ok
	default:
		ok, _ := s.o.Scope.AllowURL(o.Key)
		return ok
	}
}

func (s *state) runTool(ctx context.Context, d StageDef, attempt int) stageResult {
	a, cfg := d.Adapter, s.o.Cfg
	info := s.tools[d.ID]
	if info.Status != adapters.Available {
		msg := fmt.Sprintf("tool %q %s: %s. Install: %s", a.Binary, info.Status, info.Detail, info.Install)
		s.tr.Event(d.ID + ": skipped, tool " + string(info.Status))
		return stageResult{status: model.Skipped, detail: msg}
	}
	in := adapters.Input{Target: s.o.Target, Threads: orDefault(cfg.Conc.PerStage[d.ID], 5), RateLimit: orDefault(cfg.RateLimit[d.ID], 10),
		Depth: cfg.Crawl.Depth, Timeout: 30 * time.Second}
	var res stageResult
	if a.NeedsFile {
		var lines []string
		var err error
		if d.ID == "katana" {
			lines, err = s.serviceInputs()
		} else {
			lines, res.dropped, err = s.hostInputs()
		}
		if err != nil {
			return stageResult{status: model.Failed, detail: "read inputs: " + err.Error()}
		}
		if len(lines) == 0 {
			return stageResult{status: model.Success, detail: "no in-scope inputs available", dropped: res.dropped}
		}
		if len(lines) > cfg.Limits.MaxRecords {
			lines = lines[:cfg.Limits.MaxRecords]
		}
		if in.File, err = s.writeInput(d.ID, lines); err != nil {
			return stageResult{status: model.Failed, detail: "write input: " + err.Error()}
		}
		res.inputs = len(lines)
	} else {
		res.inputs = 1
	}
	raw := filepath.Join(s.lay.RunDir(s.run.ID), "raw", d.ID+".out")
	res.artifact = raw
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	k := newSink(s, d, in, cancel)
	k.dropped = res.dropped
	if d.ID == "katana" {
		in.Has = info.Has
		return s.runCrawl(ctx, cctx, d, info, in, k, res)
	}
	spec := runner.Spec{
		Path: info.Path, Args: a.Args(in), Dir: s.lay.RunDir(s.run.ID), Timeout: cfg.StageTimeout(d.ID), Grace: cfg.Timeouts.Grace,
		MaxRaw: cfg.Limits.MaxOutputBytes, MaxLine: cfg.Limits.MaxLineBytes, RawPath: raw, OnLine: k.onLine,
	}
	s.log.Info("exec", "stage", d.ID, "path", info.Path, "args", logging.Redact(strings.Join(spec.Args, " ")), "attempt", attempt)
	rr := runner.Run(cctx, spec)
	k.finish()
	res.outputs, res.dropped, res.exit = k.b.persist, k.dropped, rr.ExitCode
	s.writeMeta(d.ID, map[string]any{"args": logging.Redact(strings.Join(spec.Args, " ")), "exit_code": rr.ExitCode, "timed_out": rr.TimedOut,
		"raw_truncated": rr.Truncated, "lines": rr.Lines, "long_lines_dropped": rr.LongLines, "bytes": rr.Bytes, "stderr": logging.Redact(rr.Stderr),
		"parsed": k.parsed, "unparseable": k.bad, "filtered": k.filtered, "persisted": k.b.persist})
	if k.b.err != nil {
		res.status, res.detail = model.Failed, "database error: "+k.b.err.Error()
		return res
	}
	note := k.note()
	if rr.Truncated {
		note += "; raw evidence file truncated at max_output_bytes"
	}
	if rr.LongLines > 0 {
		note += fmt.Sprintf("; %d over-long lines dropped", rr.LongLines)
	}
	switch {
	case ctx.Err() != nil:
		res.status, res.detail = model.Cancelled, "cancelled"
	case rr.Err != nil:
		res.status, res.detail = model.Failed, "could not run tool: "+rr.Err.Error()
	case k.limitHit:
		res.status, res.detail = model.Partial, fmt.Sprintf("stopped at max_records_per_stage=%d%s", cfg.Limits.MaxRecords, note)
	case rr.TimedOut:
		res.status = model.Partial
		if res.outputs == 0 {
			res.status = model.Failed
		}
		res.detail = fmt.Sprintf("timed out after %s with %d records%s", cfg.StageTimeout(d.ID), res.outputs, note)
	case rr.ExitCode != 0:
		res.status = model.Failed
		if res.outputs > 0 {
			res.status = model.Partial
		}
		res.retryable = adapters.Transient(rr.Stderr, rr.ExitCode)
		res.detail = fmt.Sprintf("exit code %d: %s%s", rr.ExitCode, strings.TrimSpace(logging.Redact(rr.Stderr)), note)
	case k.bad > 0 && k.parsed == 0:
		res.status, res.detail = model.Failed, fmt.Sprintf("output could not be parsed (%d bad lines, first: %s)", k.bad, k.firstBad)
	case k.bad > 0:
		res.status, res.detail = model.Partial, fmt.Sprintf("%d unparseable lines (first: %s)%s", k.bad, k.firstBad, note)
	case rr.Lines == 0:
		res.status, res.detail = model.Success, "tool produced no output (empty result)"+note
	default:
		res.status, res.detail = model.Success, strings.TrimPrefix(note, "; ")
	}
	return res
}

func orDefault(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

// ---------------------------------------------------------------- javascript stage

func isPolicyRejection(err error) bool {
	m := err.Error()
	for _, w := range []string{"out of scope", "content-type", "oversized", "unsupported", "http status 4", "blocked by scope", "redirect"} {
		if strings.Contains(m, w) {
			return true
		}
	}
	return false
}

func (s *state) runJS(ctx context.Context) stageResult {
	cfg := s.o.Cfg
	ents, err := s.o.DB.RunEntities(s.run.ID)
	if err != nil {
		return stageResult{status: model.Failed, detail: err.Error()}
	}
	var urls []string
	skippedScope := 0
	for _, e := range ents {
		if e.Kind != model.KindURL || !normalize.IsJS(e.Key) {
			continue
		}
		// Only JS on explicitly in-scope hosts is ever retrieved directly.
		if ok, _ := s.o.Scope.AllowURL(e.Key); !ok {
			skippedScope++
			continue
		}
		urls = append(urls, e.Key)
	}
	urls = sortedUnique(urls)
	if len(urls) > cfg.JS.MaxFile {
		s.tr.Event(fmt.Sprintf("js: limiting to first %d of %d JavaScript URLs (javascript.max_files)", cfg.JS.MaxFile, len(urls)))
		urls = urls[:cfg.JS.MaxFile]
	}
	res := stageResult{inputs: len(urls), dropped: skippedScope}
	if len(urls) == 0 {
		res.status, res.detail = model.Success, "no in-scope JavaScript URLs known"
		return res
	}
	f := jsintel.NewFetcher(s.o.Scope, cfg.Limits.JSDownload, cfg.JS.Timeout)
	var okN, errN, rejN int32
	work := make(chan string)
	tick := time.NewTicker(time.Second / time.Duration(cfg.JS.RPS))
	defer tick.Stop()
	var wg sync.WaitGroup
	for i := 0; i < cfg.JS.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range work {
				now := time.Now().UTC()
				fr, err := f.Fetch(ctx, u)
				if err != nil {
					out := "error"
					if isPolicyRejection(err) {
						out = "rejected"
						atomic.AddInt32(&rejN, 1)
					} else {
						atomic.AddInt32(&errN, 1)
					}
					s.o.DB.JSFetchOutcome(s.run.ID, u, out, logging.Redact(err.Error()), now)
					continue
				}
				sha := jsintel.SHA256(fr.Body)
				path, err := jsintel.Store(s.lay.JSFiles, sha, fr.Body)
				if err == nil {
					err = s.o.DB.PutJSContent(s.run.ID, sha, u, fr.ContentType, path, int64(len(fr.Body)), fr.Status, now)
				}
				if err == nil {
					err = s.analyze(sha, fr.Body, now)
				}
				if err != nil {
					atomic.AddInt32(&errN, 1)
					s.o.DB.JSFetchOutcome(s.run.ID, u, "error", logging.Redact(err.Error()), now)
					continue
				}
				atomic.AddInt32(&okN, 1)
				s.o.DB.JSFetchOutcome(s.run.ID, u, "ok", "", now)
			}
		}()
	}
loop:
	for _, u := range urls {
		select {
		case <-ctx.Done():
			break loop
		case <-tick.C:
		}
		select {
		case <-ctx.Done():
			break loop
		case work <- u:
		}
	}
	close(work)
	wg.Wait()
	res.outputs = int(okN)
	detail := fmt.Sprintf("%d fetched, %d rejected by policy, %d errors", okN, rejN, errN)
	switch {
	case ctx.Err() != nil:
		res.status, res.detail = model.Cancelled, "cancelled; "+detail
	case errN > 0 && okN == 0:
		res.status, res.detail = model.Failed, detail
	case errN > 0:
		res.status, res.detail = model.Partial, detail
	default:
		res.status, res.detail = model.Success, detail
	}
	return res
}

func (s *state) analyze(sha string, body []byte, at time.Time) error {
	key := storage.JSKey{SHA: sha, Analyzer: jsintel.AnalyzerName, Version: jsintel.AnalyzerVersion, ConfigHash: jsintel.ConfigHash(), Rules: jsintel.RulesVersion}
	done, err := s.o.DB.Analyzed(key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	first := !s.jsSHA[sha]
	s.jsSHA[sha] = true
	s.mu.Unlock()
	if !done {
		cands := jsintel.Analyze(body)
		if err := s.o.DB.SaveAnalysis(s.run.ID, key, cands, at); err != nil {
			return err
		}
	}
	if first {
		s.mu.Lock()
		n := len(s.jsSHA)
		s.mu.Unlock()
		s.tr.With(func(t *model.Tracker) { t.Counts["js"] = n })
		if cands, err := s.o.DB.RunCandidates(s.run.ID); err == nil {
			s.tr.With(func(t *model.Tracker) { t.Counts["js_candidates"] = len(cands) })
		}
	}
	return nil
}
