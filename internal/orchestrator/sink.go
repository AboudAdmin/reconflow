package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"reconflow/internal/adapters"
	"reconflow/internal/logging"
	"reconflow/internal/model"
	"reconflow/internal/reporting"
	"reconflow/internal/runner"
	"reconflow/internal/triage"
)

// sink turns tool output lines into persisted observations. It is shared by
// every process of a stage (katana runs one per host), so all state is locked.
// URLs are triaged here, before they count against max_records_per_stage:
// static resources and parameter/ID variants beyond max_urls_per_shape are
// counted but not persisted. They are never lost: the raw evidence file keeps
// every line the tool printed.
type sink struct {
	s        *state
	d        StageDef
	in       adapters.Input
	cancel   context.CancelFunc
	mu       sync.Mutex
	b        *batcher
	bad      int
	parsed   int
	dropped  int
	firstBad string
	limitHit bool
	seen     map[string]bool
	shapes   map[string]int
	filtered map[string]int
}

func newSink(s *state, d StageDef, in adapters.Input, cancel context.CancelFunc) *sink {
	return &sink{s: s, d: d, in: in, cancel: cancel, b: &batcher{s: s, stage: d.ID, last: time.Now()},
		seen: map[string]bool{}, shapes: map[string]int{}, filtered: map[string]int{}}
}

func (k *sink) onLine(line []byte) {
	obs, err := k.d.Adapter.Parse(line, k.in)
	k.mu.Lock()
	defer k.mu.Unlock()
	if err != nil {
		k.bad++
		if k.firstBad == "" {
			k.firstBad = err.Error()
		}
		return
	}
	cfg := k.s.o.Cfg
	for _, o := range obs {
		k.parsed++
		if !k.s.inScope(o) {
			k.dropped++
			continue
		}
		if o.Kind == model.KindURL {
			if k.seen[o.Key] {
				k.filtered["duplicate"]++
				continue
			}
			k.seen[o.Key] = true
			if triage.Classify(o.Key) == triage.Static {
				k.filtered["static"]++
				continue
			}
			sh := triage.Shape(o.Key)
			if k.shapes[sh] >= cfg.Limits.MaxPerShape {
				k.filtered["collapsed"]++
				continue
			}
			k.shapes[sh]++
		}
		if k.b.persist+len(k.b.buf) >= cfg.Limits.MaxRecords {
			k.limitHit = true
			k.cancel()
			return
		}
		o.Tool, o.ObservedAt = k.d.ID, time.Now().UTC()
		if o.Input == "" {
			o.Input = k.s.o.Target
		}
		k.b.add(o)
	}
}

func (k *sink) finish() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.b.flush()
}

// note describes everything that was not persisted, so a smaller count is never a mystery.
func (k *sink) note() string {
	var p []string
	if k.dropped > 0 {
		p = append(p, fmt.Sprintf("%d out-of-scope/ineligible dropped", k.dropped))
	}
	for _, c := range [][2]string{{"static", "static resources filtered"}, {"collapsed", "parameter/ID variants collapsed"}, {"duplicate", "duplicates merged"}} {
		if n := k.filtered[c[0]]; n > 0 {
			p = append(p, fmt.Sprintf("%d %s", n, c[1]))
		}
	}
	if len(p) == 0 {
		return ""
	}
	return "; " + strings.Join(p, ", ") + " (all kept in raw evidence)"
}

// writeMeta stores run facts next to the raw output: exit status, stderr, filter counts.
func (s *state) writeMeta(stage string, v map[string]any) {
	v["stage"] = stage
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := reporting.WriteAtomic(filepath.Join(s.lay.RunDir(s.run.ID), "raw", stage+".meta.json"), append(b, '\n')); err != nil {
		s.log.Warn("write stage meta", "stage", stage, "err", err.Error())
	}
}

type seedResult struct {
	Seed     string  `json:"seed"`
	Status   string  `json:"status"` // done | budget | failed | not_started
	URLs     int     `json:"urls"`
	Seconds  float64 `json:"seconds"`
	ExitCode int     `json:"exit_code"`
	Note     string  `json:"note,omitempty"`
}

// runCrawl crawls each live host in its own katana process with its own time
// budget. A single shared process meant one slow host consumed the whole stage
// timeout and every later host went uncrawled without any record of it.
func (s *state) runCrawl(ctx, cctx context.Context, d StageDef, info adapters.Info, in adapters.Input, k *sink, res stageResult) stageResult {
	cfg := s.o.Cfg
	a := d.Adapter
	seeds, err := s.serviceInputs()
	if err != nil || len(seeds) == 0 {
		res.status, res.detail = model.Success, "no in-scope inputs available"
		return res
	}
	if len(seeds) > cfg.Limits.MaxRecords {
		seeds = seeds[:cfg.Limits.MaxRecords]
	}
	par := cfg.Crawl.Parallel
	if par > len(seeds) {
		par = len(seeds)
	}
	stageTO := cfg.StageTimeout(d.ID)
	budget := cfg.Crawl.HostBudget
	if fit := time.Duration(float64(stageTO) * 0.9 * float64(par) / float64(len(seeds))); fit < budget {
		budget = fit
		if budget < 20*time.Second {
			budget = 20 * time.Second
		}
		s.tr.Event(fmt.Sprintf("katana: %d hosts do not fit the stage timeout at %s each; budget lowered to %s per host", len(seeds), cfg.Crawl.HostBudget, budget.Round(time.Second)))
	}
	in.Budget, in.File = budget, ""
	in.RateLimit = max(1, in.RateLimit/par) // keep the overall request rate, split across processes
	hard := budget
	if in.Has["-ct"] {
		hard = budget + 20*time.Second // the tool stops itself at the budget; this only guards a hang
	}
	// A retry starts from an empty evidence file; seeds append to it.
	if err := reporting.WriteAtomic(res.artifact, nil); err != nil {
		res.status, res.detail = model.Failed, "reset raw evidence: "+err.Error()
		return res
	}
	res.inputs = len(seeds)
	results := make([]seedResult, len(seeds))
	for i := range results {
		results[i] = seedResult{Seed: seeds[i], Status: "not_started"}
	}
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	var tmu sync.Mutex
	var stderrs []string
	sctx, scancel := context.WithTimeout(cctx, stageTO)
	defer scancel()
	for i, seed := range seeds {
		select {
		case <-sctx.Done():
		case sem <- struct{}{}:
			wg.Add(1)
			go func() {
				defer func() { <-sem; wg.Done() }()
				one := in
				one.Seed = seed
				start := time.Now()
				var urls int
				spec := runner.Spec{Path: info.Path, Args: a.Args(one), Dir: s.lay.RunDir(s.run.ID), Timeout: hard, Grace: cfg.Timeouts.Grace,
					MaxRaw: cfg.Limits.MaxOutputBytes, MaxLine: cfg.Limits.MaxLineBytes, RawPath: res.artifact, RawAppend: true,
					OnLine: func(l []byte) { urls++; k.onLine(l) }}
				s.log.Info("exec", "stage", d.ID, "seed", seed, "args", logging.Redact(strings.Join(spec.Args, " ")))
				rr := runner.Run(sctx, spec)
				sr := seedResult{Seed: seed, URLs: urls, Seconds: time.Since(start).Seconds(), ExitCode: rr.ExitCode}
				switch {
				case rr.Err != nil:
					sr.Status, sr.Note = "failed", "could not run tool: "+rr.Err.Error()
				case rr.TimedOut || (in.Has["-ct"] && rr.ExitCode == 0 && time.Since(start) >= budget-time.Second):
					sr.Status, sr.Note = "budget", fmt.Sprintf("crawl budget %s reached; coverage of this host is incomplete", budget.Round(time.Second))
				case sctx.Err() != nil:
					sr.Status, sr.Note = "budget", "interrupted by the stage timeout or cancellation"
				case rr.ExitCode != 0:
					sr.Status, sr.Note = "failed", fmt.Sprintf("exit %d: %s", rr.ExitCode, strings.TrimSpace(logging.Redact(rr.Stderr)))
					tmu.Lock()
					stderrs = append(stderrs, rr.Stderr)
					tmu.Unlock()
				default:
					sr.Status = "done"
				}
				if rr.Truncated {
					sr.Note += " raw evidence truncated at max_output_bytes;"
				}
				results[i] = sr
			}()
			continue
		}
		break
	}
	wg.Wait()
	k.finish()
	counts := map[string]int{}
	var bad []string
	for _, r := range results {
		counts[r.Status]++
		if r.Status != "done" && len(bad) < 5 {
			bad = append(bad, r.Seed+" ("+r.Status+")")
		}
	}
	res.outputs, res.dropped = k.b.persist, k.dropped
	s.writeMeta(d.ID, map[string]any{"per_host_budget_sec": budget.Seconds(), "parallel": par, "seeds": results, "parsed": k.parsed,
		"unparseable": k.bad, "filtered": k.filtered, "persisted": k.b.persist})
	covered := counts["done"]
	summary := fmt.Sprintf("%d/%d hosts crawled fully", covered, len(seeds))
	if n := counts["budget"]; n > 0 {
		summary += fmt.Sprintf(", %d hit the %s budget", n, budget.Round(time.Second))
	}
	if n := counts["failed"]; n > 0 {
		summary += fmt.Sprintf(", %d failed", n)
	}
	if n := counts["not_started"]; n > 0 {
		summary += fmt.Sprintf(", %d never started (stage timeout %s)", n, stageTO)
	}
	if len(bad) > 0 {
		summary += ": " + strings.Join(bad, ", ")
	}
	summary += k.note() + ". Per-host detail: raw/katana.meta.json"
	switch {
	case k.b.err != nil:
		res.status, res.detail = model.Failed, "database error: "+k.b.err.Error()
	case ctx.Err() != nil:
		res.status, res.detail = model.Cancelled, "cancelled; "+summary
	case k.limitHit:
		res.status, res.detail = model.Partial, fmt.Sprintf("stopped at max_records_per_stage=%d; %s", cfg.Limits.MaxRecords, summary)
	case covered == len(seeds):
		res.status, res.detail = model.Success, summary
	case res.outputs == 0 && counts["budget"] == 0:
		res.status, res.detail = model.Failed, summary
		res.retryable = adapters.Transient(strings.Join(stderrs, " "), 1)
	default:
		res.status, res.detail = model.Partial, summary
	}
	return res
}
