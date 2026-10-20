// Package orchestrator owns the run lifecycle: planning, tool detection,
// dependency-ordered execution, persistence, comparison and reporting.
package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"reconflow/internal/adapters"
	"reconflow/internal/config"
	"reconflow/internal/diff"
	"reconflow/internal/logging"
	"reconflow/internal/model"
	"reconflow/internal/reporting"
	"reconflow/internal/scheduler"
	"reconflow/internal/scope"
	"reconflow/internal/storage"
)

var (
	ErrNothingToResume    = errors.New("no recoverable run found for this target")
	ErrResumeIncompatible = errors.New("the unfinished run used a different scope policy or mode; refusing to resume")
)

type Options struct {
	Target  string
	Passive bool
	Resume  bool
	Cfg     *config.Config
	Scope   *scope.Policy
	DB      *storage.DB
	Tracker *model.Tracker // optional; a private one is used when nil
	Version string
	Log     *slog.Logger // optional
	// OnPlan is called once the run is created and the stage plan is known, before execution.
	OnPlan func(runID string, t *model.Tracker)
}

type Result struct {
	Run       *storage.Run
	Status    model.Status
	Stages    []storage.Stage
	Diff      *diff.Result
	Layout    Layout
	Reports   []storage.Artifact
	Resumed   []string // stages accepted as already complete
	Tools     []adapters.Info
	NoTools   bool // every tool-backed stage was unavailable
	ReportErr error
}

type StageDef struct {
	ID, Title  string
	Adapter    *adapters.Adapter // nil for the built-in js stage
	Hard, Soft []string
}

var catalog = []StageDef{
	{ID: "subfinder", Title: "Subdomain discovery"},
	{ID: "dnsx", Title: "DNS resolution", Soft: []string{"subfinder"}},
	{ID: "httpx", Title: "HTTP probing", Soft: []string{"subfinder", "dnsx"}},
	{ID: "gau", Title: "Historical URLs (gau)"},
	{ID: "waybackurls", Title: "Historical URLs (wayback)"},
	{ID: "katana", Title: "Crawling", Hard: []string{"httpx"}},
	{ID: "js", Title: "JavaScript analysis", Soft: []string{"httpx", "katana", "gau", "waybackurls"}},
}

// ValidatePassivePolicy rejects a passive_stages list naming a stage that
// would contact the target.
func ValidatePassivePolicy(cfg *config.Config) error {
	for _, p := range cfg.Passive {
		a := adapters.Get(p)
		if a == nil || !a.Passive {
			return fmt.Errorf("passive_stages lists %q, which is not a passive-capable stage", p)
		}
	}
	return nil
}

// Plan returns the stages that will run. Disabled stages and (in passive mode)
// every stage not in passive_stages are absent from the plan entirely.
func Plan(cfg *config.Config, passive bool, target string) []StageDef {
	_, ipErr := netip.ParseAddr(target) // ipErr == nil means the target is an IP literal
	var out []StageDef
	have := map[string]bool{}
	for _, d := range catalog {
		d.Adapter = adapters.Get(d.ID)
		on := cfg.StageEnabled(d.ID, true)
		if d.ID == "js" {
			on = on && cfg.JS.Enabled
		}
		if passive && (d.Adapter == nil || !d.Adapter.Passive || !cfg.IsPassive(d.ID)) {
			on = false
		}
		if d.Adapter != nil && d.Adapter.Passive && ipErr == nil {
			on = false // domain-only sources make no sense for an IP target
		}
		if on {
			have[d.ID] = true
			out = append(out, d)
		}
	}
	// drop dependency edges to stages that are not planned
	for i := range out {
		keep := func(in []string) (r []string) {
			for _, x := range in {
				if have[x] {
					r = append(r, x)
				}
			}
			return
		}
		out[i].Hard, out[i].Soft = keep(out[i].Hard), keep(out[i].Soft)
	}
	return out
}

type state struct {
	o       Options
	run     *storage.Run
	lay     Layout
	log     *slog.Logger
	tr      *model.Tracker
	tools   map[string]adapters.Info
	mu      sync.Mutex
	jsSHA   map[string]bool
	jsCands int
}

func fileSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func scopeRules(p *scope.Policy) (out [][3]string) {
	add := func(action, typ string, vs []string) {
		for _, v := range vs {
			out = append(out, [3]string{action, typ, v})
		}
	}
	add("include", "domain", p.Include.Domains)
	add("include", "host", p.Include.Hosts)
	add("include", "ip", p.Include.IPs)
	add("include", "cidr", p.Include.CIDRs)
	add("exclude", "domain", p.Exclude.Domains)
	add("exclude", "host", p.Exclude.Hosts)
	add("exclude", "ip", p.Exclude.IPs)
	add("exclude", "cidr", p.Exclude.CIDRs)
	return
}

func configHash(c *config.Config) string {
	b, _ := json.Marshal(struct {
		C config.Config
	}{*c})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// Run executes (or resumes) one run to completion or cancellation. It never
// performs network activity before the scope policy and plan are validated.
func Run(ctx context.Context, o Options) (*Result, error) {
	cfg := o.Cfg
	if err := ValidatePassivePolicy(cfg); err != nil {
		return nil, err
	}
	lay, err := NewLayout(cfg.DataDir, o.Target)
	if err != nil {
		return nil, err
	}
	release, err := acquire(filepath.Join(lay.Target, ".lock"))
	if err != nil {
		return nil, err
	}
	defer release()

	tid, err := o.DB.EnsureTarget(o.Target)
	if err != nil {
		return nil, err
	}
	plan := Plan(cfg, o.Passive, o.Target)
	if len(plan) == 0 {
		return nil, errors.New("no stages are enabled for this mode; check enabled_stages/disabled_stages/passive_stages")
	}
	var run *storage.Run
	resuming := false
	if o.Resume {
		run, err = o.DB.LatestUnfinished(tid)
		if err != nil {
			return nil, err
		}
		if run == nil {
			return nil, ErrNothingToResume
		}
		if run.ScopeHash != o.Scope.Hash() || run.Passive != o.Passive {
			return nil, fmt.Errorf("%w (run %s)", ErrResumeIncompatible, run.ID)
		}
		resuming = true
		if err := o.DB.SetRunStatus(run.ID, "running", time.Time{}); err != nil {
			return nil, err
		}
		run.Status = "running"
	} else {
		ids := make([]string, len(plan))
		for i, d := range plan {
			ids[i] = d.ID
		}
		run = &storage.Run{ID: storage.NewRunID(), TargetID: tid, Target: o.Target, Status: "running", Passive: o.Passive,
			ScopeHash: o.Scope.Hash(), ConfigHash: configHash(cfg), Started: time.Now().UTC(), OutDir: lay.RunDir(""), Version: o.Version, Plan: ids}
		run.OutDir = lay.RunDir(run.ID)
		if err := o.DB.CreateRun(*run, scopeRules(o.Scope)); err != nil {
			return nil, err
		}
	}
	runDir := lay.RunDir(run.ID)
	for _, d := range []string{runDir, filepath.Join(runDir, "raw"), filepath.Join(runDir, "inputs")} {
		if err := EnsureDir(d); err != nil {
			return nil, err
		}
	}
	base, err := o.DB.Baseline(tid, run.ScopeHash, run.Passive, run.Started, run.ID)
	if err != nil {
		return nil, err
	}
	note := ""
	if base != nil {
		run.BaselineID = base.ID
	} else {
		note = "no valid baseline: this run establishes one"
	}
	o.DB.SetBaseline(run.ID, run.BaselineID, note)

	logf, _ := os.OpenFile(filepath.Join(lay.Logs, run.ID+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	var lw io.Writer = io.Discard
	if logf != nil {
		defer logf.Close()
		lw = logf
	}
	log := logging.New(lw, cfg.Logging.Level).With("run", run.ID, "target", o.Target)
	if o.Log != nil {
		log = o.Log.With("run", run.ID)
	}

	stageStates := make([]*model.StageState, len(plan))
	for i, d := range plan {
		stageStates[i] = &model.StageState{ID: d.ID, Title: d.Title, Status: model.Queued, Passive: d.Adapter != nil && d.Adapter.Passive}
		if d.Adapter != nil {
			stageStates[i].Tool = d.Adapter.Binary
		}
	}
	tr := o.Tracker
	if tr == nil {
		tr = model.NewTracker(o.Target, run.ID, stageStates)
	} else {
		tr.With(func(t *model.Tracker) {
			t.Target, t.RunID, t.Stages, t.Started = o.Target, run.ID, stageStates, time.Now()
		})
	}
	if o.Passive {
		tr.With(func(t *model.Tracker) { t.Note = "PASSIVE MODE: no requests are sent to the target" })
	}
	if o.Scope.Implicit {
		tr.Event("scope: implicit (target + subdomains, ports 80/443); use --scope for explicit rules")
	}
	if base == nil {
		tr.Event("no valid baseline; this run will establish one")
	} else {
		tr.Event("comparing against baseline " + base.ID)
	}
	if o.OnPlan != nil {
		o.OnPlan(run.ID, tr)
	}
	st := &state{o: o, run: run, lay: lay, log: log, tr: tr, tools: map[string]adapters.Info{}, jsSHA: map[string]bool{}}
	log.Info("run start", "resume", resuming, "passive", o.Passive, "stages", len(plan))

	// Tool detection (cheap, local-only executions of `-h` / `-version`).
	res := &Result{Run: run, Layout: lay}
	var wg sync.WaitGroup
	var dmu sync.Mutex
	for _, d := range plan {
		if d.Adapter == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := d.Adapter.Detect(ctx, cfg.Tools[d.ID].Path)
			dmu.Lock()
			st.tools[d.ID] = info
			dmu.Unlock()
			o.DB.SaveTool(run.ID, storage.ToolVersion{Tool: d.ID, Path: info.Path, Version: info.Version, Status: string(info.Status), Detail: info.Detail})
		}()
	}
	wg.Wait()
	available := 0
	for _, d := range plan {
		if d.Adapter != nil {
			res.Tools = append(res.Tools, st.tools[d.ID])
			if st.tools[d.ID].Status == adapters.Available {
				available++
			}
		}
	}
	toolStages := 0
	for _, d := range plan {
		if d.Adapter != nil {
			toolStages++
		}
	}
	res.NoTools = toolStages > 0 && available == 0

	// Resume: accept stages whose stored result and artifact still verify.
	done := map[string]storage.Stage{}
	if resuming {
		rows, _ := o.DB.Stages(run.ID)
		cps, _ := o.DB.Checkpoints(run.ID)
		for _, s := range rows {
			if ok, why := st.checkpointValid(s, cps[s.ID]); ok {
				done[s.ID] = s
				res.Resumed = append(res.Resumed, s.ID)
				tr.Stage(s.ID, func(ss *model.StageState) {
					ss.Status, ss.Output, ss.Detail = model.Success, s.Outputs, "resumed: already complete"
				})
			} else if s.Status != "" && s.Status != string(model.Queued) {
				log.Info("stage will be re-run", "stage", s.ID, "reason", why)
			}
		}
		tr.Event(fmt.Sprintf("resuming run %s: %d/%d stages already complete", run.ID, len(done), len(plan)))
	}

	tasks := make([]scheduler.Task, 0, len(plan))
	for _, d := range plan {
		d := d
		t := scheduler.Task{ID: d.ID, Hard: d.Hard, Soft: d.Soft}
		if prev, ok := done[d.ID]; ok {
			t.Run = func(context.Context, int) scheduler.Outcome {
				return scheduler.Outcome{Status: model.Status(prev.Status)}
			}
		} else {
			t.Run = func(c context.Context, attempt int) scheduler.Outcome { return st.runStage(c, d, attempt) }
		}
		tasks = append(tasks, t)
	}
	hooks := scheduler.Hooks{
		OnStart: func(id string) {
			if _, ok := done[id]; ok {
				return
			}
			tr.Stage(id, func(s *model.StageState) { s.Status, s.Started = model.Running, time.Now() })
			st.recordStage(id, model.Running, nil)
		},
		OnRetry: func(id string, attempt int, delay time.Duration, err error) {
			o.DB.AddRetry(run.ID, id, attempt, logging.Redact(err.Error()), delay)
			tr.Stage(id, func(s *model.StageState) { s.Retries++ })
			tr.Event(fmt.Sprintf("%s: transient failure, retry %d in %s", id, attempt, delay.Round(time.Millisecond)))
			log.Warn("retry", "stage", id, "attempt", attempt, "delay", delay, "err", err.Error())
		},
		OnSkip: func(id, reason string) {
			tr.Stage(id, func(s *model.StageState) { s.Status, s.Detail = model.Skipped, reason })
			st.recordStage(id, model.Skipped, errors.New(reason))
		},
	}
	outcomes, err := scheduler.Run(ctx, tasks, scheduler.Options{MaxParallel: cfg.Conc.Global, MaxRetries: cfg.Retry.Max,
		BackoffBase: cfg.Retry.BackoffBase, BackoffMax: cfg.Retry.BackoffMax}, hooks)
	if err != nil {
		return nil, err
	}

	// ---- finalize with a fresh context so cancellation still persists state ----
	fin := time.Now().UTC()
	cancelled := ctx.Err() != nil
	allOK, anyOK := true, false
	for _, ss := range tr.Snapshot().Stages { // never started, or killed mid-flight without a final row
		if ss.Status == model.Queued || ss.Status == model.Running {
			st.recordStage(ss.ID, model.Cancelled, errors.New("run interrupted before this stage finished"))
			tr.Stage(ss.ID, func(s *model.StageState) { s.Status, s.Detail = model.Cancelled, "run interrupted" })
		}
	}
	for _, d := range plan {
		oc := outcomes[d.ID]
		if oc.Status != model.Success {
			allOK = false
		} else {
			anyOK = true
		}
	}
	status := model.Success
	switch {
	case cancelled:
		status = model.Cancelled
	case !allOK && anyOK:
		status = model.Partial
	case !allOK:
		status = model.Failed
	}
	o.DB.SetRunStatus(run.ID, string(status), fin)
	run.Status, run.Finished = string(status), fin
	res.Status = status

	// Comparison. A non-success run is still compared, but the diff marks reduced confidence.
	d, derr := diff.Compute(o.DB, run, base)
	if derr != nil {
		log.Error("diff failed", "err", derr.Error())
		o.DB.AddError(run.ID, "diff", derr.Error())
	} else {
		res.Diff = d
		o.DB.SaveComparisons(run.ID, d.BaselineID, d.Items)
		tr.With(func(t *model.Tracker) {
			t.Counts["new"], t.Counts["changed"] = countState(d, diff.New), countState(d, diff.Changed)
		})
	}
	res.Stages, _ = o.DB.Stages(run.ID)
	arts, rerr := reporting.Generate(reporting.Input{DB: o.DB, Run: run, Diff: res.Diff, ReportsDir: lay.Reports, JSDir: lay.JS,
		JSONL: cfg.Reports.JSONL, HTML: cfg.Reports.HTML, Now: time.Now().UTC()})
	res.Reports, res.ReportErr = arts, rerr
	for _, a := range arts {
		o.DB.AddArtifact(run.ID, a)
	}
	if rerr != nil {
		o.DB.AddError(run.ID, "report", rerr.Error())
		tr.AddError("report generation: " + rerr.Error())
	}
	tr.With(func(t *model.Tracker) {
		for _, a := range arts {
			if a.Name == "latest.html" || a.Name == "latest.json" {
				t.Reports = append(t.Reports, a.Path)
			}
		}
	})
	log.Info("run finished", "status", status)
	return res, nil
}

func countState(d *diff.Result, state string) (n int) {
	for k, v := range d.Counts {
		if strings.HasSuffix(k, "/"+state) && !strings.HasPrefix(k, diff.SubjJSIntel) {
			n += v
		}
	}
	return
}

func (s *state) checkpointValid(row storage.Stage, cp storage.Checkpoint) (bool, string) {
	if row.Status != string(model.Success) || cp.State != "done" {
		return false, "stage not complete"
	}
	if cp.ArtifactSHA != "" {
		got, err := fileSHA(row.Artifact)
		if err != nil {
			return false, "artifact missing: " + err.Error()
		}
		if got != cp.ArtifactSHA {
			return false, "artifact hash mismatch (modified or corrupted)"
		}
	}
	if row.ID == "js" {
		files, err := s.o.DB.RunJS(s.run.ID)
		if err != nil {
			return false, err.Error()
		}
		for _, f := range files {
			if _, err := os.Stat(f.Path); err != nil {
				return false, "javascript content file missing"
			}
		}
	}
	return true, ""
}

// recordStage persists a non-final stage row (running/skipped/cancelled).
func (s *state) recordStage(id string, status model.Status, err error) {
	row := storage.Stage{Run: s.run.ID, ID: id, Tool: id, Status: string(status), Passive: s.o.Cfg.IsPassive(id)}
	if a := adapters.Get(id); a != nil {
		row.Tool = a.Binary
	}
	if info, ok := s.tools[id]; ok && info.Version != "" {
		row.Tool = row.Tool + " " + info.Version
	}
	if status == model.Running {
		row.Started = time.Now().UTC()
	} else {
		row.Finished = time.Now().UTC()
	}
	if err != nil {
		row.Error = logging.Redact(err.Error())
	}
	if e := s.o.DB.UpsertStage(row); e != nil {
		s.log.Error("persist stage", "stage", id, "err", e.Error())
	}
}

func sortedUnique(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range in {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
