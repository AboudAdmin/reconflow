// Package reporting builds JSON/JSONL/text exports and the static HTML
// dashboard exclusively from persisted records.
package reporting

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"reconflow/internal/diff"
	"reconflow/internal/model"
	"reconflow/internal/storage"
)

//go:embed dashboard.html
var dashboardHTML string

const Schema = "reconflow.report/1"

// MaxEmbeddedRows caps each table embedded in the HTML; JSON/JSONL exports are complete.
const MaxEmbeddedRows = 20000

type Input struct {
	DB                *storage.DB
	Run               *storage.Run
	Diff              *diff.Result
	ReportsDir, JSDir string
	JSONL, HTML       bool
	Now               time.Time
	RunDir            string // runs/<id>; enables normalized files, per-run report.json and filter counts
	NormDir           string // <target>/normalized: mirror of the newest run's normalized files
}

type RunInfo struct {
	ID          string  `json:"id"`
	Target      string  `json:"target"`
	Status      string  `json:"status"`
	Version     string  `json:"version"`
	Passive     bool    `json:"passive"`
	Started     string  `json:"started_at"`
	Finished    string  `json:"finished_at"`
	DurationSec float64 `json:"duration_sec"`
	ScopeHash   string  `json:"scope_hash"`
	ConfigHash  string  `json:"config_hash"`
}

type StageInfo struct {
	Stage       string  `json:"stage"`
	Tool        string  `json:"tool"`
	Status      string  `json:"status"`
	Started     string  `json:"started_at"`
	Finished    string  `json:"finished_at"`
	DurationSec float64 `json:"duration_sec"`
	Inputs      int     `json:"inputs"`
	Outputs     int     `json:"outputs"`
	Dropped     int     `json:"dropped"`
	Retries     int     `json:"retries"`
	ExitCode    int     `json:"exit_code"`
	Passive     bool    `json:"passive"`
	Comparable  bool    `json:"comparable"`
	Detail      string  `json:"detail"`
	Artifact    string  `json:"artifact"`
}

type ToolInfo struct {
	Tool    string `json:"tool"`
	Path    string `json:"binary"`
	Version string `json:"version"`
	Status  string `json:"status"`
	Detail  string `json:"detail"`
}

type ErrInfo struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
	At      string `json:"at"`
}

type AssetRow struct {
	Kind     string         `json:"kind"`
	Key      string         `json:"key"`
	State    string         `json:"state"`
	Reason   string         `json:"reason"`
	Sources  []string       `json:"sources"`
	Attrs    map[string]any `json:"attrs"`
	FirstRun string         `json:"first_run"`
}

type URLRow struct {
	URL     string   `json:"url"`
	Origin  string   `json:"origin"` // crawled = observed live this run; historical = archive only
	State   string   `json:"state"`
	Sources []string `json:"sources"`
	Params  []string `json:"params"`
	IsJS    bool     `json:"is_js"`
	Class   string   `json:"class"` // api | js | sourcemap | page (static resources are filtered upstream)
	Score   int      `json:"score"` // attention rank, see internal/triage
}

type JSRow struct {
	SHA256      string   `json:"sha256"`
	ContentType string   `json:"content_type"`
	FirstRun    string   `json:"first_run"`
	URLs        []string `json:"source_urls"`
	Size        int64    `json:"size"`
	Candidates  int      `json:"candidates"`
	State       string   `json:"state"`
}

type CandRow struct {
	Type         string   `json:"type"`
	Value        string   `json:"value"`
	Rule         string   `json:"rule"`
	SHA256       string   `json:"sha256"`
	Analyzer     string   `json:"analyzer_version"`
	Verification string   `json:"verification"`
	State        string   `json:"state"`
	SourceURLs   []string `json:"source_urls"`
	Class        string   `json:"class"` // api | route | inscope | thirdparty | param | weak | static | other
	Score        int      `json:"score"`
}

type ChangeRow struct {
	Subject string `json:"subject"`
	Kind    string `json:"kind"`
	Key     string `json:"key"`
	State   string `json:"state"`
	Reason  string `json:"reason"`
}

type KindCoverage struct {
	Kind        string   `json:"kind"`
	Producers   []string `json:"producers"`
	Comparable  bool     `json:"comparable"`
	Explanation string   `json:"explanation"`
}

type Comparison struct {
	Established bool           `json:"baseline_established"`
	Note        string         `json:"note"`
	Counts      map[string]int `json:"counts"`
}

type Report struct {
	Schema      string                    `json:"schema"`
	GeneratedAt string                    `json:"generated_at"`
	Run         RunInfo                   `json:"run"`
	Baseline    string                    `json:"baseline_run_id"`
	Comparison  Comparison                `json:"comparison"`
	Summary     map[string]int            `json:"summary"`
	Stages      []StageInfo               `json:"stages"`
	Tools       []ToolInfo                `json:"tools"`
	Errors      []ErrInfo                 `json:"errors"`
	Assets      []AssetRow                `json:"assets"`
	URLs        []URLRow                  `json:"urls"`
	JS          []JSRow                   `json:"javascript"`
	JSFetches   []storage.JSFetch         `json:"javascript_fetches"`
	Cands       []CandRow                 `json:"js_candidates"`
	Changes     []ChangeRow               `json:"changes"`
	Coverage    []KindCoverage            `json:"coverage"`
	Artifacts   []string                  `json:"artifacts"`
	Complete    bool                      `json:"complete"` // true only when every planned stage succeeded
	Leads       []FindingRow              `json:"findings"`
	History     []HistoryRow              `json:"history"`
	Filtered    map[string]map[string]int `json:"filtered"` // stage -> what was kept out of the database (still in raw evidence)
	Truncated   map[string]int            `json:"html_truncated"`
	Notes       []string                  `json:"notes"`
}

func iso(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Build assembles the report model from the database.
func Build(in Input) (*Report, error) {
	db, run := in.DB, in.Run
	r := &Report{Schema: Schema, GeneratedAt: iso(in.Now), Summary: map[string]int{}, Truncated: map[string]int{}}
	r.Run = RunInfo{ID: run.ID, Target: run.Target, Status: run.Status, Version: run.Version, Passive: run.Passive,
		Started: iso(run.Started), Finished: iso(run.Finished), ScopeHash: run.ScopeHash, ConfigHash: run.ConfigHash}
	if !run.Finished.IsZero() {
		r.Run.DurationSec = run.Finished.Sub(run.Started).Seconds()
	}
	if run.Status != string(model.Success) {
		r.Notes = append(r.Notes, "This run did not complete successfully ("+run.Status+"); it is NOT used as a future baseline and comparisons carry reduced confidence.")
	}
	states := map[string]storage.Comparison{}
	if in.Diff != nil {
		r.Baseline = in.Diff.BaselineID
		r.Comparison = Comparison{in.Diff.Established, in.Diff.Note, in.Diff.Counts}
		for _, c := range in.Diff.Items {
			states[c.Subject+"\x00"+c.Key] = c
			r.Changes = append(r.Changes, ChangeRow{c.Subject, c.Kind, c.Key, c.State, c.Reason})
		}
	}
	stateOf := func(subject, key string) (string, string) {
		if !r.Comparison.Established {
			return "baseline", ""
		}
		if c, ok := states[subject+"\x00"+key]; ok {
			return c.State, c.Reason
		}
		return diff.Unchanged, ""
	}

	stages, err := db.Stages(run.ID)
	if err != nil {
		return nil, err
	}
	for _, s := range stages {
		si := StageInfo{Stage: s.ID, Tool: s.Tool, Status: s.Status, Started: iso(s.Started), Finished: iso(s.Finished), Inputs: s.Inputs,
			Outputs: s.Outputs, Dropped: s.Dropped, Retries: s.Retries, ExitCode: s.ExitCode, Passive: s.Passive, Comparable: s.Comparable,
			Detail: s.Error, Artifact: filepath.Base(s.Artifact)}
		if !s.Started.IsZero() && !s.Finished.IsZero() {
			si.DurationSec = s.Finished.Sub(s.Started).Seconds()
		}
		r.Stages = append(r.Stages, si)
	}
	tools, err := db.Tools(run.ID)
	if err != nil {
		return nil, err
	}
	for _, t := range tools {
		r.Tools = append(r.Tools, ToolInfo{t.Tool, filepath.Base(t.Path), t.Version, t.Status, t.Detail})
	}
	errs, err := db.Errors(run.ID)
	if err != nil {
		return nil, err
	}
	for _, e := range errs {
		r.Errors = append(r.Errors, ErrInfo{e.Stage, e.Message, e.At})
	}

	ents, err := db.RunEntities(run.ID)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		st, why := stateOf(e.Kind, e.Key)
		if e.Kind == model.KindURL {
			origin := "historical"
			for _, o := range e.Origins {
				if o == "crawled" {
					origin = "crawled"
				}
			}
			u := URLRow{URL: e.Key, Origin: origin, State: st, Sources: e.Sources, Params: paramNames(e.Key)}
			u.IsJS = strings.HasSuffix(strings.ToLower(pathOf(e.Key)), ".js") || strings.HasSuffix(strings.ToLower(pathOf(e.Key)), ".mjs")
			r.URLs = append(r.URLs, u)
			continue
		}
		r.Assets = append(r.Assets, AssetRow{Kind: e.Kind, Key: e.Key, State: st, Reason: why, Sources: e.Sources, Attrs: e.Attrs, FirstRun: e.FirstRun})
	}
	for k, v := range map[string]string{"subdomains": model.KindSubdomain, "dns_observations": model.KindDNS, "live_services": model.KindService} {
		for _, a := range r.Assets {
			if a.Kind == v {
				r.Summary[k]++
			}
		}
	}
	r.Summary["urls"] = len(r.URLs)
	for _, u := range r.URLs {
		if u.Origin == "crawled" {
			r.Summary["urls_crawled_live"]++
		} else {
			r.Summary["urls_historical_only"]++
		}
	}

	js, err := db.RunJS(run.ID)
	if err != nil {
		return nil, err
	}
	cands, err := db.RunCandidates(run.ID)
	if err != nil {
		return nil, err
	}
	bySHA := map[string]*JSRow{}
	srcBySHA := map[string][]string{}
	for _, j := range js {
		srcBySHA[j.SHA] = append(srcBySHA[j.SHA], j.URL)
		if bySHA[j.SHA] == nil {
			st := diff.Unchanged
			if !r.Comparison.Established {
				st = "baseline"
			} else if j.FirstRun == run.ID {
				st = diff.New
			}
			bySHA[j.SHA] = &JSRow{SHA256: j.SHA, ContentType: j.ContentType, Size: j.Size, FirstRun: j.FirstRun, State: st}
		}
	}
	for _, c := range cands {
		if row := bySHA[c.SHA]; row != nil {
			row.Candidates++
		}
	}
	for sha, row := range bySHA {
		row.URLs = srcBySHA[sha]
		sort.Strings(row.URLs)
		r.JS = append(r.JS, *row)
	}
	sort.Slice(r.JS, func(i, j int) bool { return r.JS[i].SHA256 < r.JS[j].SHA256 })
	for _, c := range cands {
		st, _ := stateOf(diff.SubjJSIntel, c.Value)
		urls := srcBySHA[c.SHA]
		r.Cands = append(r.Cands, CandRow{Type: c.Type, Value: c.Value, Rule: c.Rule, SHA256: c.SHA, Analyzer: c.AnalyzerVersion, Verification: c.Verification, State: st, SourceURLs: urls})
	}
	r.Summary["js_contents"], r.Summary["js_candidates"] = len(r.JS), len(r.Cands)
	if r.JSFetches, err = db.RunJSFetches(run.ID); err != nil {
		return nil, err
	}

	// Coverage: which entity kinds can be compared reliably in this run.
	st := map[string]StageInfo{}
	for _, s := range r.Stages {
		st[s.Stage] = s
	}
	for _, kind := range []string{model.KindSubdomain, model.KindDNS, model.KindService, model.KindURL} {
		kc := KindCoverage{Kind: kind, Comparable: true}
		for _, p := range diff.Producers[kind] {
			s, ok := st[p]
			if !ok {
				continue
			}
			kc.Producers = append(kc.Producers, p)
			if s.Status != string(model.Success) {
				kc.Comparable = false
				kc.Explanation += fmt.Sprintf("%s ended %s. ", p, s.Status)
			}
		}
		if len(kc.Producers) == 0 {
			kc.Comparable, kc.Explanation = false, "no stage collecting this kind was part of this run"
		}
		r.Coverage = append(r.Coverage, kc)
	}
	enrich(r, in)
	r.Notes = append(r.Notes,
		"Findings are leads for manual review, derived from names and fingerprints. None is a confirmed vulnerability.",
		"JavaScript candidates come from static regex extraction and are unverified; they are not vulnerabilities.",
		"URLs with origin 'historical' come from web archives and are not evidence of current availability.",
		"'not_seen' means absent from this run; it is not proof of removal. 'confirmed_removed' is never produced.")
	return r, nil
}

func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Path
}

func paramNames(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var n []string
	for k := range u.Query() {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// WriteAtomic writes via a temp file in the same directory and renames it.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("refusing to overwrite non-regular file %s", path)
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func jsonBytes(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return append(b, '\n')
}

func jsonl[T any](rows []T) []byte {
	var b bytes.Buffer
	for _, r := range rows {
		x, _ := json.Marshal(r)
		b.Write(x)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func lines(header string, rows []string) []byte {
	sort.Strings(rows)
	return []byte(header + "\n" + strings.Join(rows, "\n") + func() string {
		if len(rows) > 0 {
			return "\n"
		}
		return ""
	}())
}

// Generate writes every report file and returns their descriptors.
func Generate(in Input) ([]storage.Artifact, error) {
	for _, d := range []string{in.ReportsDir, in.JSDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	r, err := Build(in)
	if err != nil {
		return nil, err
	}
	var arts []storage.Artifact
	put := func(dir, name, kind string, data []byte) error {
		p := filepath.Join(dir, name)
		if err := WriteAtomic(p, data); err != nil {
			return err
		}
		h := sha256.Sum256(data)
		arts = append(arts, storage.Artifact{Name: name, Path: p, SHA256: hex.EncodeToString(h[:]), Kind: kind})
		r.Artifacts = append(r.Artifacts, name)
		return nil
	}
	// text lists (only meaningful with a baseline)
	hdr := func(what string) string {
		if !r.Comparison.Established {
			return "# " + what + ": no valid baseline, this run establishes one; nothing can be classified as new"
		}
		return "# " + what + " (baseline " + r.Baseline + ", run " + r.Run.ID + ")"
	}
	var newA, newE, newJS, chg, gone []string
	for _, c := range r.Changes {
		line := c.Kind + "\t" + c.Key
		isAsset := c.Kind == model.KindSubdomain || c.Kind == model.KindDNS || c.Kind == model.KindService
		switch {
		case c.State == diff.New && isAsset:
			newA = append(newA, line)
		case c.State == diff.New && c.Kind == model.KindURL:
			newE = append(newE, line)
		case (c.State == diff.New || c.State == diff.Changed) && (c.Subject == diff.SubjJS || c.Subject == diff.SubjJSIntel):
			newJS = append(newJS, c.State+"\t"+c.Kind+"\t"+c.Key)
		case c.State == diff.Changed:
			chg = append(chg, line+"\t"+c.Reason)
		case c.State == diff.NotSeen || c.State == diff.PossiblyRemoved || c.State == diff.Unknown:
			gone = append(gone, c.State+"\t"+line+"\t"+c.Reason)
		}
	}
	if r.Comparison.Established {
		for _, f := range []struct {
			n, h string
			rows []string
		}{{"new_assets.txt", "new assets", newA}, {"new_endpoints.txt", "new URLs/endpoints", newE}, {"new_js_intel.txt", "new/changed JavaScript intelligence (unverified candidates)", newJS},
			{"changed_assets.txt", "changed assets", chg}, {"not_seen_assets.txt", "assets not seen (absence is not proof of removal)", gone}} {
			if err := put(in.ReportsDir, f.n, "text", lines(hdr(f.h), f.rows)); err != nil {
				return arts, err
			}
		}
	}
	if err := put(in.ReportsDir, "execution.json", "json", jsonBytes(map[string]any{"schema": Schema + "/execution", "run": r.Run, "stages": r.Stages, "tools": r.Tools, "errors": r.Errors, "js_fetches": r.JSFetches})); err != nil {
		return arts, err
	}
	if err := put(in.ReportsDir, "coverage.json", "json", jsonBytes(map[string]any{"schema": Schema + "/coverage", "run": r.Run.ID, "run_status": r.Run.Status, "stages": r.Stages, "kinds": r.Coverage})); err != nil {
		return arts, err
	}
	if in.JSONL {
		if err := put(in.ReportsDir, "assets.jsonl", "jsonl", jsonl(r.Assets)); err != nil {
			return arts, err
		}
		if err := put(in.ReportsDir, "urls.jsonl", "jsonl", jsonl(r.URLs)); err != nil {
			return arts, err
		}
		var ends, params []CandRow
		for _, c := range r.Cands {
			switch c.Type {
			case model.CandParam:
				params = append(params, c)
			default:
				ends = append(ends, c)
			}
		}
		if err := put(in.JSDir, "inventory.jsonl", "jsonl", jsonl(r.JS)); err != nil {
			return arts, err
		}
		if err := put(in.JSDir, "endpoints.jsonl", "jsonl", jsonl(ends)); err != nil {
			return arts, err
		}
		if err := put(in.JSDir, "parameters.jsonl", "jsonl", jsonl(params)); err != nil {
			return arts, err
		}
	}
	if in.HTML {
		page := BuildHTML(r)
		if err := put(in.ReportsDir, "latest.html", "html", page); err != nil {
			return arts, err
		}
	}
	if in.RunDir != "" {
		files, _ := normalizedFiles(r)
		runNorm := filepath.Join(in.RunDir, "normalized")
		if err := os.MkdirAll(runNorm, 0o700); err != nil {
			return arts, err
		}
		for name, data := range files {
			if err := put(runNorm, name, "normalized", data); err != nil {
				return arts, err
			}
			if in.NormDir != "" { // newest run's copy for scripts that want a stable path
				if err := os.MkdirAll(in.NormDir, 0o700); err != nil {
					return arts, err
				}
				if err := WriteAtomic(filepath.Join(in.NormDir, name), data); err != nil {
					return arts, err
				}
			}
		}
	}
	// latest.json last so it can list every artifact above
	r.Artifacts = append(r.Artifacts, "latest.json")
	full := jsonBytes(r)
	if in.RunDir != "" { // per-run copy: history stays readable after the next run overwrites latest.*
		if err := WriteAtomic(filepath.Join(in.RunDir, "report.json"), full); err != nil {
			return arts, err
		}
	}
	p := filepath.Join(in.ReportsDir, "latest.json")
	if err := WriteAtomic(p, full); err != nil {
		return arts, err
	}
	h := sha256.Sum256(full)
	arts = append(arts, storage.Artifact{Name: "latest.json", Path: p, SHA256: hex.EncodeToString(h[:]), Kind: "json"})
	return arts, nil
}

// BuildHTML embeds capped table data into the static dashboard. All data is
// JSON inside a non-executing <script type="application/json"> block; the
// page renders it with textContent only, so no untrusted string is ever
// interpreted as HTML. json.Marshal escapes <, > and & as < etc., so
// "</script>" cannot appear in the payload.
func BuildHTML(r *Report) []byte {
	c := *r
	capRows := func(name string, n int) int {
		if n > MaxEmbeddedRows {
			c.Truncated[name] = n
			return MaxEmbeddedRows
		}
		return n
	}
	c.Truncated = map[string]int{}
	c.Assets = c.Assets[:capRows("assets", len(c.Assets))]
	c.URLs = c.URLs[:capRows("urls", len(c.URLs))]
	c.JS = c.JS[:capRows("js", len(c.JS))]
	c.Cands = c.Cands[:capRows("candidates", len(c.Cands))]
	c.Changes = c.Changes[:capRows("changes", len(c.Changes))]
	b, _ := json.Marshal(&c)
	return []byte(strings.Replace(dashboardHTML, "/*__DATA__*/null", string(b), 1))
}
