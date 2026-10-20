package reporting

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"reconflow/internal/diff"
	"reconflow/internal/model"
	"reconflow/internal/triage"
)

// FindingRow is a lead (never a confirmed vulnerability) plus its change state.
type FindingRow struct {
	triage.Lead
	State string `json:"state"`
	Score int    `json:"score"`
}

type HistoryRow struct {
	ID       string         `json:"id"`
	Status   string         `json:"status"`
	Passive  bool           `json:"passive"`
	Started  string         `json:"started_at"`
	Finished string         `json:"finished_at"`
	Counts   map[string]int `json:"counts"`
	Problems int            `json:"problem_stages"` // stages that did not end in success
	Baseline string         `json:"baseline_run_id"`
}

var prio = map[string]int{"high": 0, "medium": 1, "low": 2}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func strList(v any) []string {
	var out []string
	if a, ok := v.([]any); ok {
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// enrich adds triage (class, score, leads), history and filter counts to the report.
func enrich(r *Report, in Input) {
	r.Complete = r.Run.Status == string(model.Success)
	sort.SliceStable(r.URLs, func(i, j int) bool {
		if r.URLs[i].Score != r.URLs[j].Score {
			return r.URLs[i].Score > r.URLs[j].Score
		}
		return r.URLs[i].URL < r.URLs[j].URL
	})
	seen := map[string]bool{}
	add := func(l triage.Lead, state string, score int) {
		k := l.Type + "|" + l.Rule + "|" + triage.Shape(l.Subject)
		if l.Type == "parameter" { // one lead per host+parameter, not one per page that carries it
			k = l.Type + "|" + l.Title + "|" + hostOf(l.Subject)
		}
		if seen[k] {
			return
		}
		seen[k] = true
		r.Leads = append(r.Leads, FindingRow{Lead: l, State: state, Score: score})
	}
	for i := range r.URLs {
		u := &r.URLs[i]
		c := triage.Classify(u.URL)
		u.Class = string(c)
		u.Score = triage.Score(u.URL, c, u.Origin == "crawled")
	}
	sort.SliceStable(r.URLs, func(i, j int) bool {
		if r.URLs[i].Score != r.URLs[j].Score {
			return r.URLs[i].Score > r.URLs[j].Score
		}
		return r.URLs[i].URL < r.URLs[j].URL
	})
	for _, u := range r.URLs {
		for _, l := range triage.URLLeads(u.URL, u.Origin == "crawled") {
			add(l, u.State, u.Score)
		}
	}
	for _, a := range r.Assets {
		if a.Kind == model.KindService {
			for _, l := range triage.ServiceLeads(a.Key, str(a.Attrs, "title"), strList(a.Attrs["tech"])) {
				add(l, a.State, 50)
			}
		}
	}
	for i := range r.Cands {
		c := &r.Cands[i]
		c.Class, c.Score = triage.CandidateClass(c.Type, c.Value, c.Rule, r.Run.Target)
		src := "JavaScript " + strings.Join(c.SourceURLs, ", ")
		switch {
		case c.Class == "api":
			add(triage.Lead{Type: "js-endpoint", Priority: "medium", Title: "API path referenced in JavaScript", Subject: c.Value, Evidence: src + " (static match, unverified)", Rule: c.Rule}, c.State, c.Score)
		case c.Type == model.CandSourceMap:
			add(triage.Lead{Type: "sourcemap", Priority: "medium", Title: "Source map referenced", Subject: c.Value, Evidence: src, Rule: c.Rule}, c.State, 30)
		}
	}
	sort.SliceStable(r.Cands, func(i, j int) bool { return r.Cands[i].Score > r.Cands[j].Score })
	sort.SliceStable(r.Leads, func(i, j int) bool {
		a, b := r.Leads[i], r.Leads[j]
		if prio[a.Priority] != prio[b.Priority] {
			return prio[a.Priority] < prio[b.Priority]
		}
		if (a.State == diff.New) != (b.State == diff.New) {
			return a.State == diff.New
		}
		return a.Score > b.Score
	})
	for _, l := range r.Leads {
		r.Summary["leads_"+l.Priority]++
	}
	for _, u := range r.URLs {
		r.Summary["urls_"+u.Class]++
	}

	if runs, err := in.DB.RecentRuns(in.Run.TargetID, 30); err == nil {
		for _, h := range runs {
			row := HistoryRow{ID: h.ID, Status: h.Status, Passive: h.Passive, Started: iso(h.Started), Finished: iso(h.Finished), Baseline: h.BaselineID}
			row.Counts, _ = in.DB.Counts(h.ID)
			if sts, err := in.DB.Stages(h.ID); err == nil {
				for _, s := range sts {
					if s.Status != string(model.Success) {
						row.Problems++
					}
				}
			}
			r.History = append(r.History, row)
		}
	}
	r.Filtered = map[string]map[string]int{}
	if in.RunDir != "" {
		metas, _ := filepath.Glob(filepath.Join(in.RunDir, "raw", "*.meta.json"))
		for _, m := range metas {
			var v struct {
				Stage    string         `json:"stage"`
				Filtered map[string]int `json:"filtered"`
			}
			if b, err := os.ReadFile(m); err == nil && json.Unmarshal(b, &v) == nil && len(v.Filtered) > 0 {
				r.Filtered[v.Stage] = v.Filtered
			}
		}
	}
}

type fileInfo struct {
	Name   string `json:"name"`
	Lines  int    `json:"lines"`
	SHA256 string `json:"sha256"`
}

// normalizedFiles renders the clean, deduplicated lists. Raw tool output stays in runs/<id>/raw.
func normalizedFiles(r *Report) (map[string][]byte, []fileInfo) {
	files := map[string][]byte{}
	list := func(name string, rows []string) {
		sort.Strings(rows)
		files[name] = []byte(strings.Join(uniq(rows), "\n") + "\n")
		if len(rows) == 0 {
			files[name] = nil
		}
	}
	var subs, live, js []string
	var liveRows []map[string]any
	for _, a := range r.Assets {
		switch a.Kind {
		case model.KindSubdomain:
			subs = append(subs, a.Key)
		case model.KindService:
			live = append(live, a.Key)
			liveRows = append(liveRows, map[string]any{"url": a.Key, "status_code": a.Attrs["status_code"], "title": a.Attrs["title"],
				"webserver": a.Attrs["webserver"], "tech": a.Attrs["tech"], "state": a.State})
		}
	}
	var urls, prio40 []string
	type apiRow struct {
		Value    string `json:"value"`
		Source   string `json:"source"` // url | javascript
		Score    int    `json:"score"`
		State    string `json:"state"`
		Verified bool   `json:"verified"`
	}
	var apis []apiRow
	apiSeen := map[string]bool{}
	for _, u := range r.URLs {
		urls = append(urls, u.URL)
		if u.IsJS {
			js = append(js, u.URL)
		}
		if u.Score >= 40 {
			prio40 = append(prio40, fmt.Sprintf("%04d\t%s", 9999-u.Score, u.URL)) // sorts best-first; rewritten below
		}
		if u.Class == string(triage.API) && !apiSeen[u.URL] {
			apiSeen[u.URL] = true
			apis = append(apis, apiRow{u.URL, "url", u.Score, u.State, false})
		}
	}
	for _, c := range r.Cands {
		if (c.Class == "api" || (c.Class == "inscope" && triage.Classify(c.Value) == triage.API)) && !apiSeen[c.Value] {
			apiSeen[c.Value] = true
			apis = append(apis, apiRow{c.Value, "javascript", c.Score, c.State, false})
		}
	}
	sort.SliceStable(apis, func(i, j int) bool { return apis[i].Score > apis[j].Score })
	list("subdomains.txt", subs)
	list("live_hosts.txt", live)
	files["live_hosts.jsonl"] = jsonl(liveRows)
	files["urls.txt"] = nil
	sort.Strings(urls)
	if len(urls) > 0 {
		files["urls.txt"] = []byte(strings.Join(urls, "\n") + "\n")
	}
	if len(prio40) > 0 { // already best-first
		files["urls_priority.tsv"] = []byte(strings.Join(prio40, "\n") + "\n")
	}
	list("js_files.txt", js)
	var av []string
	for _, a := range apis {
		av = append(av, a.Value)
	}
	files["api_endpoints.txt"] = nil
	if len(av) > 0 {
		files["api_endpoints.txt"] = []byte(strings.Join(av, "\n") + "\n")
	}
	files["api_endpoints.jsonl"] = jsonl(apis)
	files["findings.jsonl"] = jsonl(r.Leads)
	var md strings.Builder
	md.WriteString("# Leads for " + r.Run.Target + " (run " + r.Run.ID + ", " + r.Run.Status + ")\n\n")
	md.WriteString("These are pointers for manual review, derived from names and fingerprints. None is a confirmed vulnerability.\n")
	if !r.Complete {
		md.WriteString("\n> This run did not complete (" + r.Run.Status + "); absence of a lead is not evidence of absence.\n")
	}
	last := ""
	for _, l := range r.Leads {
		if l.Priority != last {
			md.WriteString("\n## " + strings.ToUpper(l.Priority) + "\n\n")
			last = l.Priority
		}
		tag := ""
		if l.State == diff.New {
			tag = " **[NEW]**"
		}
		md.WriteString(fmt.Sprintf("- %s%s — `%s`  \n  %s\n", l.Title, tag, l.Subject, l.Evidence))
	}
	files["findings.md"] = []byte(md.String())

	var infos []fileInfo
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h := sha256.Sum256(files[n])
		infos = append(infos, fileInfo{n, strings.Count(string(files[n]), "\n"), hex.EncodeToString(h[:])})
	}
	manifest := map[string]any{
		"schema": Schema + "/manifest", "generated_at": r.GeneratedAt, "run": r.Run, "complete": r.Complete, "baseline_run_id": r.Baseline,
		"stages": r.Stages, "filtered_not_stored": r.Filtered, "files": infos, "summary": r.Summary,
		"notes": []string{
			"complete=false means at least one planned stage did not succeed; these lists are real but possibly partial.",
			"filtered_not_stored counts URLs kept out of these lists (static resources, parameter/ID variants, duplicates). Every one is still in runs/<id>/raw/.",
		},
	}
	files["manifest.json"] = jsonBytes(manifest)
	return files, infos
}

func uniq(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return raw
}
