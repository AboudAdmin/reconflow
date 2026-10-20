// Package diff classifies the current run against a compatible baseline.
//
// States: new, changed, unchanged, not_seen, possibly_removed, unknown.
// "confirmed_removed" is intentionally never produced: ReconFlow has no
// verification policy that could justify it. Absence is never proof of deletion.
package diff

import (
	"fmt"
	"sort"
	"strings"

	"reconflow/internal/model"
	"reconflow/internal/storage"
)

const (
	New             = "new"
	Changed         = "changed"
	Unchanged       = "unchanged"
	NotSeen         = "not_seen"
	PossiblyRemoved = "possibly_removed"
	Unknown         = "unknown"
)

// Producers maps an entity kind to the stages that can observe it.
var Producers = map[string][]string{
	model.KindSubdomain: {"subfinder"},
	model.KindDNS:       {"dnsx"},
	model.KindService:   {"httpx"},
	model.KindURL:       {"gau", "waybackurls", "katana"},
}

const (
	SubjJS      = "js_content"
	SubjJSIntel = "js_intel"
)

type Result struct {
	BaselineID  string
	Established bool // true when a valid baseline existed
	Note        string
	Items       []storage.Comparison // everything except "unchanged"
	Counts      map[string]int       // "<subject>/<state>" -> n, including unchanged
}

func (r *Result) add(subject, kind, key, state, reason string) {
	r.Counts[subject+"/"+state]++
	if state != Unchanged {
		r.Items = append(r.Items, storage.Comparison{Subject: subject, Kind: kind, Key: key, State: state, Reason: reason})
	}
}

// reliability returns, per kind, an explanation when absence cannot be trusted
// ("" = reliable) and whether the kind was collected at all in this run.
func reliability(stages []storage.Stage) (reason map[string]string, planned map[string]bool) {
	reason, planned = map[string]string{}, map[string]bool{}
	st := map[string]storage.Stage{}
	for _, s := range stages {
		st[s.ID] = s
	}
	for kind, prods := range Producers {
		for _, p := range prods {
			s, ok := st[p]
			if !ok {
				continue
			}
			planned[kind] = true
			if s.Status != string(model.Success) && reason[kind] == "" {
				reason[kind] = fmt.Sprintf("stage %s ended %s", p, s.Status)
			}
		}
	}
	return
}

func Compute(db *storage.DB, run, baseline *storage.Run) (*Result, error) {
	res := &Result{Counts: map[string]int{}}
	if baseline == nil {
		res.Note = "no valid baseline (a prior fully successful run with the same target, scope policy and mode): this run establishes the baseline; 'new' cannot be determined"
		return res, nil
	}
	res.BaselineID, res.Established = baseline.ID, true
	stages, err := db.Stages(run.ID)
	if err != nil {
		return nil, err
	}
	bad, planned := reliability(stages)
	cur, err := db.RunEntities(run.ID)
	if err != nil {
		return nil, err
	}
	base, err := db.RunEntities(baseline.ID)
	if err != nil {
		return nil, err
	}
	baseByID := map[int64]storage.Entity{}
	for _, e := range base {
		baseByID[e.ID] = e
	}
	curIDs := map[int64]bool{}
	for _, e := range cur {
		curIDs[e.ID] = true
		if !planned[e.Kind] {
			continue
		}
		b, ok := baseByID[e.ID]
		switch {
		case !ok && e.FirstRun == run.ID:
			res.add(e.Kind, e.Kind, e.Key, New, "first observation")
		case !ok:
			res.add(e.Kind, e.Kind, e.Key, New, "not in baseline; seen in an earlier run")
		case b.Hash != e.Hash:
			res.add(e.Kind, e.Kind, e.Key, Changed, "material attributes differ: "+diffAttrs(b.Attrs, e.Attrs))
		default:
			res.add(e.Kind, e.Kind, e.Key, Unchanged, "")
		}
	}
	for _, b := range base {
		if curIDs[b.ID] || !planned[b.Kind] {
			continue
		}
		if why := bad[b.Kind]; why != "" {
			res.add(b.Kind, b.Kind, b.Key, Unknown, "cannot compare: "+why)
		} else {
			res.add(b.Kind, b.Kind, b.Key, NotSeen, "in baseline, absent now; absence is not proof of removal")
		}
	}
	comparable, err := db.ComparableRuns(run.TargetID, run.ScopeHash, run.Passive)
	if err != nil {
		return nil, err
	}
	older, err := db.PriorEntities(run.TargetID, run.ID, baseline.ID)
	if err != nil {
		return nil, err
	}
	for _, e := range older {
		if !planned[e.Kind] || bad[e.Kind] != "" || !comparable[e.LastRun] {
			continue
		}
		res.add(e.Kind, e.Kind, e.Key, PossiblyRemoved, "absent from baseline and current run; last seen in "+e.LastRun)
	}
	if err := computeJS(db, run, baseline, stages, res); err != nil {
		return nil, err
	}
	sort.Slice(res.Items, func(i, j int) bool {
		a, b := res.Items[i], res.Items[j]
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		if a.State != b.State {
			return a.State < b.State
		}
		return a.Key < b.Key
	})
	return res, nil
}

func diffAttrs(a, b map[string]any) string {
	var out []string
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	for k := range keys {
		if fmt.Sprint(a[k]) != fmt.Sprint(b[k]) {
			out = append(out, fmt.Sprintf("%s: %v -> %v", k, a[k], b[k]))
		}
	}
	sort.Strings(out)
	return strings.Join(out, "; ")
}

func computeJS(db *storage.DB, run, baseline *storage.Run, stages []storage.Stage, res *Result) error {
	jsOK := false
	for _, s := range stages {
		if s.ID == "js" {
			jsOK = s.Status == string(model.Success)
			if s.Status == string(model.Skipped) {
				return nil
			}
		}
	}
	if !hasStage(stages, "js") {
		return nil
	}
	cur, err := db.RunJS(run.ID)
	if err != nil {
		return err
	}
	base, err := db.RunJS(baseline.ID)
	if err != nil {
		return err
	}
	byURL := func(in []storage.JSSource) map[string][]string {
		m := map[string][]string{}
		for _, j := range in {
			m[j.URL] = append(m[j.URL], j.SHA)
		}
		return m
	}
	cu, bu := byURL(cur), byURL(base)
	baseSHA := map[string]bool{}
	for _, j := range base {
		baseSHA[j.SHA] = true
	}
	for u, shas := range cu {
		old, ok := bu[u]
		switch {
		case !ok:
			state, why := New, "url not fetched in baseline"
			if allIn(shas, baseSHA) {
				state, why = Unchanged, ""
			}
			res.add(SubjJS, "js", u+" sha256:"+shas[0], state, why)
		case !sameSet(old, shas):
			res.add(SubjJS, "js", u, Changed, fmt.Sprintf("content hash %s -> %s", short(old), short(shas)))
		default:
			res.add(SubjJS, "js", u, Unchanged, "")
		}
	}
	for u := range bu {
		if _, ok := cu[u]; !ok {
			if jsOK {
				res.add(SubjJS, "js", u, NotSeen, "fetched in baseline, not in current run")
			} else {
				res.add(SubjJS, "js", u, Unknown, "cannot compare: js stage did not succeed")
			}
		}
	}
	cc, err := db.RunCandidates(run.ID)
	if err != nil {
		return err
	}
	bc, err := db.RunCandidates(baseline.ID)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, c := range bc {
		have[c.Type+"\x00"+c.Value] = true
	}
	seen := map[string]bool{}
	for _, c := range cc {
		k := c.Type + "\x00" + c.Value
		if seen[k] {
			continue
		}
		seen[k] = true
		if have[k] {
			res.add(SubjJSIntel, c.Type, c.Value, Unchanged, "")
		} else {
			res.add(SubjJSIntel, c.Type, c.Value, New, "candidate not present in baseline JS (unverified)")
		}
	}
	return nil
}

func hasStage(ss []storage.Stage, id string) bool {
	for _, s := range ss {
		if s.ID == id {
			return true
		}
	}
	return false
}

func short(shas []string) string {
	var o []string
	for _, s := range shas {
		if len(s) > 12 {
			s = s[:12]
		}
		o = append(o, s)
	}
	sort.Strings(o)
	return strings.Join(o, ",")
}

func allIn(a []string, m map[string]bool) bool {
	for _, x := range a {
		if !m[x] {
			return false
		}
	}
	return true
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}
