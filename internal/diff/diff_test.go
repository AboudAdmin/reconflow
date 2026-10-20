package diff

import (
	"path/filepath"
	"testing"
	"time"

	"reconflow/internal/model"
	"reconflow/internal/storage"
)

type fx struct {
	db  *storage.DB
	tid int64
	t0  time.Time
}

func newFx(t *testing.T) *fx {
	d, err := storage.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	tid, _ := d.EnsureTarget("example.com")
	return &fx{d, tid, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// run creates a run with the given stage statuses and observations.
func (f *fx) run(t *testing.T, id string, hour int, status string, stages map[string]string, obs ...model.Obs) *storage.Run {
	t.Helper()
	at := f.t0.Add(time.Duration(hour) * time.Hour)
	r := storage.Run{ID: id, TargetID: f.tid, Status: status, ScopeHash: "s", ConfigHash: "c", Started: at, OutDir: "/x", Version: "t"}
	if err := f.db.CreateRun(r, nil); err != nil {
		t.Fatal(err)
	}
	for st, ss := range stages {
		f.db.UpsertStage(storage.Stage{Run: id, ID: st, Tool: st, Status: ss})
	}
	for i := range obs {
		obs[i].ObservedAt = at
		if obs[i].Tool == "" {
			obs[i].Tool = "subfinder"
		}
	}
	if _, err := f.db.Persist(id, f.tid, obs); err != nil {
		t.Fatal(err)
	}
	got, _ := f.db.GetRun(id)
	return got
}

func sub(h string) model.Obs { return model.Obs{Kind: model.KindSubdomain, Key: h} }
func svc(u string, code int) model.Obs {
	return model.Obs{Kind: model.KindService, Key: u, Tool: "httpx", Attrs: map[string]any{"status_code": code}}
}

func states(r *Result) map[string]string {
	m := map[string]string{}
	for _, c := range r.Items {
		m[c.Key] = c.State
	}
	return m
}

func TestNoBaselineEstablishesBaseline(t *testing.T) {
	f := newFx(t)
	cur := f.run(t, "r1", 0, "running", map[string]string{"subfinder": "success"}, sub("a.example.com"))
	r, err := Compute(f.db, cur, nil)
	if err != nil || r.Established || len(r.Items) != 0 || r.Note == "" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestNewChangedUnchangedNotSeen(t *testing.T) {
	f := newFx(t)
	ok := map[string]string{"subfinder": "success", "httpx": "success"}
	base := f.run(t, "r1", 0, "success", ok, sub("keep.example.com"), sub("gone.example.com"), svc("https://keep.example.com/", 200), svc("https://x.example.com/", 200))
	cur := f.run(t, "r2", 1, "running", ok, sub("keep.example.com"), sub("new.example.com"), svc("https://keep.example.com/", 200), svc("https://x.example.com/", 403))
	r, _ := Compute(f.db, cur, base)
	got := states(r)
	want := map[string]string{"new.example.com": New, "gone.example.com": NotSeen, "https://x.example.com/": Changed}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (all=%v)", k, got[k], v, got)
		}
	}
	if _, listed := got["keep.example.com"]; listed || r.Counts["subdomain/unchanged"] != 1 || r.Counts["service/unchanged"] != 1 {
		t.Errorf("unchanged handling wrong: %v %v", got, r.Counts)
	}
	for _, c := range r.Items {
		if c.State == "confirmed_removed" {
			t.Fatal("confirmed_removed must never be produced")
		}
	}
}

func TestFailedProducerGivesUnknownNotRemoval(t *testing.T) {
	f := newFx(t)
	base := f.run(t, "r1", 0, "success", map[string]string{"subfinder": "success"}, sub("a.example.com"))
	cur := f.run(t, "r2", 1, "partial", map[string]string{"subfinder": "failed"})
	r, _ := Compute(f.db, cur, base)
	if s := states(r)["a.example.com"]; s != Unknown {
		t.Fatalf("failed stage must yield unknown, got %q", s)
	}
}

func TestPossiblyRemovedNeedsTwoAbsences(t *testing.T) {
	f := newFx(t)
	ok := map[string]string{"subfinder": "success"}
	f.run(t, "r1", 0, "success", ok, sub("old.example.com"), sub("a.example.com"))
	base := f.run(t, "r2", 1, "success", ok, sub("a.example.com"))
	cur := f.run(t, "r3", 2, "running", ok, sub("a.example.com"))
	r, _ := Compute(f.db, cur, base)
	if s := states(r)["old.example.com"]; s != PossiblyRemoved {
		t.Fatalf("got %q", s)
	}
}

func TestJSChangesAndIntel(t *testing.T) {
	f := newFx(t)
	stages := map[string]string{"js": "success"}
	base := f.run(t, "r1", 0, "success", stages)
	cur := f.run(t, "r2", 1, "running", stages)
	now := time.Now()
	f.db.PutJSContent("r1", "aaa", "https://example.com/app.js", "text/javascript", "/p", 1, 200, now)
	f.db.PutJSContent("r1", "ddd", "https://example.com/old.js", "text/javascript", "/p", 1, 200, now)
	f.db.PutJSContent("r2", "bbb", "https://example.com/app.js", "text/javascript", "/p", 1, 200, now)
	f.db.PutJSContent("r2", "ccc", "https://example.com/new.js", "text/javascript", "/p", 1, 200, now)
	f.db.SaveAnalysis("r1", storage.JSKey{SHA: "aaa", Analyzer: "a", Version: "1"}, []storage.Candidate{{Type: "endpoint", Value: "/api/old", Rule: "r"}}, now)
	f.db.SaveAnalysis("r2", storage.JSKey{SHA: "bbb", Analyzer: "a", Version: "1"}, []storage.Candidate{{Type: "endpoint", Value: "/api/new", Rule: "r"}}, now)
	r, _ := Compute(f.db, cur, base)
	got := states(r)
	if got["https://example.com/app.js"] != Changed || got["https://example.com/old.js"] != NotSeen || got["/api/new"] != New {
		t.Fatalf("%v", got)
	}
	foundNew := false
	for _, c := range r.Items {
		if c.Subject == SubjJS && c.State == New {
			foundNew = true
		}
	}
	if !foundNew {
		t.Errorf("new.js should be new: %v", got)
	}
}
