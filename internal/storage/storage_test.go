package storage

import (
	"path/filepath"
	"testing"
	"time"

	"reconflow/internal/model"
)

func open(t *testing.T) (*DB, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "db", "t.db")
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, p
}

func mkRun(t *testing.T, d *DB, tid int64, id, status, scope string, passive bool, at time.Time) {
	t.Helper()
	if err := d.CreateRun(Run{ID: id, TargetID: tid, Status: status, ScopeHash: scope, ConfigHash: "c", Started: at, OutDir: "/x", Version: "t", Passive: passive}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPersistKeepsProvenanceAndDedupes(t *testing.T) {
	d, _ := open(t)
	tid, _ := d.EnsureTarget("example.com")
	mkRun(t, d, tid, "r1", "running", "s", false, time.Now())
	now := time.Now()
	obs := []model.Obs{
		{Kind: "subdomain", Key: "a.example.com", Tool: "subfinder", Input: "example.com", ObservedAt: now},
		{Kind: "subdomain", Key: "a.example.com", Tool: "other", Input: "example.com", ObservedAt: now},
		{Kind: "subdomain", Key: "a.example.com", Tool: "subfinder", Input: "example.com", ObservedAt: now}, // exact repeat
	}
	n, err := d.Persist("r1", tid, obs)
	if err != nil || n != 1 {
		t.Fatalf("new=%d err=%v", n, err)
	}
	ents, _ := d.RunEntities("r1")
	if len(ents) != 1 || len(ents[0].Sources) != 2 {
		t.Fatalf("provenance lost: %+v", ents)
	}
	if c, _ := d.Counts("r1"); c["subdomain"] != 1 {
		t.Fatalf("counts %v", c)
	}
}

func TestReopenIntegrityAndNewerSchemaRefused(t *testing.T) {
	d, p := open(t)
	tid, _ := d.EnsureTarget("example.com")
	mkRun(t, d, tid, "r1", "success", "s", false, time.Now())
	d.Persist("r1", tid, []model.Obs{{Kind: "url", Key: "https://example.com/", Tool: "gau", ObservedAt: time.Now()}})
	d.Close()
	d2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := d2.IntegrityCheck(); err != nil {
		t.Fatal(err)
	}
	if e, _ := d2.RunEntities("r1"); len(e) != 1 {
		t.Fatal("data lost across reopen")
	}
	d2.sql.Exec("PRAGMA user_version=99")
	d2.Close()
	if _, err := Open(p); err == nil {
		t.Fatal("newer schema must be refused")
	}
}

func TestBaselineSelection(t *testing.T) {
	d, _ := open(t)
	tid, _ := d.EnsureTarget("example.com")
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mkRun(t, d, tid, "ok-old", "success", "s", false, t0)
	mkRun(t, d, tid, "partial", "partial", "s", false, t0.Add(time.Hour))
	mkRun(t, d, tid, "other-scope", "success", "OTHER", false, t0.Add(2*time.Hour))
	mkRun(t, d, tid, "passive", "success", "s", true, t0.Add(3*time.Hour))
	mkRun(t, d, tid, "cancelled", "cancelled", "s", false, t0.Add(4*time.Hour))
	mkRun(t, d, tid, "cur", "running", "s", false, t0.Add(5*time.Hour))
	b, err := d.Baseline(tid, "s", false, t0.Add(5*time.Hour), "cur")
	if err != nil || b == nil || b.ID != "ok-old" {
		t.Fatalf("baseline=%+v err=%v", b, err)
	}
	if b, _ := d.Baseline(tid, "nomatch", false, t0.Add(9*time.Hour), "cur"); b != nil {
		t.Fatal("different scope hash must have no baseline")
	}
}

func TestFinishStageIsAtomicWithCheckpoint(t *testing.T) {
	d, _ := open(t)
	tid, _ := d.EnsureTarget("example.com")
	mkRun(t, d, tid, "r1", "running", "s", false, time.Now())
	st := Stage{Run: "r1", ID: "subfinder", Tool: "subfinder", Status: "success", Outputs: 3, Started: time.Now(), Finished: time.Now()}
	if err := d.FinishStage(st, Checkpoint{Stage: "subfinder", State: "done", ArtifactSHA: "abc"}); err != nil {
		t.Fatal(err)
	}
	cps, _ := d.Checkpoints("r1")
	stages, _ := d.Stages("r1")
	if cps["subfinder"].ArtifactSHA != "abc" || len(stages) != 1 || stages[0].Outputs != 3 {
		t.Fatalf("%+v %+v", cps, stages)
	}
}

func TestJSAnalysisCacheKey(t *testing.T) {
	d, _ := open(t)
	tid, _ := d.EnsureTarget("example.com")
	mkRun(t, d, tid, "r1", "running", "s", false, time.Now())
	now := time.Now()
	d.PutJSContent("r1", "sha1", "https://example.com/a.js", "application/javascript", "/p", 10, 200, now)
	d.PutJSContent("r1", "sha1", "https://example.com/b.js", "application/javascript", "/p", 10, 200, now)
	k := JSKey{"sha1", "builtin", "1", "cfg", "r1"}
	if ok, _ := d.Analyzed(k); ok {
		t.Fatal("not analyzed yet")
	}
	d.SaveAnalysis("r1", k, []Candidate{{Type: "endpoint", Value: "/api/x", Rule: "path", Verification: model.VerifStatic}}, now)
	if ok, _ := d.Analyzed(k); !ok {
		t.Fatal("must be cached")
	}
	k2 := k
	k2.Version = "2"
	if ok, _ := d.Analyzed(k2); ok {
		t.Fatal("analyzer version change must invalidate cache")
	}
	src, _ := d.RunJS("r1")
	cands, _ := d.RunCandidates("r1")
	if len(src) != 2 || len(cands) != 1 {
		t.Fatalf("one content, two source URLs expected: %d %d", len(src), len(cands))
	}
}
