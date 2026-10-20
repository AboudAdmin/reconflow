package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reconflow/internal/adapters"
	"reconflow/internal/config"
	"reconflow/internal/model"
	"reconflow/internal/scope"
	"reconflow/internal/storage"
	"reconflow/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.MaybeRunFake()
	os.Exit(m.Run())
}

type env struct {
	t     *testing.T
	cfg   *config.Config
	db    *storage.DB
	pol   *scope.Policy
	bin   string
	port  string
	logs  string
	hits  *int
	srv   *httptest.Server
	tools map[string]testutil.Behavior
}

const jsBody = `/*! jQuery v3.6.0 */ var a="/api/v1/users?id=1&sort=asc";var g="https://api.example.test/graphql";`

func newEnv(t *testing.T) *env {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(jsBody))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.Database = filepath.Join(dir, "data", "db", "rf.db")
	cfg.Retry.BackoffBase, cfg.Retry.BackoffMax = time.Millisecond, 2*time.Millisecond
	cfg.JS.RPS = 100
	cfg.Timeouts.Grace = time.Second
	sp := filepath.Join(dir, "scope.yaml")
	os.WriteFile(sp, []byte(fmt.Sprintf("include: {domains: [example.test], ips: [\"127.0.0.1\"], cidrs: [\"127.0.0.0/8\"]}\nports: [80, 443, %s]\n", u.Port())), 0o600)
	pol, err := scope.Load(sp)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &env{t: t, cfg: cfg, db: db, pol: pol, bin: filepath.Join(dir, "bin"), port: u.Port(), logs: filepath.Join(dir, "logs"), hits: &hits, srv: srv, tools: map[string]testutil.Behavior{}}
	os.MkdirAll(e.bin, 0o700)
	os.MkdirAll(e.logs, 0o700)
	e.defaults()
	e.install()
	return e
}

func (e *env) defaults() {
	jl := func(v map[string]any) string { b, _ := json.Marshal(v); return string(b) }
	e.tools["subfinder"] = testutil.Behavior{Stdout: []string{
		jl(map[string]any{"host": "a.example.test", "source": []string{"crtsh"}}), jl(map[string]any{"host": "b.example.test"}), jl(map[string]any{"host": "evil.other.com"})}}
	e.tools["dnsx"] = testutil.Behavior{Stdout: []string{jl(map[string]any{"host": "a.example.test", "a": []string{"93.184.216.34"}}), jl(map[string]any{"host": "b.example.test", "a": []string{"93.184.216.35"}})}}
	e.tools["httpx"] = testutil.Behavior{Stdout: []string{
		jl(map[string]any{"url": "http://a.example.test", "input": "a.example.test", "status_code": 200, "title": "A", "tech": []string{"nginx"}}),
		jl(map[string]any{"url": "http://b.example.test", "input": "b.example.test", "status_code": 403})}}
	e.tools["katana"] = testutil.Behavior{Stdout: []string{
		jl(map[string]any{"request": map[string]any{"endpoint": "http://127.0.0.1:" + e.port + "/app.js", "source": "http://a.example.test/"}}),
		jl(map[string]any{"request": map[string]any{"endpoint": "http://a.example.test/login", "source": "http://a.example.test/"}})}}
	e.tools["gau"] = testutil.Behavior{Stdout: []string{"http://a.example.test/old?x=1", "https://thirdparty.com/x.js", "http://a.example.test:8080/not-allowed-port"}}
	e.tools["waybackurls"] = testutil.Behavior{}
}

func (e *env) install() {
	for name, b := range e.tools {
		a := adapters.Get(name)
		b.Help = strings.Join(a.RequiredFlags, " ")
		b.Version = "Current Version: v1.2.3"
		b.ArgsLog = filepath.Join(e.logs, name+".args")
		e.cfg.Tools[name] = config.Tool{Path: testutil.Install(e.t, e.bin, name, b)}
	}
}

func (e *env) run(ctx context.Context, passive, resume bool) (*Result, error) {
	return Run(ctx, Options{Target: "example.test", Passive: passive, Resume: resume, Cfg: e.cfg, Scope: e.pol, DB: e.db, Version: "test"})
}

func (e *env) invocations(tool string) int {
	f, err := os.Open(filepath.Join(e.logs, tool+".args"))
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n++
	}
	return n
}

func stageMap(r *Result) map[string]storage.Stage {
	m := map[string]storage.Stage{}
	for _, s := range r.Stages {
		m[s.ID] = s
	}
	return m
}

func TestFullRunPersistsScopedDataAndJS(t *testing.T) {
	e := newEnv(t)
	res, err := e.run(context.Background(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	st := stageMap(res)
	for _, id := range []string{"subfinder", "dnsx", "httpx", "gau", "waybackurls", "katana", "js"} {
		if st[id].Status != "success" {
			t.Errorf("%s: %s %s", id, st[id].Status, st[id].Error)
		}
	}
	if res.Status != model.Success {
		t.Fatalf("run status %s", res.Status)
	}
	c, _ := e.db.Counts(res.Run.ID)
	if c["subdomain"] != 2 || c["dns"] != 2 || c["service"] != 2 {
		t.Errorf("counts %v (out-of-scope host must be dropped)", c)
	}
	if st["subfinder"].Dropped != 1 {
		t.Errorf("subfinder dropped=%d want 1", st["subfinder"].Dropped)
	}
	if st["waybackurls"].Outputs != 0 || !strings.Contains(st["waybackurls"].Error, "empty") {
		t.Errorf("empty result must be explicit: %+v", st["waybackurls"])
	}
	ents, _ := e.db.RunEntities(res.Run.ID)
	for _, en := range ents {
		if strings.Contains(en.Key, "thirdparty") || strings.Contains(en.Key, ":8080") {
			t.Errorf("ineligible URL persisted: %s", en.Key)
		}
	}
	// JS: fetched once from the in-scope host, stored by hash, analyzed with provenance
	js, _ := e.db.RunJS(res.Run.ID)
	if len(js) != 1 || *e.hits != 1 {
		t.Fatalf("js sources=%d hits=%d", len(js), *e.hits)
	}
	if _, err := os.Stat(js[0].Path); err != nil || !strings.HasPrefix(js[0].Path, res.Layout.JSFiles) {
		t.Errorf("content file not stored under javascript/files: %v", err)
	}
	cands, _ := e.db.RunCandidates(res.Run.ID)
	have := map[string]bool{}
	for _, c := range cands {
		have[c.Type+"|"+c.Value] = true
		if c.Verification != "static_unverified" || c.SHA != js[0].SHA {
			t.Errorf("candidate provenance wrong: %+v", c)
		}
	}
	if !have["graphql|https://api.example.test/graphql"] || !have["library|jquery 3.6.0"] || !have["parameter|sort"] {
		t.Errorf("candidates: %v", have)
	}
	for _, f := range []string{"latest.html", "latest.json", "execution.json", "coverage.json"} {
		if _, err := os.Stat(filepath.Join(res.Layout.Reports, f)); err != nil {
			t.Errorf("missing report %s", f)
		}
	}
	tools, _ := e.db.Tools(res.Run.ID)
	if len(tools) != 6 || tools[0].Version != "1.2.3" {
		t.Errorf("tool versions not recorded: %+v", tools)
	}
	// raw evidence kept as an inspectable artifact
	if _, err := os.Stat(filepath.Join(res.Layout.RunDir(res.Run.ID), "raw", "subfinder.out")); err != nil {
		t.Error("raw evidence missing")
	}
	// Argument boundaries: the target is passed as a single argv element.
	f, _ := os.ReadFile(filepath.Join(e.logs, "subfinder.args"))
	if !strings.Contains(string(f), `["-d","example.test","-silent","-json"]`) {
		t.Errorf("subfinder args: %s", f)
	}
}

func TestSecondRunProducesDiffAgainstBaseline(t *testing.T) {
	e := newEnv(t)
	r1, err := e.run(context.Background(), false, false)
	if err != nil || r1.Status != model.Success {
		t.Fatalf("%v %v", err, r1)
	}
	if r1.Diff.Established {
		t.Fatal("first run must establish a baseline")
	}
	jl := func(h string) string { return fmt.Sprintf(`{"host":%q}`, h) }
	e.tools["subfinder"] = testutil.Behavior{Stdout: []string{jl("a.example.test"), jl("c.example.test")}} // b gone, c new
	e.install()
	time.Sleep(1100 * time.Millisecond) // run ids / started_at ordering
	r2, err := e.run(context.Background(), false, false)
	if err != nil || r2.Status != model.Success {
		t.Fatalf("%v %v", err, r2)
	}
	if r2.Diff.BaselineID != r1.Run.ID {
		t.Fatalf("baseline %q want %q", r2.Diff.BaselineID, r1.Run.ID)
	}
	got := map[string]string{}
	for _, c := range r2.Diff.Items {
		got[c.Key] = c.State
	}
	if got["c.example.test"] != "new" || got["b.example.test"] != "not_seen" {
		t.Fatalf("diff states: %v", got)
	}
	b, _ := os.ReadFile(filepath.Join(r2.Layout.Reports, "new_assets.txt"))
	if !strings.Contains(string(b), "c.example.test") || strings.Contains(string(b), "a.example.test") {
		t.Errorf("new_assets.txt: %s", b)
	}
}

func TestToolFailuresAreIsolatedAndRetriesBounded(t *testing.T) {
	e := newEnv(t)
	e.tools["httpx"] = testutil.Behavior{Exit: 2, Stderr: "flag provided but not defined: -x"} // permanent
	e.tools["gau"] = testutil.Behavior{Exit: 1, Stderr: "dial tcp: connection reset by peer", FailFirst: 1, Stdout: []string{"http://a.example.test/old"}}
	e.install()
	res, err := e.run(context.Background(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	st := stageMap(res)
	if st["httpx"].Status != "failed" || e.invocations("httpx") != 1 {
		t.Errorf("permanent error must fail without retry: %s invocations=%d", st["httpx"].Status, e.invocations("httpx"))
	}
	if st["katana"].Status != "skipped" || !strings.Contains(st["katana"].Error, "prerequisite httpx") {
		t.Errorf("katana must be skipped when its hard prerequisite failed: %+v", st["katana"])
	}
	if st["gau"].Status != "success" || st["gau"].Retries != 1 || e.invocations("gau") != 2 {
		t.Errorf("transient failure should be retried once: %+v inv=%d", st["gau"], e.invocations("gau"))
	}
	if st["subfinder"].Status != "success" || st["js"].Status != "success" {
		t.Errorf("independent stages must continue: %s %s", st["subfinder"].Status, st["js"].Status)
	}
	if res.Status != model.Partial {
		t.Errorf("run status %s, want partial", res.Status)
	}
	errs, _ := e.db.Errors(res.Run.ID)
	if len(errs) == 0 {
		t.Error("failure must be recorded in errors")
	}
}

func TestInvalidOutputIsFailureNotEmptySuccess(t *testing.T) {
	e := newEnv(t)
	e.tools["subfinder"] = testutil.Behavior{Stdout: []string{"{not json", "also bad"}}
	e.install()
	res, _ := e.run(context.Background(), false, false)
	// plain-text lines are valid subfinder hosts only if they are valid hostnames; "also bad" has a space.
	if s := stageMap(res)["subfinder"]; s.Status != "failed" || !strings.Contains(s.Error, "could not be parsed") {
		t.Fatalf("%+v", s)
	}
}

func TestPassiveModeRunsOnlyPassiveStages(t *testing.T) {
	e := newEnv(t)
	res, err := e.run(context.Background(), true, false)
	if err != nil {
		t.Fatal(err)
	}
	st := stageMap(res)
	if len(st) != 3 || st["subfinder"].ID == "" || st["gau"].ID == "" || st["waybackurls"].ID == "" {
		t.Fatalf("passive plan wrong: %v", st)
	}
	for _, tool := range []string{"dnsx", "httpx", "katana"} {
		if e.invocations(tool) != 0 {
			t.Errorf("%s was executed in passive mode", tool)
		}
	}
	if *e.hits != 0 {
		t.Error("passive mode made a direct HTTP request")
	}
	if !res.Run.Passive {
		t.Error("run must be marked passive")
	}
}

func TestPassivePolicyRejectsActiveStage(t *testing.T) {
	e := newEnv(t)
	e.cfg.Passive = append(e.cfg.Passive, "httpx")
	if _, err := e.run(context.Background(), true, false); err == nil || !strings.Contains(err.Error(), "not a passive-capable stage") {
		t.Fatalf("err=%v", err)
	}
}

func TestMissingToolsAreSkippedWithGuidance(t *testing.T) {
	e := newEnv(t)
	for n := range e.cfg.Tools {
		e.cfg.Tools[n] = config.Tool{Path: filepath.Join(e.bin, "does-not-exist-"+n)}
	}
	res, err := e.run(context.Background(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NoTools || res.Status == model.Success {
		t.Errorf("NoTools=%v status=%s", res.NoTools, res.Status)
	}
	if s := stageMap(res)["subfinder"]; s.Status != "skipped" || !strings.Contains(s.Error, "Install:") {
		t.Errorf("want actionable skip: %+v", s)
	}
}

func TestCancelThenResumeRerunsOnlyUnfinishedStages(t *testing.T) {
	e := newEnv(t)
	e.tools["httpx"] = testutil.Behavior{SleepMS: 20000, Stdout: e.tools["httpx"].Stdout}
	e.install()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for i := 0; i < 400; i++ { // wait until the slow stage has really started
			if e.invocations("httpx") > 0 {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		cancel()
	}()
	start := time.Now()
	r1, err := e.run(ctx, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Status != model.Cancelled || time.Since(start) > 15*time.Second {
		t.Fatalf("status=%s after %v", r1.Status, time.Since(start))
	}
	st := stageMap(r1)
	if st["subfinder"].Status != "success" || st["httpx"].Status == "success" || st["js"].Status == "success" {
		t.Errorf("unfinished stages must not look successful: %v", statuses(st))
	}
	if run, _ := e.db.GetRun(r1.Run.ID); run.Status != "cancelled" || run.Finished.IsZero() {
		t.Errorf("run row: %+v", run)
	}
	cps, _ := e.db.Checkpoints(r1.Run.ID)
	if cps["subfinder"].State != "done" || cps["httpx"].State == "done" {
		t.Errorf("checkpoints: %+v", cps)
	}
	// a cancelled run is never a baseline
	if b, _ := e.db.Baseline(r1.Run.TargetID, r1.Run.ScopeHash, false, time.Now().Add(time.Hour), "x"); b != nil {
		t.Error("cancelled run selected as baseline")
	}

	// resume with a fast httpx
	e.tools["httpx"] = testutil.Behavior{Stdout: e.tools["httpx"].Stdout}
	e.install()
	subBefore := e.invocations("subfinder")
	r2, err := e.run(context.Background(), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Run.ID != r1.Run.ID || r2.Status != model.Success {
		t.Fatalf("resume: id %s vs %s status %s stages %v", r2.Run.ID, r1.Run.ID, r2.Status, statuses(stageMap(r2)))
	}
	if e.invocations("subfinder") != subBefore {
		t.Error("completed stage was re-run on resume")
	}
	found := false
	for _, id := range r2.Resumed {
		found = found || id == "subfinder"
	}
	if !found {
		t.Errorf("subfinder not reported as resumed: %v", r2.Resumed)
	}
	if c, _ := e.db.Counts(r2.Run.ID); c["service"] != 2 {
		t.Errorf("resumed run counts: %v", c)
	}
}

func statuses(m map[string]storage.Stage) map[string]string {
	o := map[string]string{}
	for k, v := range m {
		o[k] = v.Status
	}
	return o
}

func TestResumeDetectsTamperedArtifact(t *testing.T) {
	e := newEnv(t)
	e.tools["httpx"] = testutil.Behavior{Exit: 2, Stderr: "boom"}
	e.install()
	r1, _ := e.run(context.Background(), false, false) // partial
	raw := filepath.Join(r1.Layout.RunDir(r1.Run.ID), "raw", "subfinder.out")
	os.WriteFile(raw, []byte("tampered\n"), 0o600)
	e.tools["httpx"] = testutil.Behavior{Stdout: e.tools["httpx"].Stdout}
	e.install()
	before := e.invocations("subfinder")
	r2, err := e.run(context.Background(), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if e.invocations("subfinder") != before+1 {
		t.Error("stage with a modified artifact must be re-run, not trusted")
	}
	for _, id := range r2.Resumed {
		if id == "subfinder" {
			t.Error("tampered stage reported as resumed")
		}
	}
}

func TestResumeRefusals(t *testing.T) {
	e := newEnv(t)
	if _, err := e.run(context.Background(), false, true); err != ErrNothingToResume {
		t.Fatalf("want ErrNothingToResume, got %v", err)
	}
	e.tools["httpx"] = testutil.Behavior{Exit: 2, Stderr: "boom"}
	e.install()
	e.run(context.Background(), false, false) // partial -> resumable
	if _, err := e.run(context.Background(), true, true); err == nil || !strings.Contains(err.Error(), "different scope policy or mode") {
		t.Fatalf("passive resume of an active run must be refused: %v", err)
	}
}

func TestDuplicateRunPrevention(t *testing.T) {
	e := newEnv(t)
	lay, _ := NewLayout(e.cfg.DataDir, "example.test")
	lock := filepath.Join(lay.Target, ".lock")
	os.WriteFile(lock, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600) // "another process" = this live pid
	if _, err := e.run(context.Background(), false, false); err == nil || !strings.Contains(err.Error(), "already working") {
		t.Fatalf("want lock error, got %v", err)
	}
	os.WriteFile(lock, []byte("999999999\n"), 0o600) // stale
	if res, err := e.run(context.Background(), false, false); err != nil || res.Status != model.Success {
		t.Fatalf("stale lock should be replaced: %v", err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Error("lock not released")
	}
}

func TestDatabaseReopenKeepsRun(t *testing.T) {
	e := newEnv(t)
	res, _ := e.run(context.Background(), false, false)
	e.db.Close()
	db2, err := storage.Open(e.cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if err := db2.IntegrityCheck(); err != nil {
		t.Fatal(err)
	}
	r, err := db2.GetRun(res.Run.ID)
	if err != nil || r.Status != "success" {
		t.Fatalf("%v %+v", err, r)
	}
}
