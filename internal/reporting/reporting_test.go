package reporting

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reconflow/internal/diff"
	"reconflow/internal/model"
	"reconflow/internal/storage"
)

const evil = `</script><img src=x onerror=alert(1)>"'&`

func fixture(t *testing.T, withBaseline bool) (Input, string) {
	t.Helper()
	d, err := storage.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	tid, _ := d.EnsureTarget("example.com")
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(id string, h int, status string) *storage.Run {
		d.CreateRun(storage.Run{ID: id, TargetID: tid, Status: status, ScopeHash: "s", ConfigHash: "c", Started: t0.Add(time.Duration(h) * time.Hour), OutDir: "/x", Version: "t"}, nil)
		r, _ := d.GetRun(id)
		return r
	}
	var base *storage.Run
	if withBaseline {
		base = mk("base", 0, "success")
		d.UpsertStage(storage.Stage{Run: "base", ID: "subfinder", Tool: "subfinder", Status: "success"})
		d.Persist("base", tid, []model.Obs{{Kind: "subdomain", Key: "old.example.com", Tool: "subfinder", ObservedAt: t0}})
	}
	cur := mk("cur", 1, "success")
	d.UpsertStage(storage.Stage{Run: "cur", ID: "subfinder", Tool: "subfinder", Status: "success", Started: t0, Finished: t0.Add(time.Second), Error: evil})
	d.UpsertStage(storage.Stage{Run: "cur", ID: "httpx", Tool: "httpx", Status: "failed", Error: "boom " + evil})
	d.Persist("cur", tid, []model.Obs{
		{Kind: "subdomain", Key: "new." + evil, Tool: "subfinder", ObservedAt: t0},
		{Kind: "url", Key: "https://example.com/a.js?x=" + evil, Tool: "katana", ObservedAt: t0, Meta: map[string]any{"origin": "crawled"}},
		{Kind: "url", Key: "https://example.com/old", Tool: "gau", ObservedAt: t0, Meta: map[string]any{"origin": "historical"}}})
	d.PutJSContent("cur", "abc", "https://example.com/a.js", "text/javascript", "/p", 5, 200, t0)
	d.SaveAnalysis("cur", storage.JSKey{SHA: "abc", Analyzer: "a", Version: "1"}, []storage.Candidate{{Type: "endpoint", Value: evil, Rule: "api-like-path", Verification: "static_unverified"}}, t0)
	dr, err := diff.Compute(d, cur, base)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return Input{DB: d, Run: cur, Diff: dr, ReportsDir: filepath.Join(dir, "reports"), JSDir: filepath.Join(dir, "js"), JSONL: true, HTML: true, Now: t0}, dir
}

func TestGenerateFilesFromPersistedData(t *testing.T) {
	in, _ := fixture(t, true)
	arts, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, a := range arts {
		names[a.Name] = true
		if _, err := os.Stat(a.Path); err != nil {
			t.Errorf("artifact missing: %s", a.Path)
		}
	}
	for _, n := range []string{"latest.json", "latest.html", "execution.json", "coverage.json", "new_assets.txt", "new_endpoints.txt", "new_js_intel.txt", "changed_assets.txt", "not_seen_assets.txt", "assets.jsonl", "urls.jsonl", "inventory.jsonl", "endpoints.jsonl"} {
		if !names[n] {
			t.Errorf("missing %s", n)
		}
	}
	var rep Report
	b, _ := os.ReadFile(filepath.Join(in.ReportsDir, "latest.json"))
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Run.ID != "cur" || rep.Baseline != "base" || rep.Summary["subdomains"] != 1 || rep.Summary["urls_crawled_live"] != 1 || rep.Summary["urls_historical_only"] != 1 {
		t.Fatalf("report content wrong: %+v", rep.Summary)
	}
	ns, _ := os.ReadFile(filepath.Join(in.ReportsDir, "not_seen_assets.txt"))
	if !strings.Contains(string(ns), "old.example.com") {
		t.Errorf("not_seen list: %s", ns)
	}
	// httpx failed, so service coverage must not be claimed comparable
	for _, k := range rep.Coverage {
		if k.Kind == "service" && k.Comparable {
			t.Error("service coverage must be non-comparable when httpx failed")
		}
	}
}

func TestNoBaselineWritesNoNewLists(t *testing.T) {
	in, _ := fixture(t, false)
	arts, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range arts {
		if a.Name == "new_assets.txt" {
			t.Fatal("must not write new_* lists without a baseline")
		}
	}
	b, _ := os.ReadFile(filepath.Join(in.ReportsDir, "latest.json"))
	if !strings.Contains(string(b), `"baseline_established": false`) {
		t.Error("report must state that no baseline exists")
	}
}

func TestHTMLEscapesUntrustedValues(t *testing.T) {
	in, _ := fixture(t, true)
	r, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	page := string(BuildHTML(r))
	if strings.Contains(page, "<img src=x") || strings.Contains(page, "onerror=alert(1)>") {
		t.Fatal("raw hostile markup reached the page")
	}
	// Exactly the two legitimate script blocks may close.
	if n := strings.Count(page, "</script>"); n != 2 {
		t.Fatalf("expected 2 </script>, got %d (injection)", n)
	}
	if !strings.Contains(page, `</script>`) {
		t.Error("hostile value should be present only in escaped form")
	}
	// The React bundle itself mentions innerHTML (react-dom internals); our own source must never opt in.
	src, _ := filepath.Glob("../../dashboard/src/*")
	for _, f := range src {
		if b, _ := os.ReadFile(f); strings.Contains(string(b), "dangerouslySetInnerHTML") || strings.Contains(string(b), ".innerHTML") {
			t.Errorf("%s renders raw HTML", f)
		}
	}
	// the embedded block must be valid JSON
	start := strings.Index(page, `type="application/json">`) + len(`type="application/json">`)
	end := strings.Index(page[start:], "</script>")
	var v map[string]any
	if err := json.Unmarshal([]byte(page[start:start+end]), &v); err != nil {
		t.Fatalf("embedded data is not valid JSON: %v", err)
	}
}

func TestEmbeddedRowCap(t *testing.T) {
	r := &Report{Summary: map[string]int{}, Truncated: map[string]int{}}
	for i := 0; i < MaxEmbeddedRows+5; i++ {
		r.URLs = append(r.URLs, URLRow{URL: "https://example.com/x"})
	}
	page := string(BuildHTML(r))
	if !strings.Contains(page, `"html_truncated":{"urls":20005}`) {
		t.Error("truncation must be declared in the page data")
	}
	if len(r.URLs) != MaxEmbeddedRows+5 {
		t.Error("BuildHTML must not mutate the report used for JSON exports")
	}
}

func TestNormalizedOutputsAreCleanAndHonest(t *testing.T) {
	in, dir := fixture(t, true)
	in.RunDir, in.NormDir = filepath.Join(dir, "run"), filepath.Join(dir, "norm")
	os.MkdirAll(filepath.Join(in.RunDir, "raw"), 0o755)
	os.WriteFile(filepath.Join(in.RunDir, "raw", "katana.meta.json"), []byte(`{"stage":"katana","filtered":{"static":7}}`), 0o644)
	in.DB.Persist("cur", in.Run.TargetID, []model.Obs{
		{Kind: "url", Key: "https://example.com/api/v1/users", Tool: "katana", ObservedAt: in.Now, Meta: map[string]any{"origin": "crawled"}},
		{Kind: "url", Key: "https://example.com/actuator/env?redirect=/x", Tool: "gau", ObservedAt: in.Now, Meta: map[string]any{"origin": "historical"}},
		{Kind: "service", Key: "https://ci.example.com", Tool: "httpx", ObservedAt: in.Now, Attrs: map[string]any{"title": "Dashboard [Jenkins]"}}})
	if _, err := Generate(in); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(in.RunDir, "normalized"), in.NormDir} {
		for _, f := range []string{"subdomains.txt", "live_hosts.txt", "urls.txt", "js_files.txt", "api_endpoints.txt", "findings.jsonl", "findings.md", "manifest.json"} {
			if _, err := os.Stat(filepath.Join(d, f)); err != nil {
				t.Errorf("%s missing in %s", f, d)
			}
		}
	}
	read := func(n string) string {
		b, _ := os.ReadFile(filepath.Join(in.RunDir, "normalized", n))
		return string(b)
	}
	if !strings.Contains(read("api_endpoints.txt"), "/api/v1/users") {
		t.Error("API URL missing from api_endpoints.txt")
	}
	fm := read("findings.md")
	for _, w := range []string{"Jenkins", "actuator", "None is a confirmed vulnerability"} {
		if !strings.Contains(fm, w) {
			t.Errorf("findings.md lacks %q", w)
		}
	}
	if strings.Index(fm, "Jenkins") > strings.Index(fm, "redirect") && strings.Contains(fm, "## LOW") && strings.Index(fm, "## HIGH") > strings.Index(fm, "## LOW") {
		t.Error("high priority leads must come first")
	}
	var man struct {
		Complete bool                      `json:"complete"`
		Filtered map[string]map[string]int `json:"filtered_not_stored"`
	}
	if err := json.Unmarshal([]byte(read("manifest.json")), &man); err != nil {
		t.Fatal(err)
	}
	if man.Filtered["katana"]["static"] != 7 {
		t.Errorf("filter counts not carried into manifest: %+v", man.Filtered)
	}
	if _, err := os.Stat(filepath.Join(in.RunDir, "report.json")); err != nil {
		t.Error("per-run report.json missing")
	}
}
