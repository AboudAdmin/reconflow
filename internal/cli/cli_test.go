package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reconflow/internal/adapters"
	"reconflow/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.MaybeRunFake()
	os.Exit(m.Run())
}

func run(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	c := Main(args, &o, &e)
	return c, o.String(), e.String()
}

type fx struct {
	dir, cfg, scope string
}

// newFx writes a config + scope and fake tools. mutate may adjust the tool behaviours.
func newFx(t *testing.T, mutate func(map[string]*testutil.Behavior)) *fx {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o700)
	bs := map[string]*testutil.Behavior{
		"subfinder":   {Stdout: []string{`{"host":"a.example.test"}`, `{"host":"b.example.test"}`}},
		"dnsx":        {Stdout: []string{`{"host":"a.example.test","a":["93.184.216.34"]}`}},
		"httpx":       {Stdout: []string{`{"url":"http://a.example.test","status_code":200,"title":"x"}`}},
		"gau":         {Stdout: []string{"http://a.example.test/old"}},
		"waybackurls": {},
		"katana":      {Stdout: []string{`{"request":{"endpoint":"http://a.example.test/app.css","source":"http://a.example.test/"}}`}},
	}
	if mutate != nil {
		mutate(bs)
	}
	var tools strings.Builder
	tools.WriteString("tools:\n")
	for name, b := range bs {
		b.Help = strings.Join(adapters.Get(name).RequiredFlags, " ")
		b.Version = "v1.0.0"
		tools.WriteString(fmt.Sprintf("  %s: {path: '%s'}\n", name, testutil.Install(t, bin, name, *b)))
	}
	f := &fx{dir: dir, cfg: filepath.Join(dir, "config.yaml"), scope: filepath.Join(dir, "scope.yaml")}
	os.WriteFile(f.cfg, []byte(fmt.Sprintf("data_dir: '%s'\nretry: {max: 1, backoff_base: 1ms, backoff_max: 2ms}\n%s", filepath.Join(dir, "data"), tools.String())), 0o600)
	os.WriteFile(f.scope, []byte("include: {domains: [example.test]}\nexclude: {hosts: [admin.example.test]}\n"), 0o600)
	return f
}

func TestVersionHelpAndUsageErrors(t *testing.T) {
	if c, o, _ := run("--version"); c != ExitOK || !strings.Contains(o, "reconflow "+Version) {
		t.Errorf("version: %d %q", c, o)
	}
	if c, o, _ := run("--help"); c != ExitOK || !strings.Contains(o, "Exit codes") {
		t.Errorf("help: %d", c)
	}
	f := newFx(t, nil)
	for name, args := range map[string][]string{
		"no target":        {},
		"url target":       {"-d", "https://example.test", "--config", f.cfg},
		"injection target": {"-d", "example.test;id", "--config", f.cfg},
		"out of scope":     {"-d", "other.org", "--config", f.cfg, "--scope", f.scope},
		"unknown flag":     {"-d", "example.test", "--bogus"},
		"status+passive":   {"-d", "example.test", "--status", "--passive", "--config", f.cfg},
		"missing config":   {"-d", "example.test", "--config", filepath.Join(f.dir, "nope.yaml")},
		"stray args":       {"-d", "example.test", "extra", "--config", f.cfg},
	} {
		if c, _, e := run(args...); c != ExitUsage || e == "" {
			t.Errorf("%s: exit %d stderr %q", name, c, e)
		}
	}
	bad := filepath.Join(f.dir, "bad.yaml")
	os.WriteFile(bad, []byte("concurrency: {global: 0}\nunknown_key: 1\n"), 0o600)
	if c, _, _ := run("-d", "example.test", "--config", bad); c != ExitUsage {
		t.Errorf("invalid config must exit %d, got %d", ExitUsage, c)
	}
}

func TestValidateScopeCommand(t *testing.T) {
	f := newFx(t, nil)
	c, o, _ := run("validate-scope", "--scope", f.scope, "-d", "a.example.test", "https://example.test/x", "admin.example.test", "evilexample.test")
	if c != ExitUsage { // two DENY lines
		t.Errorf("exit %d", c)
	}
	for _, w := range []string{"scope OK", "ALLOW a.example.test", "ALLOW https://example.test/x", "DENY  admin.example.test", "DENY  evilexample.test"} {
		if !strings.Contains(o, w) {
			t.Errorf("missing %q in %s", w, o)
		}
	}
	bad := filepath.Join(f.dir, "bad-scope.yaml")
	os.WriteFile(bad, []byte("include: {}\n"), 0o600)
	if c, _, _ := run("validate-scope", "--scope", bad); c != ExitUsage {
		t.Errorf("empty include must be invalid")
	}
}

func TestStatusAndResumeWithoutRuns(t *testing.T) {
	f := newFx(t, nil)
	if c, o, _ := run("-d", "example.test", "--config", f.cfg, "--status"); c != ExitNoResume || !strings.Contains(o, "No runs") {
		t.Errorf("status: %d %q", c, o)
	}
	if c, _, e := run("-d", "example.test", "--config", f.cfg, "--resume"); c != ExitNoResume || !strings.Contains(e, "no recoverable run") {
		t.Errorf("resume: %d %q", c, e)
	}
}

func TestEndToEndRunNewAllStatusReport(t *testing.T) {
	f := newFx(t, nil)
	c, o, e := run("-d", "example.test", "--config", f.cfg, "--scope", f.scope, "--new", "--all")
	if c != ExitOK {
		t.Fatalf("exit %d\nstdout:%s\nstderr:%s", c, o, e)
	}
	if strings.Contains(o, "\x1b[") {
		t.Error("non-terminal output must not contain escape codes")
	}
	for _, w := range []string{"== Summary ==", "SUCCESS", "Subdomains 2", "no valid baseline", "== Current inventory ==", "subdomain  a.example.test", "Report:", "latest.html"} {
		if !strings.Contains(o, w) {
			t.Errorf("missing %q in output:\n%s", w, o)
		}
	}
	if keep := os.Getenv("RF_KEEP_DIR"); keep != "" { // optional: keep artifacts for manual inspection
		copyTree(t, filepath.Join(f.dir, "data"), keep)
	}
	c, o, _ = run("-d", "example.test", "--config", f.cfg, "--status")
	if c != ExitOK || !strings.Contains(o, "subfinder") || !strings.Contains(o, "checkpoint=done") || !strings.Contains(o, "Status:   success") {
		t.Errorf("status: %d\n%s", c, o)
	}
	c, o, _ = run("report", "-d", "example.test", "--config", f.cfg)
	if c != ExitOK || !strings.Contains(o, "latest.html") {
		t.Errorf("report: %d %s", c, o)
	}
}

func TestExitCodesForPartialAndMissingTools(t *testing.T) {
	f := newFx(t, func(b map[string]*testutil.Behavior) { *b["httpx"] = testutil.Behavior{Exit: 2, Stderr: "usage error"} })
	if c, o, _ := run("-d", "example.test", "--config", f.cfg); c != ExitPartial || !strings.Contains(o, "! httpx: failed") {
		t.Errorf("partial: %d\n%s", c, o)
	}
	g := newFx(t, nil)
	cfg, _ := os.ReadFile(g.cfg)
	var lines []string
	for _, l := range strings.Split(string(cfg), "\n") {
		if i := strings.Index(l, "{path: '"); i >= 0 {
			l = l[:i] + "{path: '" + filepath.Join(g.dir, "nonexistent") + "'}"
		}
		lines = append(lines, l)
	}
	os.WriteFile(g.cfg, []byte(strings.Join(lines, "\n")), 0o600)
	if c, _, e := run("-d", "example.test", "--config", g.cfg); c != ExitMissingDeps || !strings.Contains(e, "reconflow tools") {
		t.Errorf("missing deps: %d %q", c, e)
	}
}

func TestToolsCommand(t *testing.T) {
	f := newFx(t, nil)
	c, o, _ := run("tools", "--config", f.cfg)
	if c != ExitOK || !strings.Contains(o, "6/6 tools usable") || !strings.Contains(o, "available") {
		t.Errorf("%d\n%s", c, o)
	}
}

func copyTree(t *testing.T, src, dst string) {
	filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.HasSuffix(p, ".db-wal") || strings.HasSuffix(p, ".db-shm") {
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		b, _ := os.ReadFile(p)
		os.MkdirAll(filepath.Dir(filepath.Join(dst, rel)), 0o755)
		os.WriteFile(filepath.Join(dst, rel), b, 0o644)
		return nil
	})
}
