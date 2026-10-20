package jsintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reconflow/internal/scope"
)

const sample = `/*! jQuery v3.6.0 | (c) OpenJS */
var a="/api/v1/users?id=1&sort=asc",b='https://api.example.com/graphql',c="wss://ws.example.com/socket",
d="/static/logo.png",e="/dashboard/settings";fetch(a);var x=cond?q=1:2;var big="` + "\x00" + `";
//# sourceMappingURL=app.js.map
`

func TestAnalyze(t *testing.T) {
	got := map[string]bool{}
	for _, c := range Analyze([]byte(sample)) {
		got[c.Type+"|"+c.Value] = true
		if c.Verification != "static_unverified" {
			t.Errorf("candidate must be unverified: %+v", c)
		}
	}
	for _, w := range []string{"endpoint|/api/v1/users?id=1&sort=asc", "parameter|id", "parameter|sort", "graphql|https://api.example.com/graphql",
		"websocket|wss://ws.example.com/socket", "endpoint|/dashboard/settings", "sourcemap_ref|app.js.map", "library|jquery 3.6.0", "url|https://api.example.com/graphql"} {
		if !got[w] {
			t.Errorf("missing candidate %s (have %v)", w, got)
		}
	}
	for _, bad := range []string{"endpoint|/static/logo.png", "parameter|q"} {
		if got[bad] {
			t.Errorf("false positive %s", bad)
		}
	}
	if len(Analyze([]byte("\xff\xfe garbage \x00\x01 ((("))) != 0 || len(Analyze(nil)) != 0 {
		t.Error("malformed input must yield no candidates and not panic")
	}
	a, b := Analyze([]byte(sample)), Analyze([]byte(sample))
	if len(a) != len(b) {
		t.Error("deterministic")
	}
}

func TestSHAAndStore(t *testing.T) {
	if SHA256([]byte("abc")) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("sha256 wrong")
	}
	dir := t.TempDir()
	sha := SHA256([]byte("x"))
	p1, err := Store(dir, sha, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := Store(dir, sha, []byte("DIFFERENT")) // same hash: existing content must be preserved
	b, _ := os.ReadFile(p2)
	if p1 != p2 || string(b) != "x" {
		t.Fatalf("store not idempotent: %q", b)
	}
	if _, err := Store(dir, "../../etc/passwd", []byte("x")); err == nil {
		t.Error("non-hash names must be rejected")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("temp files leaked: %v", ents)
	}
	_ = filepath.Join
}

func policyFor(t *testing.T, srvURL string, extra string) *scope.Policy {
	u, _ := url.Parse(srvURL)
	y := "include: {hosts: [\"127.0.0.1\"], cidrs: [\"127.0.0.0/8\"]}\nports: [" + u.Port() + "]\n" + extra
	p := filepath.Join(t.TempDir(), "s.yaml")
	os.WriteFile(p, []byte(y), 0o600)
	pol, err := scope.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func TestFetchPolicies(t *testing.T) {
	big := strings.Repeat("a", 2000)
	mux := http.NewServeMux()
	mux.HandleFunc("/ok.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte("var a='/api/x';"))
	})
	mux.HandleFunc("/gz.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Content-Encoding", "gzip")
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Write([]byte("var z=1;"))
		zw.Close()
		w.Write(b.Bytes())
	})
	mux.HandleFunc("/page.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>"))
	})
	mux.HandleFunc("/big.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(big))
	})
	mux.HandleFunc("/redir.js", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://evil.example.net/x.js", 302) })
	mux.HandleFunc("/slow.js", func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	f := NewFetcher(policyFor(t, srv.URL, ""), 1000, 500*time.Millisecond)
	ctx := context.Background()
	if r, err := f.Fetch(ctx, srv.URL+"/ok.js"); err != nil || string(r.Body) != "var a='/api/x';" {
		t.Fatalf("ok: %v", err)
	}
	if r, err := f.Fetch(ctx, srv.URL+"/gz.js"); err != nil || string(r.Body) != "var z=1;" {
		t.Fatalf("gzip transparently decoded: %v %v", r, err)
	}
	for path, want := range map[string]string{"/page.js": "content-type", "/big.js": "oversized", "/redir.js": "out of scope", "/slow.js": "", "/missing.js": "404"} {
		_, err := f.Fetch(ctx, srv.URL+path)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want error containing %q, got %v", path, want, err)
		}
	}
	if _, err := f.Fetch(ctx, "http://evil.example.net/a.js"); err == nil || !strings.Contains(err.Error(), "out of scope") {
		t.Errorf("third-party JS must not be fetched: %v", err)
	}
}

func TestFetchBlocksSpecialAddressWithoutExplicitCIDR(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	// Name rule matches 127.0.0.1 but no CIDR authorises loopback -> blocked at dial time.
	p := filepath.Join(t.TempDir(), "s.yaml")
	os.WriteFile(p, []byte("include: {ips: [\"198.51.100.1\"], hosts: [\"localhost\"]}\nports: ["+u.Port()+"]\n"), 0o600)
	pol, err := scope.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	f := NewFetcher(pol, 1000, time.Second)
	_, err = f.Fetch(context.Background(), "http://localhost:"+u.Port()+"/a.js")
	if err == nil || !strings.Contains(err.Error(), "special-purpose") {
		t.Fatalf("expected special-purpose block, got %v", err)
	}
}
