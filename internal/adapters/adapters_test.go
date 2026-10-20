package adapters

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"reconflow/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.MaybeRunFake()
	os.Exit(m.Run())
}

func parse(t *testing.T, a *Adapter, line string) (key string, n int, err error) {
	obs, err := a.Parse([]byte(line), Input{Target: "example.com"})
	if len(obs) > 0 {
		key = obs[0].Key
	}
	return key, len(obs), err
}

func TestParsers(t *testing.T) {
	cases := []struct {
		tool, line, key string
		n               int
		err             bool
	}{
		{"subfinder", `{"host":"WWW.Example.com","input":"example.com","source":["crtsh","hackertarget"]}`, "www.example.com", 1, false},
		{"subfinder", `api.example.com`, "api.example.com", 1, false},
		{"subfinder", `{"host":"bad host"}`, "", 0, true},
		{"subfinder", `{not json`, "", 0, true},
		{"dnsx", `{"host":"a.example.com","a":["2.2.2.2","1.1.1.1"],"status_code":"NOERROR"}`, "a.example.com", 1, false},
		{"dnsx", `garbage`, "", 0, true},
		{"httpx", `{"url":"https://A.example.com:443","input":"a.example.com","status_code":200,"title":"Hi","tech":["Nginx","PHP"],"webserver":"nginx"}`, "https://a.example.com/", 1, false},
		{"httpx", `{"url":"https://dead.example.com","failed":true}`, "", 0, false},
		{"gau", `https://example.com/a?b=1&a=2#x`, "https://example.com/a?a=2&b=1", 1, false},
		{"waybackurls", `javascript:alert(1)`, "", 0, true},
		{"katana", `{"request":{"method":"GET","endpoint":"https://example.com/app.js","tag":"script","attribute":"src","source":"https://example.com/"}}`, "https://example.com/app.js", 1, false},
		{"katana", `https://example.com/plain`, "https://example.com/plain", 1, false},
		{"katana", `{"response":{}}`, "", 0, true},
	}
	for _, c := range cases {
		k, n, err := parse(t, Get(c.tool), c.line)
		if k != c.key || n != c.n || (err != nil) != c.err {
			t.Errorf("%s %q => key=%q n=%d err=%v", c.tool, c.line, k, n, err)
		}
	}
}

func TestDNSAttrsAreSortedForStableHash(t *testing.T) {
	a, _ := Get("dnsx").Parse([]byte(`{"host":"a.example.com","a":["2.2.2.2","1.1.1.1"]}`), Input{})
	b, _ := Get("dnsx").Parse([]byte(`{"host":"a.example.com","a":["1.1.1.1","2.2.2.2"]}`), Input{})
	if a[0].Attrs["a"].([]string)[0] != b[0].Attrs["a"].([]string)[0] {
		t.Fatal("A records must be order-insensitive")
	}
}

func TestArgsAreStructuredAndPassiveFlags(t *testing.T) {
	in := Input{Target: "ex.com;rm -rf /", File: "/tmp/in", Threads: 5, RateLimit: 7, Depth: 2, Timeout: 30 * time.Second}
	for _, a := range All() {
		args := a.Args(in)
		for _, x := range args {
			if strings.Contains(x, " ") && x != in.Target {
				t.Errorf("%s: unexpected arg with space %q", a.Name, x)
			}
		}
	}
	if !Get("subfinder").Passive || !Get("gau").Passive || !Get("waybackurls").Passive {
		t.Error("archive/passive-source tools must be passive")
	}
	for _, n := range []string{"dnsx", "httpx", "katana"} {
		if Get(n).Passive {
			t.Errorf("%s contacts the target and must not be passive", n)
		}
	}
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	a := Get("subfinder")
	if i := a.Detect(ctx, dir+"/nope"); i.Status != Missing {
		t.Errorf("want missing: %+v", i)
	}
	ok := testutil.Install(t, dir, "subfinder", testutil.Behavior{Help: "Flags: -d domain -silent -json", Version: "Current Version: v2.6.3"})
	i := a.Detect(ctx, ok)
	if i.Status != Available || i.Version != "2.6.3" {
		t.Errorf("want available v2.6.3: %+v", i)
	}
	d2 := t.TempDir()
	bad := testutil.Install(t, d2, "subfinder", testutil.Behavior{Help: "Flags: -d domain", Version: "v1.0.0"})
	if i := a.Detect(ctx, bad); i.Status != Incompatible || len(i.MissingFlags) != 2 {
		t.Errorf("want incompatible: %+v", i)
	}
}

func TestTransient(t *testing.T) {
	if !Transient("dial tcp: connection reset by peer", 1) || !Transient("HTTP 429 Too Many Requests", 1) || Transient("flag provided but not defined: -x", 2) {
		t.Fatal("transient classification wrong")
	}
}
