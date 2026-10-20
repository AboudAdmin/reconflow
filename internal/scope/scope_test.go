package scope

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseTarget(t *testing.T) {
	good := map[string]string{"Example.COM": "example.com", "example.com.": "example.com", "bücher.de": "xn--bcher-kva.de", "10.0.0.1": "10.0.0.1"}
	for in, want := range good {
		got, err := ParseTarget(in)
		if err != nil || got != want {
			t.Errorf("ParseTarget(%q)=%q,%v want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "https://example.com", "example.com/path", "user@example.com", "example.com:8080", "localhost", "a b.com", "-a.com", "a..com", "example.com;id", "$(id).com", "1.2.3"} {
		if _, err := ParseTarget(in); err == nil {
			t.Errorf("ParseTarget(%q) should fail", in)
		}
	}
}

func mustPolicy(t *testing.T, yml string) *Policy {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.yaml")
	os.WriteFile(p, []byte(yml), 0o600)
	pol, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func TestHostMatchingAndPrecedence(t *testing.T) {
	p := mustPolicy(t, `
include: {domains: [example.com], hosts: [other.org], cidrs: ["203.0.113.0/24"]}
exclude: {domains: [corp.example.com], hosts: [www.example.com], ips: ["203.0.113.9"]}
`)
	cases := map[string]bool{
		"example.com": true, "a.b.example.com": true, "EXAMPLE.com.": true,
		"evilexample.com": false, "example.com.evil.com": false, // label boundary
		"corp.example.com": false, "x.corp.example.com": false, "www.example.com": false,
		"other.org": true, "sub.other.org": false, // hosts are exact
		"203.0.113.5": true, "203.0.113.9": false, "198.51.100.1": false, "": false,
	}
	for h, want := range cases {
		if got, why := p.AllowHost(h); got != want {
			t.Errorf("AllowHost(%q)=%v (%s) want %v", h, got, why, want)
		}
	}
}

func TestAllowURL(t *testing.T) {
	p := mustPolicy(t, "include: {domains: [example.com]}\nports: [80, 443, 8443]\n")
	cases := map[string]bool{
		"https://a.example.com/x.js": true, "http://example.com:80/": true, "https://example.com:8443/": true,
		"https://example.com:9999/": false, "ftp://example.com/": false, "file:///etc/passwd": false,
		"https://user:pw@example.com/": false, "https://evil.com/?u=example.com": false,
		"https://example.com@evil.com/": false, "https://evil.com\n.example.com/": false, "//example.com/x": false,
	}
	for u, want := range cases {
		if got, why := p.AllowURL(u); got != want {
			t.Errorf("AllowURL(%q)=%v (%s) want %v", u, got, why, want)
		}
	}
}

func TestAllowConnectSpecialAddresses(t *testing.T) {
	p := mustPolicy(t, "include: {domains: [example.com], cidrs: [\"10.1.0.0/16\"]}\nexclude: {ips: [\"198.51.100.7\"]}\n")
	cases := []struct {
		ip   string
		want bool
	}{
		{"93.184.216.34", true}, {"127.0.0.1", false}, {"169.254.169.254", false}, {"10.2.0.1", false},
		{"10.1.2.3", true}, {"::1", false}, {"::ffff:127.0.0.1", false}, {"100.64.1.1", false}, {"198.51.100.7", false},
	}
	for _, c := range cases {
		if got, why := p.AllowConnect("a.example.com", netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("AllowConnect(%s)=%v (%s) want %v", c.ip, got, why, c.want)
		}
	}
	if ok, _ := p.AllowConnect("evil.com", netip.MustParseAddr("93.184.216.34")); ok {
		t.Error("out-of-scope name must be denied")
	}
}

func TestLoadErrorsAndHash(t *testing.T) {
	for _, y := range []string{"include: {}\n", "include: {cidrs: [\"1.2.3.4/99\"]}\n", "bogus: 1\n", "include: {domains: [\"bad host\"]}\n",
		"include: {domains: [a.com]}\nports: [70000]\n"} {
		p := filepath.Join(t.TempDir(), "s.yaml")
		os.WriteFile(p, []byte(y), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("expected error for %q", y)
		}
	}
	a := mustPolicy(t, "include: {domains: [b.com, a.com]}\n")
	b := mustPolicy(t, "include: {domains: [A.com, b.com]}\n")
	c := mustPolicy(t, "include: {domains: [a.com]}\n")
	if a.Hash() != b.Hash() || a.Hash() == c.Hash() {
		t.Error("hash must be order/case-insensitive and rule-sensitive")
	}
	if ok, _ := ImplicitFor("example.com").AllowHost("x.example.com"); !ok {
		t.Error("implicit scope should include subdomains")
	}
}
