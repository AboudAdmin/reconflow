package triage

import "testing"

func TestClassify(t *testing.T) {
	for u, want := range map[string]Class{
		"https://a.example.com/logo.PNG?v=2":      Static,
		"https://a.example.com/fonts/x.woff2":     Static,
		"https://a.example.com/app.js":            JS,
		"https://a.example.com/app.js.map":        SourceMap,
		"https://a.example.com/api/v1/users":      API,
		"https://a.example.com/data.json":         API,
		"https://a.example.com/_next/data/x.json": API,
		"https://a.example.com/about":             Page,
		"https://a.example.com/dir.v2/about":      Page, // dot in a directory is not an extension
	} {
		if got := Classify(u); got != want {
			t.Errorf("Classify(%s)=%s want %s", u, got, want)
		}
	}
}

func TestShapeCollapsesVariants(t *testing.T) {
	same := [][2]string{
		{"https://a.com/item?id=1", "http://a.com/item?id=999"},
		{"https://a.com/u/123/posts", "https://a.com/u/987654/posts/"},
		{"https://a.com/x?utm_source=a&q=1", "https://a.com/x?q=2&fbclid=z"},
		{"https://a.com/o/550e8400-e29b-41d4-a716-446655440000", "https://a.com/o/123e4567-e89b-12d3-a456-426614174000"},
	}
	for _, p := range same {
		if Shape(p[0]) != Shape(p[1]) {
			t.Errorf("shapes differ: %s vs %s", Shape(p[0]), Shape(p[1]))
		}
	}
	if Shape("https://a.com/item?id=1") == Shape("https://a.com/item?name=1") {
		t.Error("different parameter names must keep distinct shapes")
	}
	if Shape("https://a.com/v1/users") == Shape("https://a.com/v2/users") {
		t.Error("version segments are not IDs")
	}
}

func TestLeadsAndScore(t *testing.T) {
	ls := URLLeads("https://a.com/actuator/env?redirect=/x", true)
	types := map[string]bool{}
	for _, l := range ls {
		types[l.Type] = true
		if l.Verified {
			t.Error("leads must never be marked verified")
		}
	}
	if !types["sensitive-path"] || !types["parameter"] {
		t.Errorf("missing leads: %+v", ls)
	}
	if Score("https://a.com/api/x", API, true) <= Score("https://a.com/about", Page, true) {
		t.Error("API must outrank a plain page")
	}
	if len(URLLeads("https://a.com/about", true)) != 0 {
		t.Error("plain page must yield no leads")
	}
}

func TestServiceLeads(t *testing.T) {
	if l := ServiceLeads("https://ci.a.com", "Dashboard [Jenkins]", nil); len(l) != 1 || l[0].Priority != "high" {
		t.Errorf("jenkins: %+v", l)
	}
	if l := ServiceLeads("https://a.com", "Welcome", []string{"nginx"}); len(l) != 0 {
		t.Errorf("unexpected: %+v", l)
	}
}

func TestCandidateClass(t *testing.T) {
	for _, c := range []struct{ typ, v, rule, want string }{
		{"url", "https://www.w3.org/2000/svg", "absolute-url", "thirdparty"},
		{"url", "https://api.a.com/v1/x", "absolute-url", "inscope"},
		{"endpoint", "/api/users", "api-like-path", "api"},
		{"endpoint", "/home", "quoted-path", "weak"},
		{"endpoint", "/a/b", "quoted-path", "route"},
		{"endpoint", "/img/a.png", "quoted-path", "static"},
	} {
		if got, _ := CandidateClass(c.typ, c.v, c.rule, "a.com"); got != c.want {
			t.Errorf("%s: got %s want %s", c.v, got, c.want)
		}
	}
}
