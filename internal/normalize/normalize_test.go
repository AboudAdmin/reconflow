package normalize

import "testing"

func TestURL(t *testing.T) {
	cases := map[string]string{
		"HTTP://Example.COM:80":          "http://example.com/",
		"https://example.com:443/a#frag": "https://example.com/a",
		"https://example.com/a?b=2&a=1":  "https://example.com/a?a=1&b=2",
		"https://example.com:8443/x%2fy": "https://example.com:8443/x%2Fy",
		"https://EXAMPLE.com./":          "https://example.com/",
		"https://bücher.de/ü":            "https://xn--bcher-kva.de/%C3%BC",
		"https://example.com/a%20b":      "https://example.com/a%20b",
		"wss://example.com:443/socket":   "wss://example.com/socket",
	}
	for in, want := range cases {
		got, err := URL(in)
		if err != nil || got != want {
			t.Errorf("URL(%q)=%q,%v want %q", in, got, err, want)
		}
		if again, _ := URL(got); again != got {
			t.Errorf("not idempotent: %q -> %q", got, again)
		}
	}
	for _, bad := range []string{"", "javascript:alert(1)", "ftp://x.com/", "https://u:p@x.com/", "https://x.com/a b", "file:///etc/passwd", "//x.com"} {
		if got, err := URL(bad); err == nil {
			t.Errorf("URL(%q) accepted as %q", bad, got)
		}
	}
	if !IsJS("https://x.com/a/app.min.js?v=1") || IsJS("https://x.com/a.json") || !IsJS("https://x.com/m.MJS") {
		t.Error("IsJS wrong")
	}
}
