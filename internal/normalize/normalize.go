// Package normalize canonicalizes URLs so equal resources deduplicate to one key.
package normalize

import (
	"errors"
	"net/url"
	"sort"
	"strings"

	"reconflow/internal/scope"
)

// URL returns the canonical form: lowercase scheme/host (punycode), default
// port removed, fragment dropped, empty path -> "/", path re-escaped, query
// pairs sorted by (key,value). Credentials and non-web schemes are rejected.
func URL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n\t ") {
		return "", errors.New("empty or contains control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https", "ws", "wss":
	default:
		return "", errors.New("unsupported scheme " + u.Scheme)
	}
	if u.User != nil {
		return "", errors.New("credentials in url")
	}
	host, err := scope.NormalizeHost(u.Hostname())
	if err != nil {
		return "", err
	}
	port := u.Port()
	if (port == "80" && (u.Scheme == "http" || u.Scheme == "ws")) || (port == "443" && (u.Scheme == "https" || u.Scheme == "wss")) {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	path = upperPercent(path) // %2f must stay %2F, never become '/'
	if path == "" {
		path = "/"
	}
	out := u.Scheme + "://" + host + path
	if u.RawQuery != "" {
		parts := strings.Split(u.RawQuery, "&")
		sort.Strings(parts)
		out += "?" + strings.Join(parts, "&")
	}
	return out, nil
}

// IsJS reports whether the URL path looks like a JavaScript file.
func IsJS(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs")
}

// Params returns query parameter names of a URL.
func Params(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var n []string
	for k := range u.Query() {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func upperPercent(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			for j := i + 1; j <= i+2; j++ {
				if b[j] >= 'a' && b[j] <= 'f' {
					b[j] -= 32
				}
			}
			i += 2
		}
	}
	return string(b)
}
