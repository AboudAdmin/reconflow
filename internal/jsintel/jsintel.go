// Package jsintel safely downloads in-scope JavaScript, stores it by SHA-256
// and extracts static candidates.
//
// LIMITATION: extraction is regex/heuristic over quoted string literals and
// banner comments. It is not a JavaScript parser; it misses dynamically built
// strings, can match dead code, and every result is an UNVERIFIED candidate.
package jsintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"reconflow/internal/model"
	"reconflow/internal/scope"
	"reconflow/internal/storage"
)

const (
	AnalyzerName    = "reconflow-regex"
	AnalyzerVersion = "1"
	RulesVersion    = "1"
	MaxCandidates   = 5000
)

var (
	literalRe = regexp.MustCompile("\"((?:[^\"\\\\\\n]|\\\\.){1,500})\"|'((?:[^'\\\\\\n]|\\\\.){1,500})'|`([^`\\\\]{1,500})`")
	paramRe   = regexp.MustCompile(`[?&]([A-Za-z_][A-Za-z0-9_.\-]{0,39})=`)
	mapRe     = regexp.MustCompile(`//[#@]\s*sourceMappingURL=([^\s'"]{1,300})`)
	apiPath   = regexp.MustCompile(`(?i)/(api|rest|graphql|gql|v\d+|oauth|auth|admin|internal|ajax|rpc)(/|$|\?)`)
	staticExt = regexp.MustCompile(`(?i)\.(png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|map|mp[34]|webm|pdf)(\?|$)`)
	libRe     = regexp.MustCompile(`(?i)\b(jquery|react|vue|angular|lodash|underscore|moment|axios|bootstrap|backbone|d3|three)(?:\.js)?(?: javascript library| core)?[ @/v-]{1,3}v?(\d+\.\d+(?:\.\d+)?)`)
)

// ConfigHash identifies analysis-relevant configuration for the cache key.
func ConfigHash() string { return fmt.Sprintf("max=%d", MaxCandidates) }

// Analyze extracts candidates from JS bytes. Output is deduplicated and sorted.
func Analyze(content []byte) []storage.Candidate {
	seen := map[string]bool{}
	var out []storage.Candidate
	add := func(typ, val, rule string) {
		val = strings.ToValidUTF8(strings.TrimSpace(val), "")
		k := typ + "\x00" + val + "\x00" + rule
		if val == "" || seen[k] || len(out) >= MaxCandidates {
			return
		}
		seen[k] = true
		out = append(out, storage.Candidate{Type: typ, Value: val, Rule: rule, Verification: model.VerifStatic})
	}
	for _, m := range literalRe.FindAllSubmatch(content, -1) {
		var s string
		for _, g := range m[1:] {
			if len(g) > 0 {
				s = string(g)
			}
		}
		s = strings.TrimRight(s, ",;")
		low := strings.ToLower(s)
		switch {
		case strings.HasPrefix(low, "ws://") || strings.HasPrefix(low, "wss://"):
			add(model.CandWebSocket, s, "ws-url")
		case strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://"):
			add(model.CandURL, s, "absolute-url")
			if strings.Contains(low, "graphql") {
				add(model.CandGraphQL, s, "graphql-url")
			}
		case strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") && len(s) >= 3 && len(s) <= 300 &&
			!strings.ContainsAny(s, " \t<>{}()*") && regexp.MustCompile(`[A-Za-z]`).MatchString(s) && !staticExt.MatchString(s):
			rule := "quoted-path"
			if apiPath.MatchString(s) {
				rule = "api-like-path"
			}
			add(model.CandEndpoint, s, rule)
			if strings.Contains(low, "graphql") {
				add(model.CandGraphQL, s, "graphql-path")
			}
		}
		if strings.ContainsAny(s, "?&") && strings.Contains(s, "=") && (strings.HasPrefix(s, "/") || strings.HasPrefix(low, "http") || s[0] == '?' || s[0] == '&') {
			for _, p := range paramRe.FindAllStringSubmatch(s, -1) {
				add(model.CandParam, p[1], "query-param")
			}
		}
	}
	for _, m := range mapRe.FindAllSubmatch(content, -1) {
		add(model.CandSourceMap, string(m[1]), "sourcemap-comment") // recorded only, never fetched
	}
	for _, m := range libRe.FindAllSubmatch(content, -1) {
		add(model.CandLibrary, strings.ToLower(string(m[1]))+" "+string(m[2]), "library-banner")
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func SHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Store writes content to dir/<sha>.js atomically (temp file + rename).
// An existing file with the same hash is left untouched.
func Store(dir, sha string, body []byte) (string, error) {
	if !hexRe.MatchString(sha) {
		return "", errors.New("invalid hash")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, sha+".js")
	if st, err := os.Lstat(dst); err == nil {
		if !st.Mode().IsRegular() {
			return "", errors.New("refusing to overwrite non-regular file")
		}
		return dst, nil
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(body); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return dst, os.Rename(tmp, dst)
}

type Fetched struct {
	Body        []byte
	Status      int
	ContentType string
}

type Fetcher struct {
	pol      *scope.Policy
	max      int64
	client   *http.Client
	Resolver interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
}

func NewFetcher(pol *scope.Policy, maxBytes int64, timeout time.Duration) *Fetcher {
	f := &Fetcher{pol: pol, max: maxBytes, Resolver: net.DefaultResolver}
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Proxy:                 nil, // never inherit proxy settings from the environment
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   2,
		DisableCompression:    false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var ips []netip.Addr
			if ip, err := netip.ParseAddr(host); err == nil {
				ips = []netip.Addr{ip}
			} else if ips, err = f.Resolver.LookupNetIP(ctx, "ip", host); err != nil {
				return nil, err
			}
			var last error
			for _, ip := range ips {
				// Validate the exact address we connect to: defeats DNS rebinding between check and use.
				if ok, why := pol.AllowConnect(host, ip); !ok {
					last = fmt.Errorf("blocked by scope: %s", why)
					continue
				}
				c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			if last == nil {
				last = errors.New("no addresses")
			}
			return nil, last
		},
	}
	f.client = &http.Client{
		Transport: tr, Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return errors.New("too many redirects")
			}
			if ok, why := pol.AllowURL(req.URL.String()); !ok {
				return fmt.Errorf("redirect out of scope: %s", why)
			}
			return nil
		},
	}
	return f
}

func okType(ct string) bool {
	if ct == "" {
		return true
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return strings.Contains(mt, "javascript") || strings.Contains(mt, "ecmascript") || mt == "text/plain" || mt == "application/octet-stream"
}

// Fetch retrieves one in-scope JS URL under size, type and redirect limits.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (*Fetched, error) {
	if ok, why := f.pol.AllowURL(rawURL); !ok {
		return nil, fmt.Errorf("out of scope: %s", why)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ReconFlow/0.1")
	req.Header.Set("Accept", "application/javascript, text/javascript, */*;q=0.1")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !okType(ct) {
		return nil, fmt.Errorf("unexpected content-type %q", ct)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		return nil, fmt.Errorf("unsupported content-encoding %q", enc) // gzip is decoded and the header removed by net/http
	}
	if resp.ContentLength > f.max {
		return nil, fmt.Errorf("oversized: %d > %d bytes", resp.ContentLength, f.max)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > f.max {
		return nil, fmt.Errorf("oversized: > %d bytes", f.max)
	}
	return &Fetched{Body: body, Status: resp.StatusCode, ContentType: ct}, nil
}
