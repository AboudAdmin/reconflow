// Package triage separates signal from noise. It classifies URLs, builds a
// "shape" key that collapses parameter/ID explosions, scores what is left and
// derives leads. Everything here is a heuristic over strings: a lead is a
// pointer for a human to check, never a confirmed vulnerability.
package triage

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type Class string

const (
	Static    Class = "static"    // images, fonts, styles, media: never persisted as URLs
	JS        Class = "js"        // .js/.mjs
	SourceMap Class = "sourcemap" // .map
	API       Class = "api"       // API-looking path or data extension
	Page      Class = "page"      // everything else
)

var (
	staticExt = map[string]bool{"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "ico": true, "webp": true, "avif": true,
		"bmp": true, "css": true, "woff": true, "woff2": true, "ttf": true, "otf": true, "eot": true, "mp3": true, "mp4": true, "webm": true,
		"ogg": true, "wav": true, "avi": true, "mov": true}
	apiSeg   = regexp.MustCompile(`(?i)^(api|rest|graphql|gql|v\d+|oauth2?|auth|rpc|ajax|wp-json|_next|trpc|odata|soap|ws)$`)
	sensSeg  = regexp.MustCompile(`(?i)^(admin|administrator|internal|debug|console|actuator|swagger|swagger-ui|openapi|api-docs|graphiql|phpinfo\.php|server-status|\.git|\.svn|\.env|\.htpasswd|backup|backups|dump|phpmyadmin|manager|jenkins|metrics|\.well-known|\.DS_Store)$`)
	sensFile = regexp.MustCompile(`(?i)\.(bak|old|orig|sql|zip|tar|tgz|gz|7z|rar|swp|log|env|config|ini|yml|yaml|pem|key)$`)
	numSeg   = regexp.MustCompile(`^\d+$`)
	uuidSeg  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexSeg   = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	tracking = regexp.MustCompile(`(?i)^(utm_.*|fbclid|gclid|msclkid|mc_cid|mc_eid|_ga|_gl|ref|cb|_|timestamp|ts|nocache|v|ver|version|hash)$`)
	// parameter names that commonly deserve manual attention, with the reason
	interestingParam = map[string]string{
		"redirect": "open-redirect candidate", "redirect_uri": "open-redirect candidate", "return": "open-redirect candidate", "returnurl": "open-redirect candidate",
		"next": "open-redirect candidate", "url": "server-side request candidate", "uri": "server-side request candidate", "dest": "open-redirect candidate",
		"callback": "callback/JSONP candidate", "file": "file-access candidate", "path": "file-access candidate", "filename": "file-access candidate",
		"template": "file-access candidate", "page": "file-inclusion candidate", "include": "file-inclusion candidate", "cmd": "command-injection candidate",
		"exec": "command-injection candidate", "debug": "debug toggle", "token": "credential in URL", "access_token": "credential in URL", "api_key": "credential in URL",
		"apikey": "credential in URL", "key": "credential in URL", "secret": "credential in URL", "password": "credential in URL", "id": "object-reference candidate",
		"user_id": "object-reference candidate", "uid": "object-reference candidate", "q": "reflection/injection candidate", "search": "reflection/injection candidate",
	}
)

func split(raw string) (host, path string, q url.Values, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", nil, false
	}
	return strings.ToLower(u.Host), u.Path, u.Query(), true
}

func ext(path string) string {
	i := strings.LastIndexByte(path, '.')
	if i < 0 || strings.ContainsRune(path[i:], '/') {
		return ""
	}
	return strings.ToLower(path[i+1:])
}

// Classify buckets a URL. Unparseable input is a Page so nothing is lost.
func Classify(raw string) Class {
	_, p, _, ok := split(raw)
	if !ok {
		return Page
	}
	switch e := ext(p); {
	case staticExt[e]:
		return Static
	case e == "js" || e == "mjs":
		return JS
	case e == "map":
		return SourceMap
	case e == "json" || e == "xml" || e == "graphql":
		return API
	}
	for _, s := range strings.Split(strings.ToLower(p), "/") {
		if apiSeg.MatchString(s) {
			return API
		}
	}
	return Page
}

// Shape is the dedup key: scheme dropped, trailing slash dropped, numeric/uuid/hex
// path segments generalised and only parameter NAMES kept (tracking params removed).
func Shape(raw string) string {
	h, p, q, ok := split(raw)
	if !ok {
		return raw
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case numSeg.MatchString(s):
			segs[i] = "{n}"
		case uuidSeg.MatchString(s):
			segs[i] = "{uuid}"
		case hexSeg.MatchString(s):
			segs[i] = "{hex}"
		}
	}
	p = strings.TrimRight(strings.Join(segs, "/"), "/")
	var names []string
	for k := range q {
		if !tracking.MatchString(k) {
			names = append(names, strings.ToLower(k))
		}
	}
	sort.Strings(names)
	s := h + p
	if len(names) > 0 {
		s += "?" + strings.Join(names, "&")
	}
	return s
}

// Sensitive reports the first sensitive-looking path element, if any.
func Sensitive(raw string) string {
	_, p, _, ok := split(raw)
	if !ok {
		return ""
	}
	for _, s := range strings.Split(p, "/") {
		if sensSeg.MatchString(s) {
			return s
		}
	}
	if sensFile.MatchString(p) {
		return "*" + p[strings.LastIndexByte(p, '.'):]
	}
	return ""
}

// InterestingParams returns parameter name -> reason for names worth a look.
func InterestingParams(raw string) map[string]string {
	_, _, q, ok := split(raw)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k := range q {
		if r, ok := interestingParam[strings.ToLower(k)]; ok {
			out[strings.ToLower(k)] = r
		}
	}
	return out
}

// Score ranks a URL for attention (higher = look first). Pure function of the string and origin.
func Score(raw string, c Class, crawled bool) int {
	s := 0
	switch c {
	case API:
		s += 40
	case SourceMap:
		s += 30
	case JS:
		s += 10
	}
	if strings.Contains(strings.ToLower(raw), "graphql") {
		s += 20
	}
	if Sensitive(raw) != "" {
		s += 50
	}
	s += 8 * len(InterestingParams(raw))
	if _, _, q, ok := split(raw); ok && len(q) > 0 {
		s += 5
	}
	if crawled {
		s += 5 // seen live this run, not only in an archive
	}
	return s
}

// Lead is a pointer for manual follow-up. Priority is attention order, not CVSS.
type Lead struct {
	Type     string `json:"type"`
	Priority string `json:"priority"` // high | medium | low
	Title    string `json:"title"`
	Subject  string `json:"subject"`
	Evidence string `json:"evidence"`
	Rule     string `json:"rule"`
	Verified bool   `json:"verified"` // always false: ReconFlow never confirms exploitability
}

// URLLeads derives leads from one URL. historical URLs get a caveat in the evidence.
func URLLeads(raw string, crawled bool) []Lead {
	where := "seen live by the crawler"
	if !crawled {
		where = "from a web archive only; may no longer exist"
	}
	var out []Lead
	c := Classify(raw)
	if s := Sensitive(raw); s != "" {
		pr := "medium"
		if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "*") || s == "actuator" || s == "swagger" || s == "graphiql" || s == "phpinfo.php" || s == "server-status" {
			pr = "high"
		}
		out = append(out, Lead{"sensitive-path", pr, "Sensitive-looking path (" + s + ")", raw, where, "path-keyword", false})
	}
	if c == SourceMap {
		out = append(out, Lead{"sourcemap", "medium", "Source map reference", raw, where, "ext-map", false})
	}
	if strings.Contains(strings.ToLower(raw), "graphql") {
		out = append(out, Lead{"graphql", "medium", "GraphQL endpoint", raw, where, "path-graphql", false})
	}
	for p, why := range InterestingParams(raw) {
		out = append(out, Lead{"parameter", "low", "Parameter \"" + p + "\": " + why, raw, where, "param-name", false})
	}
	return out
}

var techLeads = []struct{ needle, title, pr string }{
	{"jenkins", "Jenkins CI exposed", "high"}, {"grafana", "Grafana exposed", "medium"}, {"kibana", "Kibana exposed", "medium"},
	{"phpmyadmin", "phpMyAdmin exposed", "high"}, {"gitlab", "GitLab instance", "medium"}, {"jira", "Jira instance", "low"},
	{"confluence", "Confluence instance", "low"}, {"tomcat", "Apache Tomcat", "medium"}, {"index of /", "Directory listing", "high"},
	{"swagger ui", "Swagger UI exposed", "high"}, {"sonarqube", "SonarQube exposed", "medium"}, {"rabbitmq", "RabbitMQ management", "medium"},
}

// ServiceLeads inspects a live service's title and technologies.
func ServiceLeads(u, title string, tech []string) []Lead {
	hay := strings.ToLower(title + " " + strings.Join(tech, " "))
	var out []Lead
	for _, t := range techLeads {
		if strings.Contains(hay, t.needle) {
			out = append(out, Lead{"tech", t.pr, t.title, u, "title/tech fingerprint: " + strings.TrimSpace(title), "tech-" + strings.ReplaceAll(t.needle, " ", "-"), false})
		}
	}
	return out
}

// CandidateClass rates a JS-extracted candidate. target is the apex being tested.
func CandidateClass(typ, value, rule, target string) (class string, score int) {
	low := strings.ToLower(value)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "ws") {
		h, _, _, ok := split(value)
		if !ok {
			return "invalid", 0
		}
		h = strings.SplitN(h, ":", 2)[0]
		if h != target && !strings.HasSuffix(h, "."+target) {
			return "thirdparty", 0
		}
		if Classify(value) == Static {
			return "static", 0
		}
		return "inscope", 10 + Score(value, Classify(value), false)
	}
	switch rule {
	case "api-like-path":
		return "api", 60
	case "graphql-path", "graphql-url":
		return "api", 60
	case "quoted-path":
		if Classify(value) == Static {
			return "static", 0
		}
		if strings.Count(value, "/") >= 2 || strings.ContainsAny(value, "?=") {
			return "route", 20
		}
		return "weak", 5 // single bare segment such as "/home": usually an SPA route name
	case "query-param":
		if _, ok := interestingParam[strings.ToLower(value)]; ok {
			return "param", 25
		}
		return "param", 5
	}
	return "other", 10
}
