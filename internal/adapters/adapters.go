// Package adapters describes how each external tool is detected, invoked
// (argument arrays only) and how its output lines become observations.
//
// Flag lists below come from each tool's documented CLI. They are re-verified
// at runtime: Detect fails a tool as "incompatible" if its help text lacks any
// RequiredFlags entry, so a version drift is reported instead of silently run.
package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"reconflow/internal/model"
	"reconflow/internal/normalize"
	"reconflow/internal/runner"
	"reconflow/internal/scope"
)

type Input struct {
	Target    string
	File      string // newline-separated input list written by ReconFlow in the run dir
	Threads   int
	RateLimit int
	Depth     int
	Timeout   time.Duration
}

type Adapter struct {
	Name          string
	Binary        string
	Kind          string // primary entity kind produced
	Passive       bool   // contacts only third-party data sources, never the target
	NeedsFile     bool
	HelpArgs      []string
	VersionArgs   []string
	RequiredFlags []string
	Install       string
	Args          func(Input) []string
	Parse         func(line []byte, in Input) ([]model.Obs, error)
}

type Status string

const (
	Available    Status = "available"
	Missing      Status = "missing"
	Incompatible Status = "incompatible"
)

type Info struct {
	Name, Path, Version string
	Status              Status
	MissingFlags        []string
	Detail, Install     string
}

var versionRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)`)

func probe(ctx context.Context, path string, args []string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var b bytes.Buffer
	res := runner.Run(ctx, runner.Spec{Path: path, Args: args, Timeout: 10 * time.Second, StderrCap: 64 << 10, MaxLine: 64 << 10,
		OnLine: func(l []byte) {
			if b.Len() < 128<<10 {
				b.Write(l)
				b.WriteByte('\n')
			}
		}})
	b.WriteString(res.Stderr)
	return b.String()
}

// Detect locates the binary (explicit path wins), reads its version and checks
// the required flags against its help output.
func (a *Adapter) Detect(ctx context.Context, configured string) Info {
	info := Info{Name: a.Name, Install: a.Install}
	path := configured
	if path == "" {
		p, err := exec.LookPath(a.Binary)
		if err != nil {
			info.Status, info.Detail = Missing, a.Binary+" not found on PATH"
			return info
		}
		path = p
	} else if st, err := os.Stat(path); err != nil || st.IsDir() {
		info.Status, info.Detail = Missing, "configured path not usable: "+path
		return info
	}
	info.Path = path
	help := probe(ctx, path, a.HelpArgs)
	for _, f := range a.RequiredFlags {
		if !strings.Contains(help, f) {
			info.MissingFlags = append(info.MissingFlags, f)
		}
	}
	if len(a.VersionArgs) > 0 {
		if m := versionRe.FindStringSubmatch(probe(ctx, path, a.VersionArgs)); m != nil {
			info.Version = m[1]
		}
	}
	if len(info.MissingFlags) > 0 {
		info.Status = Incompatible
		info.Detail = "help output lacks flags: " + strings.Join(info.MissingFlags, ", ")
		return info
	}
	info.Status = Available
	return info
}

// Transient reports whether a failed execution is worth retrying.
func Transient(stderr string, exit int) bool {
	s := strings.ToLower(stderr)
	for _, w := range []string{"timeout", "temporarily", "connection reset", "connection refused", "too many requests", "429", "rate limit", "eof", "unavailable", "try again"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func Get(name string) *Adapter {
	for _, a := range All() {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func itoa(i int) string { return strconv.Itoa(i) }

func obj(line []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	return m, nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func strs(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case string:
		if x != "" {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func All() []*Adapter {
	return []*Adapter{subfinder(), dnsx(), httpx(), gau(), waybackurls(), katana()}
}

func subfinder() *Adapter {
	return &Adapter{
		Name: "subfinder", Binary: "subfinder", Kind: model.KindSubdomain, Passive: true,
		HelpArgs: []string{"-h"}, VersionArgs: []string{"-version"}, RequiredFlags: []string{"-d", "-silent", "-json"},
		Install: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest  (or: sudo apt install subfinder)",
		Args:    func(in Input) []string { return []string{"-d", in.Target, "-silent", "-json"} },
		Parse: func(line []byte, in Input) ([]model.Obs, error) {
			host := ""
			var meta map[string]any
			if len(line) > 0 && line[0] == '{' {
				m, err := obj(line)
				if err != nil {
					return nil, err
				}
				host = str(m, "host")
				meta = map[string]any{"sources": strs(m["source"])}
			} else {
				host = string(line)
			}
			h, err := scope.NormalizeHost(host)
			if err != nil {
				return nil, err
			}
			return []model.Obs{{Kind: model.KindSubdomain, Key: h, Input: in.Target, Meta: meta}}, nil
		},
	}
}

func dnsx() *Adapter {
	return &Adapter{
		Name: "dnsx", Binary: "dnsx", Kind: model.KindDNS, NeedsFile: true,
		HelpArgs: []string{"-h"}, VersionArgs: []string{"-version"}, RequiredFlags: []string{"-l", "-silent", "-json", "-a", "-resp", "-rl", "-t"},
		Install: "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		Args: func(in Input) []string {
			return []string{"-l", in.File, "-silent", "-json", "-a", "-aaaa", "-cname", "-resp", "-t", itoa(in.Threads), "-rl", itoa(in.RateLimit)}
		},
		Parse: func(line []byte, in Input) ([]model.Obs, error) {
			m, err := obj(line)
			if err != nil {
				return nil, err
			}
			h, err := scope.NormalizeHost(str(m, "host"))
			if err != nil {
				return nil, err
			}
			attrs := map[string]any{}
			for _, k := range []string{"a", "aaaa", "cname"} {
				if v := strs(m[k]); len(v) > 0 {
					attrs[k] = v
				}
			}
			if s := str(m, "status_code"); s != "" {
				attrs["status"] = s
			}
			return []model.Obs{{Kind: model.KindDNS, Key: h, Input: h, Attrs: attrs}}, nil
		},
	}
}

func httpx() *Adapter {
	return &Adapter{
		Name: "httpx", Binary: "httpx", Kind: model.KindService, NeedsFile: true,
		HelpArgs: []string{"-h"}, VersionArgs: []string{"-version"},
		RequiredFlags: []string{"-l", "-silent", "-json", "-status-code", "-title", "-tech-detect", "-web-server", "-rl", "-threads"},
		Install:       "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  (Kali's python 'httpx' CLI is a different tool)",
		Args: func(in Input) []string {
			// Redirects are NOT followed (default); the Location header is recorded instead.
			return []string{"-l", in.File, "-silent", "-json", "-status-code", "-title", "-tech-detect", "-web-server",
				"-threads", itoa(in.Threads), "-rl", itoa(in.RateLimit), "-timeout", itoa(int(in.Timeout.Seconds()))}
		},
		Parse: func(line []byte, in Input) ([]model.Obs, error) {
			m, err := obj(line)
			if err != nil {
				return nil, err
			}
			if f, _ := m["failed"].(bool); f {
				return nil, nil
			}
			u, err := normalize.URL(str(m, "url"))
			if err != nil {
				return nil, err
			}
			attrs := map[string]any{}
			if sc, ok := m["status_code"].(float64); ok {
				attrs["status_code"] = int(sc)
			}
			for _, k := range []string{"title", "webserver", "location"} {
				if s := str(m, k); s != "" {
					attrs[k] = s
				}
			}
			if t := strs(m["tech"]); len(t) > 0 {
				attrs["tech"] = t
			}
			meta := map[string]any{}
			if cl, ok := m["content_length"].(float64); ok {
				meta["content_length"] = int(cl)
			}
			if ip := str(m, "host_ip"); ip != "" {
				meta["ip"] = ip
			}
			return []model.Obs{{Kind: model.KindService, Key: u, Input: str(m, "input"), Attrs: attrs, Meta: meta}}, nil
		},
	}
}

func urlParser(origin string) func([]byte, Input) ([]model.Obs, error) {
	return func(line []byte, in Input) ([]model.Obs, error) {
		u, err := normalize.URL(string(line))
		if err != nil {
			return nil, err
		}
		return []model.Obs{{Kind: model.KindURL, Key: u, Input: in.Target, Meta: map[string]any{"origin": origin}}}, nil
	}
}

func gau() *Adapter {
	return &Adapter{
		Name: "gau", Binary: "gau", Kind: model.KindURL, Passive: true,
		HelpArgs: []string{"-h"}, VersionArgs: []string{"--version"}, RequiredFlags: []string{"--subs", "--threads", "--timeout"},
		Install: "go install github.com/lc/gau/v2/cmd/gau@latest",
		Args: func(in Input) []string {
			return []string{"--subs", "--threads", itoa(in.Threads), "--timeout", itoa(int(in.Timeout.Seconds())), in.Target}
		},
		Parse: urlParser("historical"),
	}
}

func waybackurls() *Adapter {
	return &Adapter{
		Name: "waybackurls", Binary: "waybackurls", Kind: model.KindURL, Passive: true,
		HelpArgs: []string{"-h"}, RequiredFlags: []string{"-no-subs"},
		Install: "go install github.com/tomnomnom/waybackurls@latest",
		Args:    func(in Input) []string { return []string{in.Target} },
		Parse:   urlParser("historical"),
	}
}

func katana() *Adapter {
	return &Adapter{
		Name: "katana", Binary: "katana", Kind: model.KindURL, NeedsFile: true,
		HelpArgs: []string{"-h"}, VersionArgs: []string{"-version"},
		RequiredFlags: []string{"-list", "-silent", "-jsonl", "-d", "-jc", "-fs", "-rl", "-c", "-timeout"},
		Install:       "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		Args: func(in Input) []string {
			// -fs fqdn keeps the crawl on each seed's exact host.
			return []string{"-list", in.File, "-silent", "-jsonl", "-d", itoa(in.Depth), "-jc", "-fs", "fqdn",
				"-rl", itoa(in.RateLimit), "-c", itoa(in.Threads), "-timeout", itoa(int(in.Timeout.Seconds()))}
		},
		Parse: func(line []byte, in Input) ([]model.Obs, error) {
			if len(line) == 0 || line[0] != '{' {
				return urlParser("crawled")(line, in)
			}
			m, err := obj(line)
			if err != nil {
				return nil, err
			}
			req, _ := m["request"].(map[string]any)
			if req == nil {
				return nil, errors.New("katana record without request")
			}
			u, err := normalize.URL(str(req, "endpoint"))
			if err != nil {
				return nil, err
			}
			meta := map[string]any{"origin": "crawled"}
			for _, k := range []string{"method", "tag", "attribute", "source"} {
				if s := str(req, k); s != "" {
					meta[k] = s
				}
			}
			return []model.Obs{{Kind: model.KindURL, Key: u, Input: str(req, "source"), Meta: meta}}, nil
		},
	}
}
