// Package scope validates targets and enforces explicit authorization boundaries.
//
// Rules: default deny; any exclude beats any include; domain rules match the
// apex and subdomains on label boundaries; IP literals only match ip/cidr rules.
package scope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"
)

type ruleSet struct {
	Domains []string `yaml:"domains" json:"domains"`
	Hosts   []string `yaml:"hosts" json:"hosts"`
	IPs     []string `yaml:"ips" json:"ips"`
	CIDRs   []string `yaml:"cidrs" json:"cidrs"`
}

// File is the on-disk scope format.
type File struct {
	Include ruleSet  `yaml:"include" json:"include"`
	Exclude ruleSet  `yaml:"exclude" json:"exclude"`
	Ports   []int    `yaml:"ports" json:"ports"`
	Schemes []string `yaml:"schemes" json:"schemes"`
}

type Policy struct {
	File
	inDomains, inHosts, exDomains, exHosts map[string]bool
	inIPs, exIPs                           []netip.Addr
	inNets, exNets                         []netip.Prefix
	ports                                  map[int]bool
	schemes                                map[string]bool
	Implicit                               bool
}

// NormalizeHost lowercases, strips a trailing dot, converts IDN to punycode
// and validates DNS label syntax. IP literals are returned in canonical form.
func NormalizeHost(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty host")
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		if a.Zone() != "" {
			return "", errors.New("IPv6 zones are not allowed")
		}
		return a.Unmap().String(), nil
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if strings.ContainsAny(s, "/\\@:?#% \t\r\n\x00*") {
		return "", fmt.Errorf("invalid characters in host %q", s)
	}
	a, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("invalid host %q: %v", s, err)
	}
	if len(a) > 253 {
		return "", errors.New("host too long")
	}
	labels := strings.Split(a, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("invalid label in host %q", s)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", fmt.Errorf("invalid character %q in host %q", r, s)
			}
		}
	}
	return a, nil
}

// ParseTarget validates the CLI -d value: a bare registrable-style domain or IP.
func ParseTarget(s string) (string, error) {
	if strings.Contains(s, "://") || strings.ContainsAny(s, "/@?#") {
		return "", fmt.Errorf("target must be a bare hostname or IP (no scheme, path or credentials): %q", s)
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return "", fmt.Errorf("target must not include a port: %q", s)
	}
	h, err := NormalizeHost(s)
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return h, nil
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("target %q needs at least two labels", h)
	}
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return "", fmt.Errorf("target %q has a numeric TLD; not a valid IP either", h)
	}
	return h, nil
}

// Implicit returns the minimal scope implied by `-d target` alone: the target
// and its subdomains (or the single IP) on ports 80/443.
func ImplicitFor(target string) *Policy {
	f := File{}
	if _, err := netip.ParseAddr(target); err == nil {
		f.Include.IPs = []string{target}
	} else {
		f.Include.Domains = []string{target}
	}
	p, _ := compile(f)
	p.Implicit = true
	return p
}

func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse scope %s: %w", path, err)
	}
	return compile(f)
}

func hostSet(in []string) (map[string]bool, error) {
	m := map[string]bool{}
	for _, s := range in {
		h, err := NormalizeHost(s)
		if err != nil {
			return nil, err
		}
		m[h] = true
	}
	return m, nil
}

func addrs(in []string) (out []netip.Addr, err error) {
	for _, s := range in {
		a, e := netip.ParseAddr(strings.TrimSpace(s))
		if e != nil {
			return nil, fmt.Errorf("bad ip %q: %v", s, e)
		}
		out = append(out, a.Unmap())
	}
	return
}

func nets(in []string) (out []netip.Prefix, err error) {
	for _, s := range in {
		p, e := netip.ParsePrefix(strings.TrimSpace(s))
		if e != nil {
			return nil, fmt.Errorf("bad cidr %q: %v", s, e)
		}
		out = append(out, p.Masked())
	}
	return
}

func compile(f File) (*Policy, error) {
	p := &Policy{File: f, ports: map[int]bool{}, schemes: map[string]bool{}}
	var err error
	var errs []error
	chk := func(e error) {
		if e != nil {
			errs = append(errs, e)
		}
	}
	p.inDomains, err = hostSet(f.Include.Domains)
	chk(err)
	p.inHosts, err = hostSet(f.Include.Hosts)
	chk(err)
	p.exDomains, err = hostSet(f.Exclude.Domains)
	chk(err)
	p.exHosts, err = hostSet(f.Exclude.Hosts)
	chk(err)
	p.inIPs, err = addrs(f.Include.IPs)
	chk(err)
	p.exIPs, err = addrs(f.Exclude.IPs)
	chk(err)
	p.inNets, err = nets(f.Include.CIDRs)
	chk(err)
	p.exNets, err = nets(f.Exclude.CIDRs)
	chk(err)
	if len(f.Ports) == 0 {
		f.Ports = []int{80, 443}
	}
	for _, port := range f.Ports {
		if port < 1 || port > 65535 {
			chk(fmt.Errorf("bad port %d", port))
		}
		p.ports[port] = true
	}
	if len(f.Schemes) == 0 {
		f.Schemes = []string{"http", "https"}
	}
	for _, s := range f.Schemes {
		s = strings.ToLower(s)
		if s != "http" && s != "https" && s != "ws" && s != "wss" {
			chk(fmt.Errorf("unsupported scheme %q", s))
		}
		p.schemes[s] = true
	}
	p.File = f
	if len(p.inDomains)+len(p.inHosts)+len(p.inIPs)+len(p.inNets) == 0 && len(errs) == 0 {
		chk(errors.New("scope has no include rules (default deny would block everything)"))
	}
	return p, errors.Join(errs...)
}

func suffixMatch(set map[string]bool, host string) bool {
	for h := host; h != ""; {
		if set[h] {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return false
}

func ipIn(ip netip.Addr, list []netip.Addr, pfx []netip.Prefix) bool {
	for _, a := range list {
		if a == ip {
			return true
		}
	}
	for _, p := range pfx {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowHost reports whether the (already normalizable) host is in scope.
func (p *Policy) AllowHost(host string) (bool, string) {
	h, err := NormalizeHost(host)
	if err != nil {
		return false, "invalid host"
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		if ipIn(ip, p.exIPs, p.exNets) {
			return false, "excluded ip"
		}
		if ipIn(ip, p.inIPs, p.inNets) {
			return true, "ip rule"
		}
		return false, "ip not in scope"
	}
	if p.exHosts[h] || suffixMatch(p.exDomains, h) {
		return false, "excluded host"
	}
	if p.inHosts[h] || suffixMatch(p.inDomains, h) {
		return true, "host rule"
	}
	return false, "not in scope"
}

// IsSpecial reports loopback/private/link-local/metadata/CGNAT/etc addresses.
func IsSpecial(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("192.0.0.0/24").Contains(ip) ||
		netip.MustParsePrefix("198.18.0.0/15").Contains(ip) || netip.MustParsePrefix("240.0.0.0/4").Contains(ip)
}

// AllowConnect decides whether a connection to ip (resolved for host) may be
// made: the name must be in scope, the IP not excluded, and special-purpose
// addresses require an explicit include rule (DNS-rebinding / SSRF guard).
func (p *Policy) AllowConnect(host string, ip netip.Addr) (bool, string) {
	if ok, why := p.AllowHost(host); !ok {
		return false, why
	}
	ip = ip.Unmap()
	if ipIn(ip, p.exIPs, p.exNets) {
		return false, "resolved ip excluded"
	}
	if IsSpecial(ip) && !ipIn(ip, p.inIPs, p.inNets) {
		return false, "resolved to special-purpose address " + ip.String()
	}
	return true, "ok"
}

// AllowURL validates scheme, credentials, host and port.
func (p *Policy) AllowURL(raw string) (bool, string) {
	if strings.ContainsAny(raw, "\x00\r\n\t ") {
		return false, "control characters in url"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false, "unparseable url"
	}
	if !p.schemes[strings.ToLower(u.Scheme)] {
		return false, "scheme not allowed: " + u.Scheme
	}
	if u.User != nil {
		return false, "credentials in url"
	}
	if ok, why := p.AllowHost(u.Hostname()); !ok {
		return false, why
	}
	port := 0
	if ps := u.Port(); ps != "" {
		port, err = strconv.Atoi(ps)
		if err != nil {
			return false, "bad port"
		}
	} else if u.Scheme == "https" || u.Scheme == "wss" {
		port = 443
	} else {
		port = 80
	}
	if !p.ports[port] {
		return false, "port not allowed: " + strconv.Itoa(port)
	}
	return true, "ok"
}

// Hash is a stable digest of the effective rules; used for baseline compatibility.
func (p *Policy) Hash() string {
	f := p.File
	for _, s := range []*[]string{&f.Include.Domains, &f.Include.Hosts, &f.Include.IPs, &f.Include.CIDRs,
		&f.Exclude.Domains, &f.Exclude.Hosts, &f.Exclude.IPs, &f.Exclude.CIDRs, &f.Schemes} {
		c := append([]string(nil), *s...)
		for i := range c {
			c[i] = strings.ToLower(c[i])
		}
		sort.Strings(c)
		*s = c
	}
	f.Ports = append([]int(nil), f.Ports...)
	sort.Ints(f.Ports)
	b, _ := json.Marshal(f)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
