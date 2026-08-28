package network

import (
	"fmt"
	"net"
	"strings"
)

type Profile string

const (
	ProfileStrict Profile = "strict"
	ProfileDev    Profile = "dev"
)

var StrictAllowlist = []string{"api.anthropic.com"}

var DevExtraAllowlist = []string{
	"registry.npmjs.org",
	"pypi.org",
	"files.pythonhosted.org",
	"proxy.golang.org",
	"github.com",
	"codeload.github.com",
	"objects.githubusercontent.com",
	"opencode.ai",
}

var AllowedPorts = map[int]bool{443: true, 80: true}

func AllowlistFor(p Profile) ([]string, error) {
	switch p {
	case ProfileStrict:
		return StrictAllowlist, nil
	case ProfileDev:
		return append(append([]string{}, StrictAllowlist...), DevExtraAllowlist...), nil
	default:
		return nil, fmt.Errorf("unknown network profile %q", p)
	}
}

type Matcher struct {
	entries []string
}

func NewMatcher(entries []string) *Matcher {
	cp := make([]string, 0, len(entries))
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			cp = append(cp, strings.TrimSuffix(e, "."))
		}
	}
	return &Matcher{entries: cp}
}

func (m *Matcher) Match(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	for _, e := range m.entries {
		if host == e || strings.HasSuffix(host, "."+e) {
			return true
		}
	}
	return false
}

func (m *Matcher) Entries() []string { return m.entries }

type Decision struct {
	Domain  string
	IP      string
	Port    int
	Allow   bool
	Reason  string
	RawIP   bool
	Private bool
}

func Evaluate(matcher *Matcher, host string, port int) Decision {
	d := Decision{Domain: host, Port: port}
	if !AllowedPorts[port] {
		d.Reason = fmt.Sprintf("port %d not allowlisted", port)
		return d
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		d.RawIP = true
		d.Reason = "raw IP connections are blocked by policy"
		return d
	}
	if !matcher.Match(host) {
		d.Reason = "domain not in allowlist"
		return d
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		d.Reason = "resolution failed"
		return d
	}
	for _, ip := range ips {
		if isRestricted(ip) {
			d.Private = true
			d.Reason = "resolves to private/loopback/link-local address"
			return d
		}
	}
	d.Allow = true
	d.IP = ips[0].String()
	d.Reason = "allowlisted destination"
	return d
}

func isRestricted(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
