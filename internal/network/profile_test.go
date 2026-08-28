package network

import (
	"strings"
	"testing"
)

func TestMatcherExactAndSubdomain(t *testing.T) {
	m := NewMatcher([]string{"api.anthropic.com", "pypi.org"})
	cases := []struct {
		host string
		want bool
	}{
		{"api.anthropic.com", true},
		{"API.ANTHROPIC.COM.", true},
		{"foo.api.anthropic.com", true},
		{"anthropic.com", false},
		{"notapi.anthropic.com.evil.com", false},
		{"pypi.org", true},
		{"files.pypi.org", true},
		{"evil.com", false},
		{"", false},
		{".", false},
	}
	for _, c := range cases {
		if got := m.Match(c.host); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestEvaluateRawIPBlocked(t *testing.T) {
	for _, host := range []string{"1.1.1.1", "[2606:4700:4700::1111]", "127.0.0.1", "10.0.0.5"} {
		d := Evaluate(NewMatcher([]string{"api.anthropic.com"}), host, 443)
		if d.Allow {
			t.Errorf("raw IP %s allowed", host)
		}
		if !d.RawIP || d.Reason == "" {
			t.Errorf("raw IP %s misclassified: %+v", host, d)
		}
	}
}

func TestEvaluateBadPort(t *testing.T) {
	d := Evaluate(NewMatcher([]string{"api.anthropic.com"}), "api.anthropic.com", 22)
	if d.Allow || d.Port != 22 {
		t.Errorf("port 22 mishandled: %+v", d)
	}
}

func TestEvaluateNonAllowlistedDomain(t *testing.T) {
	d := Evaluate(NewMatcher([]string{"api.anthropic.com"}), "evil.com", 443)
	if d.Allow || d.RawIP {
		t.Errorf("evil.com misclassified: %+v", d)
	}
	if !strings.Contains(d.Reason, "allowlist") {
		t.Errorf("reason = %q", d.Reason)
	}
}

func TestEvaluateAllowedDestination(t *testing.T) {
	d := Evaluate(NewMatcher([]string{"api.anthropic.com"}), "api.anthropic.com", 443)
	if !d.Allow {
		t.Fatalf("expected allow, got %+v", d)
	}
	if d.IP == "" {
		t.Error("resolved IP missing")
	}
}

func TestAllowlists(t *testing.T) {
	s, err := AllowlistFor(ProfileStrict)
	if err != nil || len(s) != 1 || s[0] != "api.anthropic.com" {
		t.Fatalf("strict = %v, %v", s, err)
	}
	d, err := AllowlistFor(ProfileDev)
	if err != nil || len(d) <= len(s) {
		t.Fatalf("dev = %v, %v", d, err)
	}
	if _, err := AllowlistFor("yolo"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}
