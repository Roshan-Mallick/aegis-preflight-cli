package exitgate

import (
	"regexp"
	"strings"
)

// redactedMarker replaces any recognizable secret material before it can reach
// the model prompt, the fix request, or the terminal.
const redactedMarker = "[REDACTED]"

var secretPatterns = []*regexp.Regexp{
	// Generic prefixed API keys (sk-, pk-, ak-, rk-, legacy OpenAI/Anthropic).
	regexp.MustCompile(`(?i)\b(sk|pk|ak|rk)-[A-Za-z0-9_\-]{12,}`),
	// AWS access key ids.
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	// GitHub fine-grained / PAT / OAuth tokens.
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
	// GitLab personal access tokens.
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`),
	// Slack bot / app / user tokens.
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`),
	// Telegram bot tokens.
	regexp.MustCompile(`\bbot[0-9]{6,}:[A-Za-z0-9_\-]{20,}\b`),
	// Google API keys.
	regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{30,}\b`),
	// Credential-valued assignments: key=value or key: value.
	regexp.MustCompile(`(?i)\b(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd|secret|token)\b["']?\s*[:=]\s*["']?[A-Za-z0-9_\-./+]{8,}`),
	// PEM/OpenSSH private key begin markers.
	regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
	// Authorization / Bearer headers.
	regexp.MustCompile(`(?i)\b(Bearer)\s+[A-Za-z0-9_\-.]{10,}`),
	// URLs embedding user:password@.
	regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@`),
}

// Redact replaces recognizable secret material in s with a marker. Empty
// inputs are returned untouched.
func Redact(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, re := range secretPatterns {
		out = re.ReplaceAllString(out, redactedMarker)
	}
	return out
}

// HasRedaction reports whether Redact would change s.
func HasRedaction(s string) bool {
	return Redact(s) != s
}

// RedactCredentials redacts every slice element in place (a new slice is
// returned; the input is not modified).
func RedactCredentials(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = Redact(s)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n-1]) + "…"
}

func stripNewlines(s string) string {
	return strings.Join(strings.Fields(s), " ")
}