package egress

import (
	"regexp"
	"strings"
)

// Redactor strips sensitive content from data before it flows outside the sandbox.
// This is advisory in v1 — actual enforcement requires TLS interception (v2).
type Redactor struct {
	patterns []redactPattern
}

type redactPattern struct {
	re      *regexp.Regexp
	replace string
}

// DefaultRedactor returns a redactor that strips common secret patterns.
func DefaultRedactor() *Redactor {
	r := &Redactor{}
	r.AddPattern(`(?i)(AKIA[0-9A-Z]{16})`, "[REDACTED_AWS_KEY]")
	r.AddPattern(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA )?PRIVATE KEY-----`, "[REDACTED_PRIVATE_KEY]")
	r.AddPattern(`(?i)(ghp_[a-zA-Z0-9]{36})`, "[REDACTED_GITHUB_TOKEN]")
	r.AddPattern(`(?i)(github_pat_[a-zA-Z0-9_]{82})`, "[REDACTED_GITHUB_PAT]")
	r.AddPattern(`(?i)(sk-[a-zA-Z0-9]{20,})`, "[REDACTED_OPENAI_KEY]")
	r.AddPattern(`(?i)(xox[bpsa]-[a-zA-Z0-9-]+)`, "[REDACTED_SLACK_TOKEN]")
	r.AddPattern(`(?i)(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)`, "[REDACTED_JWT]")
	return r
}

// AddPattern adds a regex-based redaction rule.
func (r *Redactor) AddPattern(pattern, replacement string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return
	}
	r.patterns = append(r.patterns, redactPattern{re: re, replace: replacement})
}

// Redact applies all redaction rules to the input and returns the cleaned text.
// Returns the original string if no patterns match.
func (r *Redactor) Redact(input string) string {
	result := input
	for _, p := range r.patterns {
		result = p.re.ReplaceAllString(result, p.replace)
	}
	return result
}

// RedactBytes is a convenience wrapper for byte-level input.
func (r *Redactor) RedactBytes(input []byte) []byte {
	return []byte(r.Redact(string(input)))
}

// Minimizer reduces context to the minimum needed for the agent to function.
// This is the "context minimization" interface from the spec.
type Minimizer struct {
	maxFileSize int
	maxLines    int
	excludeExts []string
}

// DefaultMinimizer returns a minimizer suitable for AEGIS v1.
func DefaultMinimizer() *Minimizer {
	return &Minimizer{
		maxFileSize: 1024 * 1024, // 1MB
		maxLines:    500,
		excludeExts: []string{".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".jpg", ".png", ".gif", ".mp4", ".zip", ".tar", ".gz"},
	}
}

// ShouldExclude returns true if the file should not be sent as context.
func (m *Minimizer) ShouldExclude(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range m.excludeExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// Minimize reduces content to the maximum allowed size.
// Returns the trimmed content and whether it was truncated.
func (m *Minimizer) Minimize(content []byte) ([]byte, bool) {
	if len(content) > m.maxFileSize {
		return content[:m.maxFileSize], true
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) > m.maxLines {
		truncated := lines[:m.maxLines]
		truncated = append(truncated, "\n... [truncated by AEGIS context minimizer]")
		return []byte(strings.Join(truncated, "\n")), true
	}

	return content, false
}

// ContextMinimizer is the interface that the egress layer exposes to other components.
// It combines classification, minimization, and redaction into a single pipeline.
type ContextMinimizer struct {
	policy    *ContextPolicy
	minimizer *Minimizer
	redactor  *Redactor
}

// NewContextMinimizer creates a fully-configured context processing pipeline.
func NewContextMinimizer() *ContextMinimizer {
	return &ContextMinimizer{
		policy:    DefaultPolicy(),
		minimizer: DefaultMinimizer(),
		redactor:  DefaultRedactor(),
	}
}

// ProcessResult contains the output of the context processing pipeline.
type ProcessResult struct {
	Classification Classification
	ContextType    ContextType
	Content        []byte
	Redacted       bool
	Minimized      bool
	Excluded       bool
}

// Process classifies, minimizes, and redacts content for safe external flow.
// This is advisory in v1 — the proxy enforces connection-level controls.
func (cm *ContextMinimizer) Process(path string, content []byte) ProcessResult {
	result := ProcessResult{
		Classification: cm.policy.Classify(path, content),
		ContextType:    cm.policy.ClassifyContext(path),
		Content:        content,
	}

	if cm.minimizer.ShouldExclude(path) {
		result.Excluded = true
		result.Content = nil
		return result
	}

	if result.Classification == ClassBlocked || result.Classification == ClassSensitive {
		result.Content = cm.redactor.RedactBytes(content)
		result.Redacted = true
	}

	minimized, wasMin := cm.minimizer.Minimize(result.Content)
	result.Content = minimized
	result.Minimized = wasMin

	return result
}
