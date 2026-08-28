package egress

import (
	"regexp"
	"strings"
)

// Classification represents the egress policy decision for a piece of data.
type Classification string

const (
	ClassAllowed   Classification = "ALLOWED"
	ClassBlocked   Classification = "BLOCKED"
	ClassSensitive Classification = "SENSITIVE"
	ClassRedacted  Classification = "REDACTED"
)

// ContextType describes what kind of data is being evaluated.
type ContextType string

const (
	ContextSourceCode    ContextType = "source_code"
	ContextDependency    ContextType = "dependency_manifest"
	ContextSecret        ContextType = "secret"
	ContextCredential    ContextType = "credential"
	ContextConfig        ContextType = "config"
	ContextDocumentation ContextType = "documentation"
	ContextBinary        ContextType = "binary"
	ContextUnknown       ContextType = "unknown"
)

// ContextPolicy defines rules for classifying data that may leave the sandbox.
type ContextPolicy struct {
	SensitivePatterns []*regexp.Regexp
	BlockedPaths      []string
	AllowedPaths      []string
}

// DefaultPolicy returns the default context policy for AEGIS v1.
// This is advisory — connection-level enforcement is at the proxy.
func DefaultPolicy() *ContextPolicy {
	sensitive := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)`),
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]`),
		regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
		regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})`),
		regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9]{20,})`),
	}
	return &ContextPolicy{
		SensitivePatterns: sensitive,
		BlockedPaths: []string{
			".env", ".env.*", ".env.local", ".env.production",
			"id_rsa", "id_ed25519", "id_ecdsa",
			"*.pem", "*.key", "*.p12", "*.pfx",
			".netrc", ".npmrc", ".pgpass",
			".ssh/*", ".aws/*", ".config/*",
			"credentials", "credentials.json",
			"service-account*.json",
		},
		AllowedPaths: []string{
			"*.go", "*.py", "*.js", "*.ts", "*.jsx", "*.tsx",
			"*.rs", "*.java", "*.rb", "*.c", "*.cpp", "*.h",
			"Makefile", "Dockerfile", "*.yml", "*.yaml", "*.toml",
			"*.json", "*.md", "*.txt",
			"go.mod", "go.sum", "package.json", "package-lock.json",
			"requirements*.txt", "pyproject.toml", "Cargo.toml",
		},
	}
}

// Classify determines the egress classification for a file path and content.
// This is advisory — it informs policy decisions but does not enforce them.
// Enforcement happens at the network proxy (connection-level) in v1.
func (p *ContextPolicy) Classify(path string, content []byte) Classification {
	cleaned := strings.TrimPrefix(path, "/workspace/")
	cleaned = strings.TrimPrefix(cleaned, "./")

	if p.matchesAny(cleaned, p.BlockedPaths) {
		return ClassBlocked
	}

	if p.containsSensitivePattern(content) {
		return ClassSensitive
	}

	if p.matchesAny(cleaned, p.AllowedPaths) {
		return ClassAllowed
	}

	return ClassUnknown(cleaned)
}

// ClassifyContext returns the context type for a file path.
func (p *ContextPolicy) ClassifyContext(path string) ContextType {
	cleaned := strings.TrimPrefix(path, "/workspace/")
	cleaned = strings.TrimPrefix(cleaned, "./")

	lower := strings.ToLower(cleaned)

	switch {
	case matchesAnySimple(lower, p.BlockedPaths):
		if strings.Contains(lower, "secret") || strings.Contains(lower, "key") || strings.Contains(lower, "private") {
			return ContextSecret
		}
		if strings.Contains(lower, "credential") || strings.Contains(lower, "auth") || strings.Contains(lower, "token") {
			return ContextCredential
		}
		return ContextConfig
	case isSourceFile(lower):
		return ContextSourceCode
	case isDependencyFile(lower):
		return ContextDependency
	case isDocumentation(lower):
		return ContextDocumentation
	case isBinary(lower):
		return ContextBinary
	default:
		return ContextUnknown
	}
}

func (p *ContextPolicy) containsSensitivePattern(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	s := string(content)
	for _, re := range p.SensitivePatterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func (p *ContextPolicy) matchesAny(path string, patterns []string) bool {
	lower := strings.ToLower(path)
	for _, pat := range patterns {
		if matchGlob(lower, strings.ToLower(pat)) {
			return true
		}
	}
	return false
}

func matchesAnySimple(path string, patterns []string) bool {
	for _, pat := range patterns {
		if matchGlob(path, strings.ToLower(pat)) {
			return true
		}
	}
	return false
}

func matchGlob(path, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(path, suffix)
	}
	return path == pattern
}

func ClassUnknown(path string) Classification {
	// Unknown paths are treated as blocked by default (fail-closed).
	return ClassBlocked
}

func isSourceFile(path string) bool {
	exts := []string{".go", ".py", ".js", ".ts", ".jsx", ".tsx", ".rs", ".java", ".rb", ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt"}
	for _, ext := range exts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func isDependencyFile(path string) bool {
	names := []string{"go.mod", "go.sum", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.py", "setup.cfg", "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock"}
	for _, n := range names {
		if path == n {
			return true
		}
	}
	return false
}

func isDocumentation(path string) bool {
	exts := []string{".md", ".txt", ".rst", ".adoc"}
	for _, ext := range exts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func isBinary(path string) bool {
	exts := []string{".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a"}
	for _, ext := range exts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}
