package egress

import (
	"testing"
)

func TestClassifySourceCode(t *testing.T) {
	p := DefaultPolicy()
	tests := []struct {
		path string
		want Classification
	}{
		{"src/main.go", ClassAllowed},
		{"lib/utils.py", ClassAllowed},
		{"app/index.js", ClassAllowed},
		{"README.md", ClassAllowed},
		{"go.mod", ClassAllowed},
	}
	for _, tt := range tests {
		got := p.Classify(tt.path, nil)
		if got != tt.want {
			t.Errorf("Classify(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestClassifySensitivePaths(t *testing.T) {
	p := DefaultPolicy()
	tests := []struct {
		path string
		want Classification
	}{
		{".env", ClassBlocked},
		{".env.local", ClassBlocked},
		{".env.production", ClassBlocked},
		{"id_rsa", ClassBlocked},
		{".ssh/authorized_keys", ClassBlocked},
		{".aws/credentials", ClassBlocked},
		{"secret.key", ClassBlocked},
	}
	for _, tt := range tests {
		got := p.Classify(tt.path, nil)
		if got != tt.want {
			t.Errorf("Classify(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestClassifySensitiveContent(t *testing.T) {
	p := DefaultPolicy()
	content := []byte(`API_KEY=AKIAIOSFODNN7EXAMPLE`)
	got := p.Classify("config.py", content)
	if got != ClassSensitive {
		t.Errorf("Classify with AWS key content = %q, want %q", got, ClassSensitive)
	}
}

func TestClassifyPrivateKey(t *testing.T) {
	p := DefaultPolicy()
	content := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy5AH...
-----END RSA PRIVATE KEY-----`)
	got := p.Classify("server.go", content)
	if got != ClassSensitive {
		t.Errorf("Classify with private key content = %q, want %q", got, ClassSensitive)
	}
}

func TestClassifyContextType(t *testing.T) {
	p := DefaultPolicy()
	tests := []struct {
		path string
		want ContextType
	}{
		{"src/main.go", ContextSourceCode},
		{"package.json", ContextDependency},
		{".env", ContextConfig},
		{".ssh/id_rsa", ContextConfig},
		{"README.md", ContextDocumentation},
	}
	for _, tt := range tests {
		got := p.ClassifyContext(tt.path)
		if got != tt.want {
			t.Errorf("ClassifyContext(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestRedact(t *testing.T) {
	r := DefaultRedactor()

	// AWS key — full match
	got := r.Redact("AKIAIOSFODNN7EXAMPLE")
	if got != "[REDACTED_AWS_KEY]" {
		t.Errorf("Redact AWS key = %q", got)
	}

	// OpenAI key — full match (20+ chars after sk-)
	got = r.Redact("sk-abcdefghijklmnopqrstuvwxyz1234567890")
	if got != "[REDACTED_OPENAI_KEY]" {
		t.Errorf("Redact OpenAI key = %q", got)
	}

	// GitHub token — full match (36 chars after ghp_)
	got = r.Redact("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678AB")
	if got != "[REDACTED_GITHUB_TOKEN]" {
		t.Errorf("Redact GitHub token = %q", got)
	}

	// No secrets — unchanged
	got = r.Redact("normal text with no secrets")
	if got != "normal text with no secrets" {
		t.Errorf("Redact normal text = %q", got)
	}
}

func TestMinimize(t *testing.T) {
	m := DefaultMinimizer()

	// Small file — no truncation
	small := []byte("short content")
	result, truncated := m.Minimize(small)
	if truncated {
		t.Error("Minimize should not truncate small content")
	}
	if string(result) != string(small) {
		t.Errorf("Minimize changed content: got %q", result)
	}

	// Large file — truncation
	large := make([]byte, 2*1024*1024) // 2MB
	for i := range large {
		large[i] = 'a'
	}
	_, truncated = m.Minimize(large)
	if !truncated {
		t.Error("Minimize should truncate large content")
	}
}

func TestShouldExclude(t *testing.T) {
	m := DefaultMinimizer()
	tests := []struct {
		path string
		want bool
	}{
		{"binary.exe", true},
		{"lib.so", true},
		{"image.jpg", true},
		{"main.go", false},
		{"README.md", false},
	}
	for _, tt := range tests {
		got := m.ShouldExclude(tt.path)
		if got != tt.want {
			t.Errorf("ShouldExclude(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestContextMinimizer(t *testing.T) {
	cm := NewContextMinimizer()

	// Source code — allowed, not excluded
	result := cm.Process("src/main.go", []byte("package main"))
	if result.Classification != ClassAllowed {
		t.Errorf("Process source code: classification = %q, want %q", result.Classification, ClassAllowed)
	}
	if result.Excluded {
		t.Error("Process source code should not be excluded")
	}

	// .env file — blocked
	result = cm.Process(".env", []byte("SECRET=abc123"))
	if result.Classification != ClassBlocked {
		t.Errorf("Process .env: classification = %q, want %q", result.Classification, ClassBlocked)
	}

	// Binary file — excluded
	result = cm.Process("binary.exe", []byte{0x00, 0x01, 0x02})
	if !result.Excluded {
		t.Error("Process binary should be excluded")
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		want    bool
	}{
		{"test.go", "*.go", true},
		{"test.py", "*.go", false},
		{".env", ".env", true},
		{".env.local", ".env.*", true},
		{"id_rsa", "id_rsa", true},
	}
	for _, tt := range tests {
		got := matchGlob(tt.path, tt.pattern)
		if got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
		}
	}
}
