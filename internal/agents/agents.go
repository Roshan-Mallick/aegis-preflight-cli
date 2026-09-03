package agents

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type Agent struct {
	Name        string
	BinaryPath  string
	ConfigDir   string
	DataDir     string
	Description string
}

var registry = map[string]func() *Agent{
	"opencode": detectOpencode,
	"claude":   detectClaude,
	"codex":    detectCodex,
}

func Detect(name string) (*Agent, error) {
	if fn, ok := registry[name]; ok {
		a := fn()
		if a == nil {
			return nil, fmt.Errorf("agent %q not found on this system", name)
		}
		return a, nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("agent %q not found on this system or PATH", name)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve agent %q: %w", name, err)
	}
	if info, err := os.Stat(abs); err != nil || info.Mode()&0111 == 0 {
		return nil, fmt.Errorf("agent %q not found on this system", name)
	}
	return &Agent{Name: name, BinaryPath: abs, Description: "user-provided AI agent"}, nil
}

func ListAvailable() []string {
	var available []string
	for name := range registry {
		if a := registry[name](); a != nil {
			available = append(available, name)
		}
	}
	return available
}

func detectOpencode() *Agent {
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".opencode", "bin", "opencode"),
		"/usr/local/bin/opencode",
		"/usr/bin/opencode",
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.Mode()&0111 != 0 {
			return &Agent{
				Name:        "opencode",
				BinaryPath:  p,
				ConfigDir:   filepath.Join(home, ".config", "opencode"),
				DataDir:     filepath.Join(home, ".local", "share", "opencode"),
				Description: "OpenCode AI agent",
			}
		}
	}
	if path, err := exec.LookPath("opencode"); err == nil {
		abs, _ := filepath.Abs(path)
		return &Agent{
			Name:        "opencode",
			BinaryPath:  abs,
			ConfigDir:   filepath.Join(home, ".config", "opencode"),
			DataDir:     filepath.Join(home, ".local", "share", "opencode"),
			Description: "OpenCode AI agent",
		}
	}
	return nil
}

func detectClaude() *Agent {
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".claude", "bin", "claude"),
		"/usr/local/bin/claude",
		"/usr/bin/claude",
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.Mode()&0111 != 0 {
			return &Agent{
				Name:        "claude",
				BinaryPath:  p,
				ConfigDir:   filepath.Join(home, ".claude"),
				Description: "Claude Code agent",
			}
		}
	}
	if path, err := exec.LookPath("claude"); err == nil {
		abs, _ := filepath.Abs(path)
		return &Agent{
			Name:        "claude",
			BinaryPath:  abs,
			ConfigDir:   filepath.Join(home, ".claude"),
			Description: "Claude Code agent",
		}
	}
	return nil
}

func detectCodex() *Agent {
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".codex", "bin", "codex"),
		"/usr/local/bin/codex",
		"/usr/bin/codex",
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.Mode()&0111 != 0 {
			return &Agent{
				Name:        "codex",
				BinaryPath:  p,
				ConfigDir:   filepath.Join(home, ".codex"),
				DataDir:     filepath.Join(home, ".codex"),
				Description: "OpenAI Codex CLI agent",
			}
		}
	}
	if path, err := exec.LookPath("codex"); err == nil {
		abs, _ := filepath.Abs(path)
		return &Agent{
			Name:        "codex",
			BinaryPath:  abs,
			ConfigDir:   filepath.Join(home, ".codex"),
			DataDir:     filepath.Join(home, ".codex"),
			Description: "OpenAI Codex CLI agent",
		}
	}
	return nil
}
