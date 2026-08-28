// Package agent defines the adapter interface for AI coding agents.
// AEGIS supports one agent per session. Each agent implements this interface.
// The agent is treated as untrusted — AEGIS is the security authority.
package agent

import (
	"context"
	"io"
)

// Adapter is the interface that all AI agent integrations must implement.
// It abstracts the differences between Claude Code, Codex, aider, etc.
type Adapter interface {
	// Name returns the agent identifier (e.g., "claude", "codex", "aider").
	Name() string

	// Detect checks if this agent is available on the system.
	// Returns the agent configuration if found, nil otherwise.
	Detect() (*Config, error)

	// Start launches the agent inside the sandbox.
	// The provided workspace is the only writable directory.
	// stdout/stderr are streamed to the caller.
	// The context can be cancelled to terminate the agent.
	Start(ctx context.Context, workspace string, opts StartOptions) (Session, error)

	// InjectHooks sets up observation hooks for this agent.
	// Hooks are injected into the workspace directory.
	// Returns the hook configuration that was written.
	InjectHooks(workspace string) (*HookConfig, error)
}

// Config holds discovered agent configuration.
type Config struct {
	Name       string `json:"name"`
	BinaryPath string `json:"binary_path"`
	Version    string `json:"version,omitempty"`
	ConfigDir  string `json:"config_dir,omitempty"`
	DataDir    string `json:"data_dir,omitempty"`
}

// StartOptions configures how the agent is launched.
type StartOptions struct {
	AgentPath   string            // Path to agent binary inside container
	Command     string            // Optional command override
	Environment map[string]string // Extra environment variables
	WorkDir     string            // Working directory inside container (default: /workspace)
}

// Session represents a running agent session.
type Session interface {
	// Stdin returns the writable stdin pipe to the agent.
	Stdin() io.WriteCloser

	// Stdout returns the readable stdout stream from the agent.
	Stdout() io.ReadCloser

	// Stderr returns the readable stderr stream from the agent.
	Stderr() io.ReadCloser

	// Wait blocks until the agent exits and returns the exit code.
	Wait(ctx context.Context) (int, error)

	// Kill terminates the agent process.
	Kill() error
}

// HookConfig describes the observation hooks injected for an agent.
type HookConfig struct {
	Agent        string            `json:"agent"`
	HookScript   string            `json:"hook_script_path"`
	SettingsFile string            `json:"settings_file_path"`
	ToolMap      map[string]string `json:"tool_map"` // Claude tool name → canonical event type
}

// ToolType maps agent-specific tool names to canonical event types.
// This mapping is defined per-agent and used by the observer normalizer.
var ToolType = map[string]string{
	"Bash":         "command.exec",
	"Read":         "file.read",
	"Write":        "file.write",
	"Edit":         "file.write",
	"MultiEdit":    "file.write",
	"NotebookEdit": "file.write",
	"WebFetch":     "network.connect",
	"WebSearch":    "network.connect",
}
