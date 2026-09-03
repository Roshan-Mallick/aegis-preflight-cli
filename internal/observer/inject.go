package observer

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed assets/hook.sh
var hookScript string

//go:embed assets/settings.hooks.json
var settingsJSON string

//go:embed assets/opencode.plugin.js
var opencodePluginJS string

const (
	hookBinDir      = ".aegis/bin"
	rawLogDir       = ".aegis/raw"
	rawLogName      = "hooks.jsonl"
	claudeDir       = ".claude"
	claudeSettings  = "settings.json"
	opencodeDir     = ".opencode"
	opencodePlugins = "plugins"
	opencodePlugin  = "aegis.js"
	HookPath        = "/workspace/.aegis/bin/hook.sh"
	managedMarker   = ".aegis-managed"
)

func RawLogPath(workspace string) string {
	return filepath.Join(workspace, rawLogDir, rawLogName)
}

func InjectHooks(workspace string) error {
	binDir := filepath.Join(workspace, hookBinDir)
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return fmt.Errorf("create hook bin dir: %w", err)
	}
	script := filepath.Join(binDir, "hook.sh")
	if err := os.WriteFile(script, []byte(hookScript), 0o755); err != nil {
		return fmt.Errorf("write hook script: %w", err)
	}
	if err := os.Chmod(script, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(workspace, ".aegis", managedMarker), []byte("AEGIS\n"), 0o600); err != nil {
		return fmt.Errorf("mark AEGIS hooks: %w", err)
	}
	if err := injectClaudeHooks(workspace); err != nil {
		return err
	}
	if err := injectOpenCodeHooks(workspace); err != nil {
		return err
	}
	return nil
}

func injectClaudeHooks(workspace string) error {
	dir := filepath.Join(workspace, claudeDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create .claude dir: %w", err)
	}
	if existing, err := os.ReadFile(filepath.Join(dir, claudeSettings)); err == nil && len(existing) > 0 {
		backup := filepath.Join(dir, claudeSettings+".aegis-backup")
		if err := os.WriteFile(backup, existing, 0o600); err != nil {
			return fmt.Errorf("back up existing claude settings: %w", err)
		}
	}
	path := filepath.Join(dir, claudeSettings)
	if err := os.WriteFile(path, []byte(settingsJSON), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, managedMarker), []byte("AEGIS\n"), 0o600)
}

func injectOpenCodeHooks(workspace string) error {
	dir := filepath.Join(workspace, opencodeDir, opencodePlugins)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create .opencode plugins dir: %w", err)
	}
	if existing, err := os.ReadFile(filepath.Join(dir, opencodePlugin)); err == nil && len(existing) > 0 {
		backup := filepath.Join(dir, opencodePlugin+".aegis-backup")
		if err := os.WriteFile(backup, existing, 0o600); err != nil {
			return fmt.Errorf("back up existing opencode plugin: %w", err)
		}
	}
	path := filepath.Join(dir, opencodePlugin)
	if err := os.WriteFile(path, []byte(opencodePluginJS), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(workspace, opencodeDir, managedMarker), []byte("AEGIS\n"), 0o600)
}
