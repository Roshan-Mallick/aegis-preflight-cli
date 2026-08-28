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

//go:embed assets/opencode.hooks.json
var opencodeHooksJSON string

const (
	hookBinDir     = ".aegis/bin"
	rawLogDir      = ".aegis/raw"
	rawLogName     = "hooks.jsonl"
	claudeDir      = ".claude"
	claudeSettings = "settings.json"
	opencodeDir    = ".opencode"
	opencodeConfig = "config.json"
	HookPath       = "/workspace/.aegis/bin/hook.sh"
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
	return os.WriteFile(path, []byte(settingsJSON), 0o600)
}

func injectOpenCodeHooks(workspace string) error {
	dir := filepath.Join(workspace, opencodeDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create .opencode dir: %w", err)
	}
	if existing, err := os.ReadFile(filepath.Join(dir, opencodeConfig)); err == nil && len(existing) > 0 {
		backup := filepath.Join(dir, opencodeConfig+".aegis-backup")
		if err := os.WriteFile(backup, existing, 0o600); err != nil {
			return fmt.Errorf("back up existing opencode config: %w", err)
		}
	}
	path := filepath.Join(dir, opencodeConfig)
	return os.WriteFile(path, []byte(opencodeHooksJSON), 0o600)
}
