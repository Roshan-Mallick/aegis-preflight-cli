package agent

import (
	"testing"
)

func TestToolTypeMap(t *testing.T) {
	expected := map[string]string{
		"Bash":         "command.exec",
		"Read":         "file.read",
		"Write":        "file.write",
		"Edit":         "file.write",
		"MultiEdit":    "file.write",
		"NotebookEdit": "file.write",
		"WebFetch":     "network.connect",
		"WebSearch":    "network.connect",
	}
	for tool, wantType := range expected {
		got, ok := ToolType[tool]
		if !ok {
			t.Errorf("ToolType missing entry for %q", tool)
			continue
		}
		if got != wantType {
			t.Errorf("ToolType[%q] = %q, want %q", tool, got, wantType)
		}
	}
}

func TestToolTypeCoverage(t *testing.T) {
	// All Claude Code tools should have a mapping
	claudeTools := []string{
		"Bash", "Read", "Write", "Edit", "MultiEdit",
		"NotebookEdit", "WebFetch", "WebSearch",
	}
	for _, tool := range claudeTools {
		if _, ok := ToolType[tool]; !ok {
			t.Errorf("ToolType has no mapping for Claude tool %q", tool)
		}
	}
}
