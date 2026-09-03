package main

import "testing"

// TestInteractiveUsesSplitAgentRouting verifies the UI routing required for
// the intended AEGIS flow:
//
//	Agent CLI → entry gate → sandbox → agent's native UI → scan → PASS/BLOCK
//
// CLI coding agents (opencode/claude/codex) render their own native terminal
// UI, so they must route to full-screen passthrough (split=false) even on a
// TTY, while bare shells and arbitrary commands keep the split TUI on a
// terminal and passthrough off a terminal.
func TestInteractiveUsesSplitAgentRouting(t *testing.T) {
	cases := []struct {
		name     string
		uiMode   string
		isTTY    bool
		agentRun bool
		want     bool
	}{
		// Agents on a TTY, default & auto → native passthrough.
		{"opencode default tty", "", true, true, false},
		{"opencode auto tty", "auto", true, true, false},
		{"claude default tty", "", true, true, false},
		{"codex auto tty", "auto", true, true, false},

		// Agents off a TTY → passthrough regardless.
		{"opencode default notty", "", false, true, false},
		{"opencode auto notty", "auto", false, true, false},

		// Bare shells / arbitrary commands on a TTY → split TUI.
		{"shell default tty", "", true, false, true},
		{"shell auto tty", "auto", true, false, true},
		{"sh default tty", "", true, false, true},

		// Bare shells off a TTY → passthrough.
		{"shell default notty", "", false, false, false},
		{"shell auto notty", "auto", false, false, false},

		// Explicit modes override the defaults.
		{"agent explicit split", "split", true, true, true},
		{"shell explicit passthrough", "passthrough", true, false, false},
		{"agent explicit none", "none", true, true, false},
	}
	for _, tc := range cases {
		if got := interactiveUsesSplit(tc.uiMode, tc.isTTY, tc.agentRun); got != tc.want {
			t.Errorf("%s: interactiveUsesSplit(%q,%v,%v) = %v, want %v",
				tc.name, tc.uiMode, tc.isTTY, tc.agentRun, got, tc.want)
		}
	}
}

// TestInteractiveForAgentRouting exercises interactiveFor end-to-end for the
// explicit modes (which don't depend on TTY state) to confirm agents reach
// passthrough and split can still be forced.
func TestInteractiveForAgentRouting(t *testing.T) {
	for _, name := range []string{"opencode", "claude", "codex"} {
		if f := interactiveFor("passthrough", nil, name, "strict"); f != nil {
			t.Errorf("%s: explicit passthrough should return nil", name)
		}
		if f := interactiveFor("none", nil, name, "strict"); f != nil {
			t.Errorf("%s: explicit none should return nil", name)
		}
		if f := interactiveFor("split", nil, name, "strict"); f == nil {
			t.Errorf("%s: explicit split should return a UI func", name)
		}
	}
}

// TestIsAgentName ensures runtime-resolved executables are treated as agents.
func TestIsAgentName(t *testing.T) {
	for _, name := range []string{"true", "ls"} {
		if !isAgentName(name) {
			t.Errorf("isAgentName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"shell", "bash", "sh", "", "missing-aegis-agent"} {
		if isAgentName(name) {
			t.Errorf("isAgentName(%q) = true, want false", name)
		}
	}
}
