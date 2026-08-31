package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eth0x1/aegis/internal/config"
	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/exitgate"
	"github.com/eth0x1/aegis/internal/findings"
	"github.com/eth0x1/aegis/internal/model"
	"github.com/eth0x1/aegis/internal/pipeline"
	"github.com/eth0x1/aegis/internal/preflight"
	"github.com/eth0x1/aegis/internal/session"
	"github.com/eth0x1/aegis/internal/workspace"
)

func newRunCmd() *cobra.Command {
	var netProfile string
	var projectPath string
	var uiMode string
	cmd := &cobra.Command{
		Use:   "run [command] [args...]",
		Short: "Launch an interactive Aegis sandbox",
		Long: `Launch a sandboxed shell session for the current project.

With no arguments, opens an interactive shell inside the sandbox.
You can run normal Linux commands (ls, pwd, cat, mkdir, cd, etc.) and
launch AI agents (opencode, claude) from within the sandbox.

With arguments, executes the command inside the sandbox and returns.

The directory you launch from (PROJECT_ROOT) is the security boundary.
It is mounted directly into the hardened container as /workspace: you get
full read/write access and normal navigation (cd .., creating, editing,
deleting files) inside the project, and nothing outside it — your home
directory, sibling projects, the host filesystem — is visible or reachable.
Network access is restricted by default (strict mode).

The pipeline is fully orchestrated: entry gate, sandbox, simultaneous
file/tool/network monitoring, security scan, preflight exit gate and
finalization all share a single session id.

Examples:
  aegis run                        # interactive sandbox shell (split TUI)
  aegis run ls                     # list workspace files
  aegis run opencode               # launch opencode in sandbox
  aegis run opencode "fix bug"     # run opencode with a task
  aegis run --net dev opencode     # opencode with dev network
  aegis run --ui passthrough       # full-screen terminal passthrough
  aegis run bash                   # explicit bash shell`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSandbox(args, netProfile, projectPath, uiMode)
		},
	}
	cmd.Flags().StringVar(&netProfile, "net", "", "network profile (strict|dev); default strict")
	cmd.Flags().StringVar(&projectPath, "project", "", "project root path (default: the launch directory itself)")
	cmd.Flags().StringVar(&uiMode, "ui", "", "interactive UI (split|passthrough); default split on a TTY")
	return cmd
}

func runSandbox(args []string, netProfile, projectPath, uiMode string) error {
	profile := strings.ToLower(netProfile)
	if profile == "" {
		profile = "strict"
	}
	if profile != "strict" && profile != "dev" {
		return fmt.Errorf("unknown network profile %q (strict|dev)", profile)
	}

	projectRoot := projectPath
	if projectRoot == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("cannot get working directory: %w", err)
		}
		projectRoot = cwd
	}
	detected, err := workspace.DetectRoot(projectRoot)
	if err != nil {
		return fmt.Errorf("detect project root from %s: %w", projectRoot, err)
	}
	projectRoot = detected
	fmt.Fprintf(os.Stderr, "project root: %s\n", projectRoot)

	agentName := detectAgentName(args)

	opts := pipeline.RunOptions{
		ProjectRoot: projectRoot,
		Agent:       agentName,
		Profile:     profile,
		Args:        args,
		Print: func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, format, a...)
		},
		OnBlock: func(ctx context.Context, mgr *session.Manager, ws string, final *preflight.FinalResult) {
			printBlocked(mgr, final)
			// An AI-only block was already reviewed by the local model; do
			// not also run the advisory findings explainer.
			if final != nil && final.AIBlocked && (final.Last == nil || final.Last.Blocking == 0) {
				return
			}
			runModelAnalysis(ctx, mgr, ws, final)
		},
		OnPass: func(ctx context.Context, mgr *session.Manager, ws string, final *preflight.FinalResult) {
			printPassed(mgr, final)
		},
		ExitGate: buildExitGate(projectRoot),
	}
	opts.Interactive = interactiveFor(uiMode, args, agentName, profile)

	ctx := context.Background()
	res, err := pipeline.Run(ctx, opts)
	if err != nil {
		if res != nil && res.State == session.StateBlock {
			return err
		}
		return err
	}
	_ = res
	return nil
}

func printBlocked(mgr *session.Manager, final *preflight.FinalResult) {
	snap := mgr.Snapshot()

	if final != nil && final.AIBlocked && (final.Last == nil || final.Last.Blocking == 0) {
		fmt.Fprintf(os.Stderr, "\n=== EXIT SECURITY REVIEW BLOCKED ===\n")
		fmt.Fprintf(os.Stderr, "Session:     %s\n", shortID(snap.SessionID))
		fmt.Fprintf(os.Stderr, "Cycles:      %d\n", final.Cycles)
		if final.AIUnavailable {
			fmt.Fprintf(os.Stderr, "Local AI security review UNAVAILABLE — exit blocked under the safe policy.\n")
		} else {
			fmt.Fprintf(os.Stderr, "Risk:        %s\n", orDisplay(final.AIRisk))
			if final.AISummary != "" {
				fmt.Fprintf(os.Stderr, "\n%s\n", final.AISummary)
			}
			if len(final.AIFindings) > 0 {
				fmt.Fprintf(os.Stderr, "\nFindings:\n")
				for _, f := range final.AIFindings {
					fmt.Fprintf(os.Stderr, "- %s\n", f)
				}
			}
		}
		fmt.Fprintf(os.Stderr, "\nFix these issues and retry the final security review.\n")
		fmt.Fprintf(os.Stderr, "The flagged changes were left in your project directory (%s).\n", snap.ProjectRoot)
		return
	}

	fmt.Fprintf(os.Stderr, "\n=== PREFLIGHT BLOCKED ===\n")
	fmt.Fprintf(os.Stderr, "Session:     %s\n", shortID(snap.SessionID))
	fmt.Fprintf(os.Stderr, "Cycles:      %d\n", final.Cycles)
	fmt.Fprintf(os.Stderr, "Findings:    %d total, %d blocking\n", final.Last.Total, final.Last.Blocking)
	fmt.Fprintf(os.Stderr, "\nBlocking findings:\n")
	for _, f := range uniqueBlocking(final) {
		loc := f.File
		if loc == "" {
			loc = "(project)"
		}
		fmt.Fprintf(os.Stderr, "  [%s] %s:%d rule=%s\n    %s\n",
			strings.ToUpper(f.Severity), loc, f.Line, f.Rule, f.Message)
	}
	fmt.Fprintf(os.Stderr, "\nThe flagged changes were left in your project directory (%s) and are BLOCKED.\n", snap.ProjectRoot)
	fmt.Fprintf(os.Stderr, "Fix the issues directly (they are already in place) and run 'aegis run' again.\n")
	fmt.Fprintf(os.Stderr, "View details: aegis preflight %s\n", shortID(snap.SessionID))
}

func orDisplay(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

// uniqueBlocking collapses identical blocking findings (same rule, file,
// line and message) that repeat across remediation cycles into one row, so
// the summary matches the "N total, N blocking" headline.
func uniqueBlocking(final *preflight.FinalResult) []findings.Finding {
	if final == nil || final.Last == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []findings.Finding
	for _, f := range final.Last.Findings {
		if !f.Blocking {
			continue
		}
		key := f.Rule + "|" + f.File + "|" + strconv.Itoa(f.Line) + "|" + f.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func printPassed(mgr *session.Manager, final *preflight.FinalResult) {
	snap := mgr.Snapshot()
	fmt.Fprintf(os.Stderr, "\n=== PREFLIGHT PASSED ===\n")
	fmt.Fprintf(os.Stderr, "Session:     %s\n", shortID(snap.SessionID))
	fmt.Fprintf(os.Stderr, "Cycles:      %d\n", final.Cycles)
	fmt.Fprintf(os.Stderr, "Scanners:    %s\n", strings.Join(final.Last.ScannersRun, ", "))
	if final != nil && final.AIUnavailable {
		fmt.Fprintf(os.Stderr, "Local AI security review UNAVAILABLE (warn policy) — advisory review skipped.\n")
	}
	fmt.Fprintf(os.Stderr, "\nSession is verified. Changes already live in your project (%s).\n", snap.ProjectRoot)
	fmt.Fprintf(os.Stderr, "Run 'aegis apply %s' to validate and record the promotion.\n", shortID(snap.SessionID))
}

// buildExitGate returns a RunOptions.ExitGate factory, or nil when the Local
// AI exit review is disabled (the default, keeping deterministic AEGIS
// behavior unchanged). Enabling via config (aegis.json
// {"exit_gate":{"enabled":true}}) or the AEGIS_EXIT_GATE=1 environment
// variable runs a compact security summary past the local model at the exit
// gate only — never the conversation, source files, or secrets.
func buildExitGate(projectRoot string) func(sessionID string, store *events.Store) *exitgate.Gate {
	cfg, err := config.Load(projectRoot)
	if err != nil {
		cfg = &config.Config{}
	}
	enabled := cfg.ExitGate.Enabled
	if v, ok := os.LookupEnv("AEGIS_EXIT_GATE"); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			enabled = b
		}
	}
	if !enabled {
		return nil
	}

	onDown := cfg.ExitGate.OnUnavailable
	if onDown == "" {
		onDown = exitgate.PolicyBlock
	}
	baseURL := cfg.ExitGate.BaseURL
	mdl := cfg.ExitGate.Model

	return func(sessionID string, store *events.Store) *exitgate.Gate {
		client := model.New(sessionID,
			model.WithStore(store),
			model.WithModel(mdl),
			model.WithBaseURL(baseURL))
		return exitgate.New(client, onDown)
	}
}

func detectAgentName(args []string) string {
	if len(args) == 0 {
		return "shell"
	}
	name := args[0]
	known := []string{"opencode", "claude", "codex", "shell", "bash", "sh"}
	for _, k := range known {
		if name == k {
			return name
		}
	}
	return "shell"
}

// runModelAnalysis runs blocked-session findings through the local Qwen model
// for a developer-actionable explanation. It is advisory and fail-open; every
// inference is logged to the session store with the active session_id.
func runModelAnalysis(ctx context.Context, mgr *session.Manager, ws string, final *preflight.FinalResult) {
	store := mgr.Store()
	if store == nil {
		return
	}
	snap := mgr.Snapshot()
	client := model.New(snap.SessionID, model.WithStore(store))
	if err := client.Health(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "model:       local advisor offline (%v) — deterministic findings stand\n", err)
		return
	}

	var refs []model.FindingRef
	for _, f := range uniqueBlocking(final) {
		refs = append(refs, model.FindingRef{
			Severity: strings.ToUpper(f.Severity),
			File:     f.File,
			Line:     f.Line,
			Rule:     f.Rule,
			Message:  f.Message,
		})
	}
	system, user := model.PromptForFindings(snap.SessionID, final.Cycles,
		final.Last.Blocking, final.Last.Total, refs)
	resp, err := client.Chat(ctx, system, user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "model:       analysis failed (%v)\n", err)
		return
	}
	_ = writeModelFindingsMD(mgr.Dir(), snap.SessionID, resp)
	fmt.Fprintf(os.Stderr, "\n=== LOCAL ADVISOR (Qwen2.5-Coder-1.5B) ===\n%s\n\n", strings.TrimSpace(resp.Text))
}

func writeModelFindingsMD(sessionDir, sessionID string, resp *model.Response) error {
	md := fmt.Sprintf("# AEGIS local advisor — session %s\n\n", shortID(sessionID)) +
		fmt.Sprintf("Generated: %s (latency %dms)\n\n---\n\n", time.Now().UTC().Format(time.RFC3339), resp.LatencyMS) +
		strings.TrimSpace(resp.Text) + "\n"
	return os.WriteFile(sessionDir+"/model-analysis.md", []byte(md), 0o600)
}

// isAgentName reports whether the detected command is a real CLI coding
// agent (opencode/claude/codex). Those agents render their own native
// full-screen terminal UI, so they are routed to the passthrough entry
// point rather than AEGIS's embedded split TUI. Bare shells and arbitrary
// commands ("shell", "bash", "sh", or any other command) are not agents.
func isAgentName(agentName string) bool {
	switch agentName {
	case "opencode", "claude", "codex":
		return true
	}
	return false
}

// interactiveFor selects the sandbox interactive entry point. passthrough
// (nil return) uses a full-screen terminal passthrough so a CLI agent renders
// its own native UI; split runs the embedded TUI (interactive PTY pane +
// security feed + status bar). auto prefers split when a terminal is present
// and the command is not an agent, otherwise passthrough. The default ("")
// follows the same rule: native passthrough for agents, otherwise split on a
// terminal.
func interactiveFor(uiMode string, args []string, agentName, profile string) pipeline.InteractiveFunc {
	if interactiveUsesSplit(uiMode, termIsTTY(), isAgentName(agentName)) {
		return splitTUIInteractive(args, agentName, profile)
	}
	return nil
}

// interactiveUsesSplit is the pure routing decision behind interactiveFor: it
// reports whether the given UI mode should use AEGIS's embedded split TUI
// rather than the full-screen passthrough. It is separated out so the TTY and
// agent-routing behaviour can be unit-tested without a real terminal.
func interactiveUsesSplit(uiMode string, isTTY, agentRun bool) bool {
	switch uiMode {
	case "passthrough", "none":
		return false
	case "split":
		return true
	case "auto":
		return isTTY && !agentRun
	case "":
		return isTTY && !agentRun
	default:
		return false
	}
}

func termIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
