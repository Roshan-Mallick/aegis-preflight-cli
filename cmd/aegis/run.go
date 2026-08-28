package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

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

The filesystem is restricted to the current project workspace.
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
	cmd.Flags().StringVar(&projectPath, "project", "", "project root path (default: auto-detect from cwd)")
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
			runModelAnalysis(ctx, mgr, ws, final)
		},
		OnPass: func(ctx context.Context, mgr *session.Manager, ws string, final *preflight.FinalResult) {
			printPassed(mgr, final)
		},
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
	fmt.Fprintf(os.Stderr, "\nA fix request has been written to the workspace.\n")
	fmt.Fprintf(os.Stderr, "Fix the issues and run 'aegis run' again.\n")
	fmt.Fprintf(os.Stderr, "View details: aegis preflight %s\n", shortID(snap.SessionID))
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
	fmt.Fprintf(os.Stderr, "\nSession is ready for promotion.\n")
	fmt.Fprintf(os.Stderr, "Run 'aegis apply %s' to promote changes to your project.\n", shortID(snap.SessionID))
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

// interactiveFor selects the sandbox interactive entry point. passthrough
// uses a full-screen terminal passthrough; split runs the embedded TUI
// (interactive PTY pane + security feed + status bar). auto prefers split
// when a terminal is present, otherwise passthrough.
func interactiveFor(uiMode string, args []string, agentName, profile string) pipeline.InteractiveFunc {
	switch uiMode {
	case "passthrough", "none":
		return nil
	case "split", "auto":
		if uiMode == "auto" && !termIsTTY() {
			return nil
		}
		return splitTUIInteractive(args, agentName, profile)
	case "":
		if termIsTTY() {
			return splitTUIInteractive(args, agentName, profile)
		}
		return nil
	default:
		return nil
	}
}

func termIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
