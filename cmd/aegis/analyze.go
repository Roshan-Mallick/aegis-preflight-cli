package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/model"
	"github.com/eth0x1/aegis/internal/paths"
	"github.com/eth0x1/aegis/internal/session"
)

func newAnalyzeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "analyze [session-id]",
		Short: "Analyze a session timeline with the local Qwen model (advisory)",
		Long: `Runs the last (or given) session's full event timeline through the local
Qwen2.5-Coder-1.5B model and prints a human-readable security analysis.

The model is advisory only — it never makes or overrides security decisions.
Every inference is logged to the session's event store with its session_id.

Requires the local inference server (systemctl --user start aegis-model).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) == 1 {
				id = args[0]
			} else {
				latest, err := paths.LatestSession()
				if err != nil {
					return fmt.Errorf("no sessions found; pass a session id: aegis analyze <session-id>")
				}
				id = latest
			}
			mgr, err := session.Load(paths.StateDir(), id)
			if err != nil {
				return err
			}
			defer mgr.Close()

			snap := mgr.Snapshot()
			short := shortID(snap.SessionID)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			client := model.New(snap.SessionID, model.WithStore(mgr.Store()))
			if err := client.Health(ctx); err != nil {
				return fmt.Errorf("local model not reachable (%v)\n\n"+
					"Start it with: systemctl --user start aegis-model\n"+
					"Then re-run:   aegis analyze %s", err, short)
			}

			all, err := events.ReadAll(mgr.Dir())
			if err != nil {
				return err
			}
			lines := make([]string, 0, len(all))
			for _, e := range all {
				lines = append(lines, formatEventLine(e))
			}
			system, user := model.PromptForTimeline(snap.SessionID, lines)

			fmt.Fprintf(os.Stderr, "analyzing session %s (%d events) with local model...\n", short, len(lines))
			resp, err := client.Chat(ctx, system, user)
			if err != nil {
				return fmt.Errorf("model inference failed: %w", err)
			}

			fmt.Println(strings.TrimSpace(resp.Text))
			if err := writeAnalysisArtifact(mgr.Dir(), short, resp); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not write analysis artifact: %v\n", err)
			}
			fmt.Fprintf(os.Stderr, "\n(analysis saved to %s/model-analysis.md)\n", mgr.Dir())
			fmt.Fprintf(os.Stderr, "latency: %dms  tokens: %d\n", resp.LatencyMS, resp.CompletionTokens)
			return nil
		},
	}
}

func formatEventLine(e events.Event) string {
	var b strings.Builder
	ts := e.Timestamp
	if t, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
		ts = t.Format("15:04:05")
	}
	fmt.Fprintf(&b, "%s %-14s %-6s %-8s", ts, e.Type, e.Severity, e.Source)
	if len(e.Data) > 0 {
		kb, err := json.Marshal(e.Data)
		if err == nil {
			b.WriteString(" ")
			b.WriteString(string(kb))
		}
	}
	return b.String()
}

func writeAnalysisArtifact(sessionDir, short string, resp *model.Response) error {
	md := fmt.Sprintf("# AEGIS model analysis — session %s\n\n", short) +
		fmt.Sprintf("Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339Nano)) +
		fmt.Sprintf("Latency: %dms | tokens: %d\n\n---\n\n", resp.LatencyMS, resp.CompletionTokens) +
		strings.TrimSpace(resp.Text) + "\n"
	path := filepath.Join(sessionDir, "model-analysis.md")
	if err := os.WriteFile(path, []byte(md), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
