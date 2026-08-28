package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/paths"
	"github.com/eth0x1/aegis/internal/session"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [session-id]",
		Short: "Show session state, findings, and artifacts",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) == 1 {
				id = args[0]
			} else {
				latest, err := paths.LatestSession()
				if err != nil {
					return fmt.Errorf("no sessions found in %s", paths.SessionsDir())
				}
				id = latest
			}

			mgr, err := session.Load(paths.StateDir(), id)
			if err != nil {
				return err
			}
			defer mgr.Close()
			snap := mgr.Snapshot()

			var createdAt time.Time
			if t, e := time.Parse(time.RFC3339Nano, snap.CreatedAt); e == nil {
				createdAt = t
			}

			elapsed := ""
			if !createdAt.IsZero() {
				d := time.Since(createdAt)
				elapsed = fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
			}

			fmt.Println("Session:", snap.SessionID)
			fmt.Println("State:  ", snap.State)
			fmt.Println("Agent:  ", snap.Agent)
			fmt.Println("Network:", snap.NetProfile)
			fmt.Println("Created:", snap.CreatedAt)
			fmt.Println("Updated:", snap.UpdatedAt)
			if elapsed != "" {
				fmt.Println("Elapsed:", elapsed)
			}
			if snap.ProjectRoot != "" {
				fmt.Println("Project:", snap.ProjectRoot)
			}
			if snap.Workspace != "" {
				fmt.Println("Workspc:", snap.Workspace)
			}
			if snap.Outcome != "" {
				fmt.Println("Outcome:", snap.Outcome)
			}
			if snap.PreflightCycles > 0 {
				fmt.Println("Cycles: ", snap.PreflightCycles)
			}

			evts, err := events.ReadAll(mgr.Dir())
			if err == nil {
				counts := map[string]int{}
				for _, e := range evts {
					counts[e.Type]++
				}
				if len(counts) > 0 {
					fmt.Println("\nEvents:")
					types := make([]string, 0, len(counts))
					for t := range counts {
						types = append(types, t)
					}
					sort.Strings(types)
					for _, t := range types {
						fmt.Printf("  %-24s %d\n", t, counts[t])
					}
				}
			}

			artifacts := []string{
				"metadata.json", "events.jsonl",
				"verified-diff.json", "verified-diff.txt",
				"incident-*.json", "evidence-*.tar.gz",
			}
			fmt.Println("\nArtifacts:")
			found := 0
			for _, pattern := range artifacts {
				matches, _ := filepath.Glob(filepath.Join(mgr.Dir(), pattern))
				for _, m := range matches {
					info, err := os.Stat(m)
					if err != nil {
						continue
					}
					name := filepath.Base(m)
					fmt.Printf("  %-30s %s\n", name, formatSize(info.Size()))
					found++
				}
			}
			if found == 0 {
				fmt.Println("  (none)")
			}

			return nil
		},
	}
}

func newSessionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sessions",
		Short: "List all sessions with state and outcome",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionsDir := paths.SessionsDir()
			entries, err := os.ReadDir(sessionsDir)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Println("No sessions found.")
					return nil
				}
				return err
			}

			type sessionInfo struct {
				ID      string
				State   string
				Agent   string
				Net     string
				Outcome string
				Created string
				Age     string
			}

			var sessions []sessionInfo
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				id := e.Name()
				mgr, err := session.Load(paths.StateDir(), id)
				if err != nil {
					continue
				}
				snap := mgr.Snapshot()
				mgr.Close()

				var age string
				if t, err := time.Parse(time.RFC3339Nano, snap.CreatedAt); err == nil {
					d := time.Since(t)
					switch {
					case d < time.Minute:
						age = fmt.Sprintf("%ds", int(d.Seconds()))
					case d < time.Hour:
						age = fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
					case d < 24*time.Hour:
						age = fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
					default:
						age = fmt.Sprintf("%dd", int(d.Hours()/24))
					}
				}

				sessions = append(sessions, sessionInfo{
					ID:      id,
					State:   string(snap.State),
					Agent:   snap.Agent,
					Net:     snap.NetProfile,
					Outcome: snap.Outcome,
					Created: snap.CreatedAt[:19],
					Age:     age,
				})
			}

			if len(sessions) == 0 {
				fmt.Println("No sessions found.")
				return nil
			}

			sort.Slice(sessions, func(i, j int) bool {
				return sessions[i].Created > sessions[j].Created
			})

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATE\tAGENT\tNET\tOUTCOME\tCREATED\tAGE")
			for _, s := range sessions {
				outcome := s.Outcome
				if outcome == "" {
					outcome = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					s.ID[:8], s.State, s.Agent, s.Net, outcome, s.Created, s.Age)
			}
			w.Flush()

			fmt.Printf("\n%d session(s)\n", len(sessions))
			return nil
		},
	}
}

func formatSize(bytes int64) string {
	switch {
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(bytes)/(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
