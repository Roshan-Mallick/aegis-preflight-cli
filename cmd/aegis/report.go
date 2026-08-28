package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/observer"
	"github.com/eth0x1/aegis/internal/paths"
	"github.com/eth0x1/aegis/internal/session"
)

func newReportCmd() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "report [session-id]",
		Short: "Show session summary (latest session when omitted)",
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
			evts, err := events.ReadAll(mgr.Dir())
			if err != nil {
				return err
			}
			renderReport(cmd.OutOrStdout(), mgr.Snapshot(), evts)
			if follow {
				fmt.Println("\nfollowing live events (ctrl-c to stop)...")
				ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
				defer cancel()
				printer := func(line []byte) {
					var e events.Event
					if json.Unmarshal(line, &e) != nil {
						return
					}
					fmt.Printf("  %s  [%-7s] %-18s %-8s %s\n", e.Timestamp, e.Source, e.Type, e.Severity, e.Actor)
				}
				observer.FollowJSONL(ctx, events.LogPath(mgr.Dir()), 500*time.Millisecond, printer)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&follow, "follow", false, "keep running and print new canonical events live")
	return cmd
}

func renderReport(w io.Writer, meta session.Metadata, evts []events.Event) {
	fmt.Fprintf(w, "SESSION %s\n", meta.SessionID)
	fmt.Fprintf(w, "  state:      %s\n", meta.State)
	if meta.Outcome != "" {
		fmt.Fprintf(w, "  outcome:    %s\n", meta.Outcome)
	}
	fmt.Fprintf(w, "  created:    %s\n", meta.CreatedAt)
	fmt.Fprintf(w, "  updated:    %s\n", meta.UpdatedAt)
	fmt.Fprintf(w, "  project:    %s\n", meta.ProjectRoot)
	fmt.Fprintf(w, "  workspace:  %s\n", meta.Workspace)
	fmt.Fprintf(w, "  agent:      %s\n", meta.Agent)
	fmt.Fprintf(w, "  net:        %s\n", meta.NetProfile)
	if len(meta.IncidentIDs) > 0 {
		fmt.Fprintf(w, "  incidents:  %v\n", meta.IncidentIDs)
	}
	fmt.Fprintf(w, "  preflight:  %d cycle(s)\n", meta.PreflightCycles)
	fmt.Fprintln(w)

	sevCount := map[string]int{}
	typeCount := map[string]int{}
	for _, e := range evts {
		sevCount[e.Severity]++
		typeCount[e.Type]++
	}
	fmt.Fprintf(w, "EVENTS (%d total)\n", len(evts))
	fmt.Fprintf(w, "  by severity:\n")
	for _, s := range sortedKeys(sevCount) {
		fmt.Fprintf(w, "    %-8s %d\n", s, sevCount[s])
	}
	fmt.Fprintf(w, "  by type:\n")
	for _, t := range sortedKeys(typeCount) {
		fmt.Fprintf(w, "    %-20s %d\n", t, typeCount[t])
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "STATE TIMELINE\n")
	for _, e := range evts {
		if e.Type != events.TypeSessionState && e.Type != events.TypeSessionCreated {
			continue
		}
		from, _ := e.Data["from"].(string)
		to, _ := e.Data["to"].(string)
		switch {
		case e.Type == events.TypeSessionCreated:
			fmt.Fprintf(w, "  %s  %s\n", e.Timestamp, session.StateCreated)
		case from == "":
			fmt.Fprintf(w, "  %s  %s\n", e.Timestamp, to)
		default:
			fmt.Fprintf(w, "  %s  %s -> %s\n", e.Timestamp, from, to)
		}
	}
	fmt.Fprintln(w)

	tail := evts
	if len(tail) > 20 {
		tail = tail[len(tail)-20:]
	}
	fmt.Fprintf(w, "RECENT EVENTS (last %d)\n", len(tail))
	for _, e := range tail {
		fmt.Fprintf(w, "  %s  [%-7s] %-18s %-8s %s\n", e.Timestamp, e.Source, e.Type, e.Severity, e.Actor)
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
