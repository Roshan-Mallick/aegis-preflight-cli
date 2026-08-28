package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/paths"
	"github.com/eth0x1/aegis/internal/preflight"
	"github.com/eth0x1/aegis/internal/session"
	"github.com/eth0x1/aegis/internal/workspace"
)

func newPreflightCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "preflight [session-id]",
		Short: "Run PreFlight security validation on a finished session (BLOCK/FIX/RESCAN, max 3 cycles)",
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

			switch snap.State {
			case session.StateAgentFinished, session.StatePreflight, session.StateSecurityScan:
			default:
				return fmt.Errorf("session %s is in state %s; preflight requires AGENT_FINISHED/SECURITY_SCAN/PREFLIGHT",
					id, snap.State)
			}
			if snap.Workspace == "" {
				return fmt.Errorf("session %s has no workspace record", id)
			}

			if snap.State != session.StatePreflight {
				if err := mgr.Transition(session.StatePreflight, nil); err != nil {
					return err
				}
			}

			store, err := events.Open(mgr.Dir())
			if err != nil {
				return err
			}
			defer store.Close()

			opts := preflight.RunOptions{SessionID: snap.SessionID, Store: store}
			cb := preflight.LoopCallbacks{
				BeforeCycle: func(ctx context.Context, cycle int) error {
					return nil
				},
				PublishFixRequest: func(ctx context.Context, cycle int, res *preflight.Result) error {
					fmt.Printf("cycle %d: BLOCK (%d blocking finding(s)) — fix request written to workspace\n",
						cycle, res.Blocking)
					return preflight.WriteFixRequest(mgr.Dir(), snap.Workspace, cycle, res)
				},
				BeforeRescan: func(ctx context.Context, cycle int) error {
					return nil
				},
			}

			final, err := preflight.RunLoop(context.Background(), snap.Workspace, opts, cb, nil)
			if err != nil {
				return err
			}

			for _, r := range final.AllResults {
				fmt.Printf("cycle %d: %s (%d finding(s), %d blocking)\n",
					r.Cycle, r.Verdict, r.Total, r.Blocking)
			}

			if !final.Passed {
				if err := mgr.Transition(session.StateBlock, map[string]any{
					"reason":        "preflight failed after max cycles",
					"cycles":        final.Cycles,
					"blocking_last": final.Last.Blocking,
				}); err != nil {
					return err
				}
				if err := mgr.SetOutcome("blocked"); err != nil {
					return err
				}
				fmt.Println("PREFLIGHT BLOCKED — session BLOCKED; changes will NOT be promoted")
				return fmt.Errorf("PREFLIGHT BLOCKED after %d cycle(s); changes will NOT be promoted", final.Cycles)
			}

			// Preflight passed — generate verified diff.
			before, err := workspace.LoadManifest(mgr.Dir())
			if err == nil {
				vd, verr := preflight.GenerateVerifiedDiff(snap.SessionID, before, snap.Workspace, final.Cycles)
				if verr == nil {
					if werr := preflight.WriteVerifiedArtifacts(mgr.Dir(), vd); werr == nil {
						fmt.Printf("verified diff: %d change(s) staged\n", len(vd.Changes))
					}
				}
			}

			if err := mgr.Transition(session.StatePass, map[string]any{
				"cycles": final.Cycles,
			}); err != nil {
				return err
			}
			if err := mgr.SetOutcome("verified"); err != nil {
				return err
			}
			fmt.Println("PREFLIGHT PASSED — session PASS; run 'aegis apply' to promote")
			return nil
		},
	}
}
