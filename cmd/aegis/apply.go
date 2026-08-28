package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/eth0x1/aegis/internal/paths"
	"github.com/eth0x1/aegis/internal/session"
	"github.com/eth0x1/aegis/internal/workspace"
)

func newApplyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "apply [session-id]",
		Short: "Apply a PASS session diff to the trusted project (explicit user action)",
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

			meta := mgr.Snapshot()
			if meta.State != session.StatePass {
				return fmt.Errorf("session %s is in state %s; only PASS sessions can be applied",
					id, meta.State)
			}
			if meta.Workspace == "" || meta.ProjectRoot == "" {
				return fmt.Errorf("session %s lacks workspace/project records", id)
			}

			before, err := workspace.LoadManifest(mgr.Dir())
			if err != nil {
				return err
			}
			changes, current, err := workspace.ComputeDiff(before, meta.Workspace)
			if err != nil {
				return err
			}
			if len(changes) == 0 {
				fmt.Println("no changes to apply; session produced an empty diff")
				return nil
			}
			n, err := workspace.Apply(meta.ProjectRoot, meta.Workspace, before, changes)
			if err != nil {
				return fmt.Errorf("promotion failed after %d change(s): %w", n, err)
			}
			if err := workspace.SaveManifest(mgr.Dir(), current); err != nil {
				return err
			}

			// Transition through CLEANUP -> CLOSED.
			if err := mgr.Transition(session.StateCleanup, nil); err != nil {
				// May already be in cleanup-eligible state.
				_ = err
			}
			if err := mgr.Transition(session.StateClosed, nil); err != nil {
				_ = err
			}
			if err := mgr.SetOutcome("applied"); err != nil {
				return err
			}
			fmt.Printf("applied %d change(s) from session %s to %s\n", n, id, meta.ProjectRoot)
			for _, ch := range changes {
				fmt.Printf("  %-13s %s\n", ch.Kind, ch.Path)
			}
			return nil
		},
	}
}
