package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/eth0x1/aegis/internal/agents"
)

const version = "0.1.0"

func newRootCmd() *cobra.Command {
	var netProfile string
	var projectPath string
	root := &cobra.Command{
		Use:   "aegis",
		Short: "AEGIS zero-trust security runtime for AI coding agents",
		Long: `AEGIS runs AI coding agents inside an isolated sandbox where:
  - the launch directory (PROJECT_ROOT) is mounted as /workspace — the only
    reachable, writable realm; everything outside it is invisible,
  - network egress is allowlisted at the network layer,
  - all agent activity is observed and correlated,
  - every change is baselined and security-validated before the session is
    released ("aegis apply" validates and records).

The AI agent is never its own security authority.

Running "aegis" with no subcommand auto-detects an available agent and
launches an interactive session in the current project directory.

Getting started:
  aegis run                        # interactive sandbox shell
  aegis run opencode               # launch opencode in sandbox
  aegis run --net dev opencode     # opencode with dev network access`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If args are provided, treat as: aegis <command> [args...]
			// This is a convenience shortcut for "aegis run <args...>"
			if len(args) > 0 {
				runCmd := newRunCmd()
				runArgs := args
				if projectPath != "" {
					runArgs = append([]string{"--project", projectPath}, runArgs...)
				}
				if netProfile != "" && netProfile != "strict" {
					runArgs = append([]string{"--net", netProfile}, runArgs...)
				}
				runCmd.SetArgs(runArgs)
				return runCmd.Execute()
			}

			// No args: show help with available agents
			available := agents.ListAvailable()
			if len(available) > 0 {
				fmt.Fprintf(os.Stderr, "available agents: %s\n\n", joinAgents(available))
			}
			return cmd.Help()
		},
	}
	root.PersistentFlags().StringVar(&netProfile, "net", "strict", "agent network profile (strict|dev)")
	root.PersistentFlags().StringVar(&projectPath, "project", "", "project root path (default: the launch directory)")
	root.AddCommand(
		newInitCmd(),
		newDoctorCmd(),
		newReportCmd(),
		newApplyCmd(),
		newPreflightCmd(),
		newRunCmd(),
		newStatusCmd(),
		newSessionsCmd(),
		newAnalyzeCmd(),
	)
	return root
}

func joinAgents(a []string) string {
	s := ""
	for i, name := range a {
		if i > 0 {
			s += ", "
		}
		s += name
	}
	return s
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "aegis:", err)
		os.Exit(1)
	}
}
