package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/eth0x1/aegis/internal/images"
	"github.com/eth0x1/aegis/internal/network"
	"github.com/eth0x1/aegis/internal/paths"
	"github.com/eth0x1/aegis/internal/sandbox"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Prepare local AEGIS components and verify dependencies",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := paths.EnsureSessionsDir()
			if err != nil {
				return fmt.Errorf("create sessions dir: %w", err)
			}
			fmt.Println("state directory ready:", dir)

			results := runDoctorChecks()
			failed := false
			for _, r := range results {
				fmt.Printf("[%-4s] %-24s %s\n", r.Status, r.Name, r.Detail)
				if r.Status == stFail {
					failed = true
				}
			}
			if failed {
				fmt.Println("\ninit incomplete — resolve FAIL items above")
				return fmt.Errorf("environment not ready")
			}

			if dockerReachable(results) {
				fmt.Println("building agent image (first run may download base layers)...")
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				if err := sandbox.EnsureAgentImage(ctx); err != nil {
					return fmt.Errorf("agent image: %w", err)
				}
				fmt.Println("agent image ready:", images.AgentImage)
				if err := sandbox.EnsureRuntimeImage(ctx); err != nil {
					return fmt.Errorf("runtime image: %w", err)
				}
				fmt.Println("runtime image ready:", images.RuntimeImage)
				if err := network.EnsureProxyImage(ctx); err != nil {
					return fmt.Errorf("proxy image: %w", err)
				}
				fmt.Println("proxy image ready:", images.ProxyImage)
			}
			fmt.Println("\ninit complete — launch arrives with TUI integration")
			return nil
		},
	}
}

func dockerReachable(results []checkResult) bool {
	for _, r := range results {
		if r.Name == "docker daemon" && r.Status == stOK {
			return true
		}
	}
	return false
}
