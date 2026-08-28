package main

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/pipeline"
	"github.com/eth0x1/aegis/internal/tui"
)

func pipelineEventFatal(err error) events.Event {
	return events.Event{
		Type:     events.TypeSessionState,
		Source:   events.SourceSandbox,
		Severity: "critical",
		Actor:    "aegis",
		Data:     map[string]any{"state": "error", "message": err.Error()},
	}
}

// splitTUIInteractive launches the split-view TUI (embedded interactive PTY +
// live security feed) for the sandbox. It forwards keystrokes to the real PTY,
// subscribes to the live security feed, and returns the sandbox command exit
// code once it terminates or the user quits.
func splitTUIInteractive(args []string, agentName, profile string) pipeline.InteractiveFunc {
	return func(ctx context.Context, opts pipeline.InteractiveOptions) int {
		if opts.Sandbox == nil {
			return 1
		}
		pts := tui.NewPTYSession(opts.Sandbox.ContainerName())
		out, err := pts.Start(args)
		if err != nil {
			opts.Feed.Publish(pipelineEventFatal(err))
			return 1
		}
		cfg := tui.Config{
			Session:    opts.Manager,
			Feed:       opts.Feed,
			PTYSession: pts,
			PTYOut:     out,
			Network:    profile,
			AgentName:  agentName,
		}
		model := tui.NewModel(cfg)
		p := tea.NewProgram(model, tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			pts.Close()
			return 1
		}
		pts.Close()
		code, _ := pts.Result()
		return code
	}
}
