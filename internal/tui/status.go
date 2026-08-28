package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("236")).
			Padding(0, 1)
	statusKeyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")).
			Bold(true)
	statusValueStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("255"))
	statusSepStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))
	stateReady   = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)
	stateBlocked = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	stateRunning = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	stateWarn    = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
)

type StatusBar struct {
	SessionID    string
	State        string
	StartedAt    time.Time
	FindingCount int
	BlockCount   int
	Network      string
	AgentID      string
	Width        int
}

func (s StatusBar) renderState() string {
	switch s.State {
	case "running":
		return stateRunning.Render(s.State)
	case "blocked", "failed":
		return stateBlocked.Render(strings.ToUpper(s.State))
	case "waiting-for-network":
		return stateWarn.Render("WAITING")
	default:
		return stateReady.Render(s.State)
	}
}

// shortID returns the first n characters of an ID, or the full string if shorter.
func shortIDN(id string, n int) string {
	if len(id) < n {
		return id
	}
	return id[:n]
}

func (s StatusBar) View() string {
	if s.Width <= 0 {
		s.Width = 80
	}
	elapsed := ""
	if !s.StartedAt.IsZero() {
		d := time.Since(s.StartedAt)
		elapsed = fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	sep := statusSepStyle.Render(" │ ")
	parts := []string{
		statusKeyStyle.Render("STATE") + " " + s.renderState(),
		statusKeyStyle.Render("SESSION") + " " + statusValueStyle.Render(shortIDN(s.SessionID, 8)),
	}
	if s.AgentID != "" {
		agent := s.AgentID
		if len(agent) > 12 {
			agent = agent[:12]
		}
		parts = append(parts, statusKeyStyle.Render("AGENT")+" "+statusValueStyle.Render(agent))
	}
	parts = append(parts,
		statusKeyStyle.Render("FINDINGS")+" "+statusValueStyle.Render(fmt.Sprintf("%d/%d", s.FindingCount, s.BlockCount))+
			statusSepStyle.Render(" ")+statusValueStyle.Render("blocking"),
		statusKeyStyle.Render("NET")+" "+statusValueStyle.Render(s.Network),
	)
	if elapsed != "" {
		parts = append(parts, statusKeyStyle.Render("TIME")+" "+statusValueStyle.Render(elapsed))
	}
	bar := statusBarStyle.Render(strings.Join(parts, sep))
	remaining := s.Width - lipgloss.Width(bar)
	if remaining > 0 {
		bar += statusBarStyle.Render(strings.Repeat(" ", remaining))
	}
	return bar
}
