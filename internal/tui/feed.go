package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/eth0x1/aegis/internal/events"
)

var (
	severityStyle = map[string]lipgloss.Style{
		"critical": lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true),
		"high":     lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true),
		"medium":   lipgloss.NewStyle().Foreground(lipgloss.Color("220")),
		"low":      lipgloss.NewStyle().Foreground(lipgloss.Color("250")),
		"info":     lipgloss.NewStyle().Foreground(lipgloss.Color("244")),
	}
	eventTypeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	policyStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("170")).Bold(true)
	viewBoxStyle   = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(0, 1)
	timestampStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	feedTitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).
			Bold(true).
			Padding(0, 1)
	dedupCountStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Italic(true)
)

// feedEvent is the structured representation of a security event for display.
type feedEvent struct {
	ts     string
	typ    string
	actor  string
	source string
	sep    string // separator between type and actor/source
}

// Feed renders the live security event feed with deduplication of repeated
// consecutive events.
type Feed struct {
	lines       []string
	max         int
	lastKey     string
	dedupCount  int
	dedupWindow time.Duration
	lastPush    time.Time
}

func NewFeed(maxLines int) *Feed {
	if maxLines <= 0 {
		maxLines = 200
	}
	return &Feed{
		max:         maxLines,
		dedupWindow: 30 * time.Second,
	}
}

func formatTimestamp(ts string) string {
	if ts == "" {
		return time.Now().Format("15:04:05")
	}
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		if len(ts) >= 19 {
			return ts[11:19]
		}
		return ts
	}
	return parsed.Format("15:04:05")
}

func dataString(data map[string]any, keys ...string) string {
	parts := []string{}
	for _, k := range keys {
		if v, ok := data[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, " ")
}

// dedupKey returns a key for consecutive deduplication: type + actor + data fingerprint.
// Events with different data are not deduplicated (e.g., different command arguments).
func dedupKey(evt events.Event) string {
	return evt.Type + "|" + evt.Actor + "|" + dataFingerprint(evt.Data)
}

// dataFingerprint returns a stable string fingerprint of a data map.
func dataFingerprint(data map[string]any) string {
	if len(data) == 0 {
		return ""
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%v ", k, data[k])
	}
	return b.String()
}

// Push adds an event to the feed, deduplicating consecutive identical events.
func (f *Feed) Push(evt events.Event) {
	key := dedupKey(evt)
	now := time.Now()

	// Dedup consecutive identical events within the time window.
	if key == f.lastKey && now.Sub(f.lastPush) < f.dedupWindow {
		f.dedupCount++
		// Update the last display line with the count.
		if len(f.lines) > 0 {
			fe := buildFeedEvent(evt)
			f.lines[len(f.lines)-1] = renderFeedLine(fe, f.dedupCount)
		}
		return
	}

	// New event — reset dedup state.
	f.lastKey = key
	f.dedupCount = 1
	f.lastPush = now

	fe := buildFeedEvent(evt)
	f.lines = append(f.lines, renderFeedLine(fe, 1))
	if len(f.lines) > f.max {
		f.lines = f.lines[len(f.lines)-f.max:]
	}
}

// buildFeedEvent converts a raw event into a structured feedEvent for display.
func buildFeedEvent(evt events.Event) feedEvent {
	ts := formatTimestamp(evt.Timestamp)
	switch evt.Type {
	case events.TypeFinding:
		return feedEvent{
			ts:    ts,
			typ:   "FINDING",
			actor: dataString(evt.Data, "rule", "file", "message"),
			sep:   " ",
		}
	case events.TypeCommandExec, events.TypeFileRead, events.TypeFileWrite, events.TypeNetworkConnect:
		return feedEvent{
			ts:    ts,
			typ:   strings.ToUpper(evt.Type),
			actor: evt.Actor,
			sep:   " ",
		}
	case "policy.preflight":
		return feedEvent{
			ts:    ts,
			typ:   "PREFLIGHT",
			actor: dataString(evt.Data, "verdict", "blocking", "message"),
			sep:   " ",
		}
	case events.TypeIncident:
		return feedEvent{
			ts:    ts,
			typ:   "INCIDENT",
			actor: dataString(evt.Data, "rule", "message"),
			sep:   " ",
		}
	case events.TypeSessionState:
		return feedEvent{
			ts:    ts,
			typ:   "STATE",
			actor: dataString(evt.Data, "state", "previous_state"),
			sep:   " ",
		}
	default:
		return feedEvent{
			ts:    ts,
			typ:   strings.ToUpper(evt.Type),
			actor: evt.Source,
			sep:   " ",
		}
	}
}

// renderFeedLine renders a single feed line with optional dedup count.
func renderFeedLine(fe feedEvent, count int) string {
	tsStr := timestampStyle.Render(fe.ts)
	typeStr := eventTypeStyle.Render(fe.typ)

	// Special styling for certain types.
	switch fe.typ {
	case "FINDING":
		typeStr = severityStyle["medium"].Render(fe.typ)
	case "PREFLIGHT":
		typeStr = policyStyle.Render(fe.typ)
	case "INCIDENT":
		typeStr = severityStyle["critical"].Render(fe.typ)
	}

	var line string
	if count > 1 {
		line = fmt.Sprintf("%s  %-14s %s %s",
			tsStr, typeStr, fe.actor, dedupCountStyle.Render(fmt.Sprintf("×%d", count)))
	} else {
		line = fmt.Sprintf("%s  %-14s %s",
			tsStr, typeStr, fe.actor)
	}
	return line
}

func (f *Feed) Lines() []string {
	return f.lines
}

func (f *Feed) View(width, height int) string {
	title := feedTitleStyle.Render(" Security Feed ")
	content := strings.Join(f.lines, "\n")
	return viewBoxStyle.
		Width(width - 2).
		Height(height - 2).
		Render(title + "\n" + content)
}
