package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/eth0x1/aegis/internal/correlate"
	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/session"
)

func RenderIncident(meta session.Metadata, inc correlate.Incident, evidenceRef string, all []events.Event) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# AEGIS INCIDENT REPORT")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "**VERDICT: SESSION COMPROMISED — SANDBOX TERMINATED**\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Incident ID | `%s` |\n", inc.ID)
	fmt.Fprintf(&b, "| Session | `%s` |\n", meta.SessionID)
	fmt.Fprintf(&b, "| Rule | `%s` |\n", inc.RuleID)
	fmt.Fprintf(&b, "| Detected | %s |\n", inc.DetectedAt)
	fmt.Fprintf(&b, "| Project | `%s` |\n", meta.ProjectRoot)
	fmt.Fprintf(&b, "| Agent | %s (net profile: %s) |\n", meta.Agent, meta.NetProfile)
	fmt.Fprintf(&b, "| Final state | %s |\n", meta.State)
	if evidenceRef != "" {
		fmt.Fprintf(&b, "| Evidence image | `%s` |\n", evidenceRef)
	}
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "## Detection\n\n%s\n\n", inc.Summary)

	fmt.Fprint(&b, "## Correlated event timeline\n\n")
	fmt.Fprintln(&b, "| Time (UTC) | Source | Type | Severity | Detail |")
	fmt.Fprintln(&b, "|---|---|---|---|---|")
	for _, e := range inc.Events {
		detail := describe(e)
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
			e.Timestamp, e.Source, e.Type, e.Severity, detail)
	}
	fmt.Fprintln(&b)

	sev := map[string]int{}
	for _, e := range all {
		sev[e.Severity]++
	}
	fmt.Fprintf(&b, "## Full session event totals (%d events)\n\n", len(all))
	keys := make([]string, 0, len(sev))
	for k := range sev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "- %s: %d\n", k, sev[k])
	}
	fmt.Fprintln(&b)

	fmt.Fprint(&b, "## Response executed\n\n")
	fmt.Fprintln(&b, "1. Evidence preserved (canonical log split views, container inspect, workspace diff, incident record)")
	if evidenceRef != "" {
		fmt.Fprintf(&b, "2. Container state committed to image `%s` BEFORE termination\n", evidenceRef)
	}
	fmt.Fprintln(&b, "3. Agent sandbox killed; session marked TERMINATED / outcome=compromised")
	fmt.Fprintln(&b, "4. No changes can be promoted from this session (state gate blocks apply)")
	fmt.Fprintln(&b)
	fmt.Fprint(&b, "## Honest limitations\n\n")
	fmt.Fprintln(&b, "- Hook-level observation is tool-call level, not syscall level.")
	fmt.Fprintln(&b, "- Encrypted payloads to ALLOWED destinations are not inspected in v1.")
	fmt.Fprintln(&b, "- Docker isolation defends against misbehavior, not kernel exploits.")
	fmt.Fprintln(&b)
	return b.String()
}

func describe(e events.Event) string {
	switch e.Type {
	case events.TypeCommandExec:
		cmd, _ := e.Data["command"].(string)
		return "`" + cmd + "`"
	case events.TypeFileRead, events.TypeFileWrite, events.TypeFileDelete:
		p, _ := e.Data["path"].(string)
		s, _ := e.Data["sensitive"].(bool)
		if s {
			return "`" + p + "` (SENSITIVE)"
		}
		return "`" + p + "`"
	case events.TypeNetworkConnect:
		d, _ := e.Data["domain"].(string)
		dec, _ := e.Data["decision"].(string)
		r, _ := e.Data["reason"].(string)
		return fmt.Sprintf("`%s` decision=%s reason=%q", d, dec, r)
	default:
		return fmt.Sprintf("%v", e.Data)
	}
}

func RenderSummary(meta session.Metadata, evts []events.Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# AEGIS SESSION REPORT\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Session | `%s` |\n", meta.SessionID)
	fmt.Fprintf(&b, "| State | %s |\n", meta.State)
	if meta.Outcome != "" {
		fmt.Fprintf(&b, "| Outcome | %s |\n", meta.Outcome)
	}
	fmt.Fprintf(&b, "| Created | %s |\n", meta.CreatedAt)
	fmt.Fprintf(&b, "| Updated | %s |\n", meta.UpdatedAt)
	fmt.Fprintf(&b, "| Project | `%s` |\n", meta.ProjectRoot)
	fmt.Fprintf(&b, "| Agent | %s |\n", meta.Agent)
	fmt.Fprintln(&b)
	if len(evts) == 0 {
		fmt.Fprint(&b, "_No canonical events recorded._\n\n")
		return b.String()
	}
	first, _ := time.Parse(time.RFC3339Nano, evts[0].Timestamp)
	last, _ := time.Parse(time.RFC3339Nano, evts[len(evts)-1].Timestamp)
	fmt.Fprintf(&b, "%d canonical events spanning %.1fs.\n\n", len(evts), last.Sub(first).Seconds())
	for _, e := range evts {
		fmt.Fprintf(&b, "- `%s` [%s/%s] %s: %s\n", e.Timestamp, e.Source, e.Severity, e.Type, describe(e))
	}
	fmt.Fprintln(&b)
	return b.String()
}
