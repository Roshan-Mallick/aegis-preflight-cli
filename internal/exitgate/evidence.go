// Package exitgate implements the AEGIS Local AI exit gate: a final security
// review that runs ONLY when the agent requests to exit, after the
// deterministic preflight checks have already passed.
//
// Token budget: the local model receives a small structured SECURITY SUMMARY
// (paths, hashes, counts, command names, observed destinations, findings),
// never the conversation, source files, raw command output or secrets. Any
// secret-shaped material that slips into an evidence field is redacted before
// it can reach a prompt. Unchanged evidence between remediation retries is
// served from an in-session cache keyed by the evidence digest, so nothing is
// re-sent unless the workspace actually changed.
package exitgate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/findings"
	"github.com/eth0x1/aegis/internal/policy"
	"github.com/eth0x1/aegis/internal/workspace"
)

const (
	EvidenceVersion = 1

	// MaxEvidenceJSON bounds the serialized SECURITY SUMMARY the model
	// receives, forcing the summary to stay compact no matter how large the
	// session or workspace grew.
	MaxEvidenceJSON = 16 * 1024

	maxChanges        = 200
	maxCommands       = 25
	maxSensitivePaths = 20
	maxDestinations   = 15
	maxFindings       = 40
	maxIncidents      = 5
	maxSnippets       = 3
	maxSnippetLines   = 12
	maxSnippetBytes   = 64 * 1024
)

// ChangeRef is one changed path with metadata — no content.
type ChangeRef struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	Size int64  `json:"size,omitempty"`
	Hash string `json:"hash,omitempty"` // sha256 prefix of the new entry
}

// Destination is an externally reachable host that was actually observed.
type Destination struct {
	Domain  string `json:"domain"`
	Port    int    `json:"port,omitempty"`
	Intent  string `json:"intent,omitempty"` // observed tool kind, e.g. webserver_fetch
	Reason  string `json:"reason,omitempty"` // proxy decision reason (blocks only)
	Blocked bool   `json:"blocked,omitempty"`
}

// Network summarizes observed external access without guessing.
type Network struct {
	ExternalAccess string        `json:"external_access"` // "none" or "observed"
	Destinations   []Destination `json:"destinations,omitempty"`
}

// ResFinding is a scanner finding condensed for the review.
type ResFinding struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message"`
	Blocking bool   `json:"blocking,omitempty"`
}

// Snippet is a tiny redacted excerpt of a changed file, included ONLY when a
// finding or sensitive access makes it necessary.
type Snippet struct {
	Path  string   `json:"path"`
	Lines []string `json:"lines"`
}

// Evidence is the complete localized SECURITY SUMMARY sent to the model.
type Evidence struct {
	Version           int            `json:"version"`
	ReviewID          string         `json:"review_id"`
	Cycle             int            `json:"cycle"`
	Task              string         `json:"task,omitempty"`
	Profile           string         `json:"profile,omitempty"`
	ChangeCounts      map[string]int `json:"change_counts"`
	Changes           []ChangeRef    `json:"changes,omitempty"`
	Commands          []string       `json:"commands,omitempty"`
	SensitiveAccesses []string       `json:"sensitive_accesses,omitempty"`
	Network           Network        `json:"network"`
	ScreenOrUI        string         `json:"screen_ui_access"`
	Findings          []ResFinding   `json:"findings,omitempty"`
	Incidents         []string       `json:"incidents,omitempty"`
	Snippets          []Snippet      `json:"snippets,omitempty"`
	ReadWarnings      []string       `json:"read_warnings,omitempty"`
}

// Input carries the session context needed to build an Evidence summary.
type Input struct {
	SessionID  string
	SessionDir string
	Workspace  string
	Cycle      int
	Task       string
	Profile    string
	Findings   []findings.Finding
	Baseline   workspace.Manifest // optional; empty loads from SessionDir
}

// BuildEvidence assembles the compact security summary for the exit review.
func BuildEvidence(ctx context.Context, in Input) (*Evidence, error) {
	baseline := in.Baseline
	if baseline == nil {
		var err error
		baseline, err = workspace.LoadManifest(in.SessionDir)
		if err != nil {
			return nil, fmt.Errorf("load session manifest: %w", err)
		}
	}
	changes, _, err := workspace.ComputeDiff(baseline, in.Workspace)
	if err != nil {
		return nil, fmt.Errorf("compute change set: %w", err)
	}

	ev := &Evidence{
		Version:      EvidenceVersion,
		Cycle:        in.Cycle,
		Task:         Redact(truncate(stripNewlines(in.Task), 160)),
		Profile:      in.Profile,
		ChangeCounts: map[string]int{},
		ScreenOrUI:   "none observed",
	}

	for _, ch := range changes {
		if len(ev.Changes) < maxChanges {
			ref := ChangeRef{Path: ch.Path, Kind: string(ch.Kind)}
			if ch.New != nil {
				ref.Size = ch.New.Size
				if len(ch.New.SHA256) >= 12 {
					ref.Hash = ch.New.SHA256[:12]
				}
			}
			ev.Changes = append(ev.Changes, ref)
		}
		ev.ChangeCounts[string(ch.Kind)]++
	}

	allEvs, err := events.ReadAll(in.SessionDir)
	if err != nil {
		ev.ReadWarnings = append(ev.ReadWarnings, "event log unreadable: "+err.Error())
	}
	collectEvents(allEvs, ev)
	collectFindings(in.Findings, ev)
	collectSnippets(in.Workspace, ev)

	// Cap the serialized summary so the model always receives a small blob.
	compact(ev)
	ev.ReviewID = evidenceDigest(ev)
	return ev, nil
}

func collectEvents(all []events.Event, ev *Evidence) {
	cmdSeen := map[string]bool{}
	destSeen := map[string]bool{}
	for _, e := range all {
		switch {
		case e.Source == events.SourceHook && e.Type == events.TypeCommandExec:
			if cmd := str(e.Data, "command"); cmd != "" {
				cmd = Redact(truncate(stripNewlines(cmd), 120))
				if cmd == "" || cmdSeen[cmd] {
					continue
				}
				cmdSeen[cmd] = true
				if len(ev.Commands) < maxCommands {
					ev.Commands = append(ev.Commands, cmd)
				}
			}
		case e.Source == events.SourceHook &&
			(e.Type == events.TypeFileRead || e.Type == events.TypeFileWrite):
			if b, ok := e.Data["sensitive"].(bool); ok && b {
				if p := str(e.Data, "path"); p != "" {
					if len(ev.SensitiveAccesses) < maxSensitivePaths {
						ev.SensitiveAccesses = append(ev.SensitiveAccesses, p)
					}
				}
			}
		case e.Source == events.SourceProxy && e.Type == events.TypeNetworkConnect:
			dom := str(e.Data, "domain")
			if dom == "" {
				continue
			}
			d := Destination{
				Domain:  dom,
				Port:    port(e.Data, "port"),
				Reason:  Redact(truncate(str(e.Data, "reason"), 120)),
				Blocked: str(e.Data, "decision") == "block",
			}
			key := fmt.Sprintf("%s:%d:%t", d.Domain, d.Port, d.Blocked)
			if destSeen[key] {
				continue
			}
			destSeen[key] = true
			if len(ev.Destinations()) < maxDestinations {
				ev.Network.Destinations = append(ev.Network.Destinations, d)
			}
		case e.Source == events.SourceHook && e.Type == events.TypeNetworkConnect:
			if u := str(e.Data, "url"); u != "" {
				if host := hostOf(u); host != "" {
					key := "intent:" + host
					if !destSeen[key] {
						destSeen[key] = true
						if len(ev.Destinations()) < maxDestinations {
							ev.Network.Destinations = append(ev.Network.Destinations,
								Destination{Domain: host, Intent: "agent_web_tool"})
						}
					}
				}
			}
		case e.Source == events.SourcePolicy && e.Type == events.TypeIncident:
			rule := str(e.Data, "rule_id")
			sum := Redact(truncate(stripNewlines(str(e.Data, "summary")), 180))
			if rule == "" && sum == "" {
				continue
			}
			s := strings.TrimSpace(rule + ": " + sum)
			if len(ev.Incidents) < maxIncidents {
				ev.Incidents = append(ev.Incidents, s)
			}
		}
	}

	ev.Network.ExternalAccess = externalAccess(ev.Network.Destinations)
}

// Destinations is a helper so the cap check above reads plainly.
func (ev *Evidence) Destinations() []Destination { return ev.Network.Destinations }

func externalAccess(dests []Destination) string {
	if len(dests) == 0 {
		return "none"
	}
	return fmt.Sprintf("observed (%d destination(s))", len(dests))
}

func collectFindings(fs []findings.Finding, ev *Evidence) {
	for _, f := range fs {
		if !f.Blocking && (f.Severity == findings.SevInfo || f.Severity == findings.SevLow) {
			continue // drop scanner skip-noise; keep anything security-relevant
		}
		if len(ev.Findings) >= maxFindings {
			break
		}
		ev.Findings = append(ev.Findings, ResFinding{
			Severity: f.Severity,
			Rule:     f.Rule,
			File:     f.File,
			Line:     f.Line,
			Message:  Redact(truncate(f.Message, 160)),
			Blocking: f.Blocking,
		})
	}
}

// collectSnippets attaches tiny redacted excerpts of changed files that a
// finding or a sensitive access explicitly points at — and nothing else. Raw
// file contents are never sent; sensitive paths are never read at all.
func collectSnippets(ws string, ev *Evidence) {
	need := false
	for _, f := range ev.Findings {
		if f.File != "" {
			need = true
			break
		}
	}
	if !need && len(ev.SensitiveAccesses) == 0 {
		return
	}
	seen := map[string]bool{}
	for _, f := range ev.Findings {
		if f.File == "" || len(ev.Snippets) >= maxSnippets {
			continue
		}
		if seen[f.File] || policy.IsSensitivePath(f.File) {
			continue
		}
		seen[f.File] = true
		if sn, ok := readSnippet(ws, f.File); ok {
			ev.Snippets = append(ev.Snippets, sn)
		}
	}
	if len(ev.Snippets) == 0 {
		// Fall back to a changed sensitive path listing (paths only, already
		// present in SensitiveAccesses) — no content from these files.
		return
	}
}

func readSnippet(ws, rel string) (Snippet, bool) {
	abs := filepath.Join(ws, filepath.FromSlash(rel))
	info, err := os.Stat(abs)
	if err != nil || info.IsDir() || info.Size() > maxSnippetBytes {
		return Snippet{}, false
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return Snippet{}, false
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxSnippetLines {
		lines = lines[:maxSnippetLines]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, Redact(truncate(l, 120)))
	}
	return Snippet{Path: rel, Lines: out}, true
}

func compact(ev *Evidence) {
	if ev.marshalLen() <= MaxEvidenceJSON {
		return
	}
	ev.Snippets = nil
	if ev.marshalLen() <= MaxEvidenceJSON {
		return
	}
	ev.Findings = trimFindings(ev.Findings, 10)
	ev.Commands = trimStrs(ev.Commands, 10)
	ev.SensitiveAccesses = trimStrs(ev.SensitiveAccesses, 10)
	ev.Network.Destinations = trimDests(ev.Network.Destinations, 6)
	ev.Changes = trimChanges(ev.Changes, 80)
	ev.Incidents = trimStrs(ev.Incidents, 3)
}

func (ev *Evidence) marshalLen() int {
	b, _ := json.Marshal(ev)
	return len(b)
}

func trimStrs(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func trimFindings(in []ResFinding, n int) []ResFinding {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func trimChanges(in []ChangeRef, n int) []ChangeRef {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func trimDests(in []Destination, n int) []Destination {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

// evidenceDigest is a stable content hash of the summary (excluding the digest
// field itself), used as the cache key and review_id so unchanged evidence is
// never re-sent between remediation retries.
func evidenceDigest(ev *Evidence) string {
	clone := *ev
	clone.ReviewID = ""
	b, _ := json.Marshal(clone)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func port(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}