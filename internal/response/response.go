package response

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/eth0x1/aegis/internal/correlate"
	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/report"
	"github.com/eth0x1/aegis/internal/session"
	"github.com/eth0x1/aegis/internal/workspace"
)

type Action string

const (
	ActionLog   Action = "LOG"
	ActionBlock Action = "BLOCK"
	ActionPause Action = "PAUSE"
	ActionKill  Action = "KILL"
)

func ActionsFor(severity string) []Action {
	switch severity {
	case events.SevInfo, events.SevLow:
		return []Action{ActionLog}
	case events.SevMedium:
		return []Action{ActionBlock}
	case events.SevHigh:
		return []Action{ActionBlock, ActionPause}
	case events.SevCritical:
		return []Action{ActionKill}
	default:
		return []Action{ActionLog}
	}
}

type ContainerController interface {
	Inspect(ctx context.Context) ([]byte, error)
	Commit(ctx context.Context, ref string) error
	Kill(ctx context.Context) error
}

type Responder struct {
	Ctrl        ContainerController
	Mgr         *session.Manager
	Store       *events.Store
	SessionDir  string
	Workspace   string
	Manifest    workspace.Manifest
	EvidenceRef string
	Now         func() time.Time
}

func (r *Responder) HandleFinding(ctx context.Context, f Finding) error {
	switch {
	case contains(ActionsFor(f.Severity), ActionKill):
		return r.ContainCritical(ctx, f.Incident)
	default:
		return nil
	}
}

type Finding struct {
	Severity string
	Incident correlate.Incident
	Reason   string
}

func contains(list []Action, a Action) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

func (r *Responder) ContainCritical(ctx context.Context, inc correlate.Incident) error {
	snap := r.Mgr.Snapshot()
	if !session.CanTransition(snap.State, session.StatePreservingEvidence) {
		return fmt.Errorf("containment refused: session in state %s cannot enter PRESERVING_EVIDENCE",
			snap.State)
	}
	var errs []error
	fail := func(step string, err error) {
		errs = append(errs, fmt.Errorf("%s: %w", step, err))
	}

	nowFn := r.Now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	evidenceRef := fmt.Sprintf("aegis-evidence-%s-%d", shortID(snap.SessionID), nowFn().Unix())
	r.EvidenceRef = evidenceRef

	incidentID := inc.ID
	if incidentID == "" {
		incidentID = uuid.NewString()
	}

	if err := r.Mgr.AddIncident(incidentID); err != nil {
		fail("record-incident-id", err)
	}
	if err := r.Mgr.Transition(session.StatePreservingEvidence, map[string]any{
		"incident_id": incidentID,
		"rule_id":     inc.RuleID,
	}); err != nil {
		fail("transition-preserving", err)
	}

	var inspectRaw []byte
	if r.Ctrl != nil {
		if raw, err := r.Ctrl.Inspect(ctx); err == nil {
			inspectRaw = raw
		} else {
			fail("container-inspect", err)
		}
		if err := r.Ctrl.Commit(ctx, evidenceRef); err != nil {
			fail("evidence-commit", err)
		}
	} else {
		evidenceRef = ""
	}

	diffText := ""
	if r.Workspace != "" && r.Manifest != nil {
		if changes, _, err := workspace.ComputeDiff(r.Manifest, r.Workspace); err == nil {
			diffText = renderDiff(changes)
		}
	}

	bundle := EvidenceBundle{
		Incident:    inc,
		IncidentID:  incidentID,
		EvidenceRef: evidenceRef,
		InspectJSON: inspectRaw,
		DiffText:    diffText,
		WrittenAt:   nowFn().UTC().Format(time.RFC3339Nano),
	}
	if pf, err := os.ReadFile(filepath.Join(r.SessionDir, "preflight-findings.json")); err == nil {
		bundle.PreflightFindings = pf
	}
	if err := r.writeBundle(bundle); err != nil {
		fail("evidence-bundle", err)
	}

	md := report.RenderIncident(r.Mgr.Snapshot(), inc, evidenceRef,
		mustReadAll(r.SessionDir))
	if err := os.WriteFile(filepath.Join(r.SessionDir, "report.md"), []byte(md), 0o600); err != nil {
		fail("report-md", err)
	}

	if r.Store != nil {
		corr := incidentID
		ev := events.WithCorrelation(events.New(events.SourcePolicy, events.TypeIncident,
			events.SevCritical, "aegis", snap.SessionID, map[string]any{
				"incident_id":       incidentID,
				"rule_id":           inc.RuleID,
				"matched_event_ids": eventIDs(inc.Events),
				"summary":           inc.Summary,
				"evidence_image":    evidenceRef,
			}), corr)
		if err := r.Store.Append(ev); err != nil {
			fail("incident-event", err)
		}
	}

	if r.Ctrl != nil {
		if err := r.Ctrl.Kill(ctx); err != nil {
			fail("kill-sandbox", err)
		}
	}

	if err := r.Mgr.SetOutcome("compromised"); err != nil {
		fail("outcome", err)
	}
	if err := r.Mgr.Transition(session.StateTerminated, map[string]any{
		"incident_id": incidentID,
	}); err != nil {
		fail("transition-terminated", err)
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

type EvidenceBundle struct {
	Incident          correlate.Incident `json:"incident"`
	IncidentID        string             `json:"incident_id"`
	EvidenceRef       string             `json:"evidence_image,omitempty"`
	WrittenAt         string             `json:"written_at"`
	InspectJSON       []byte             `json:"-"`
	DiffText          string             `json:"-"`
	PreflightFindings []byte             `json:"-"`
}

func (r *Responder) writeBundle(b EvidenceBundle) error {
	all, err := events.ReadAll(r.SessionDir)
	if err != nil {
		return err
	}
	writeLines := func(name string, pred func(events.Event) bool) error {
		f, err := os.OpenFile(filepath.Join(r.SessionDir, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		for _, e := range all {
			if pred(e) {
				if err := enc.Encode(e); err != nil {
					return err
				}
			}
		}
		return os.Chmod(filepath.Join(r.SessionDir, name), 0o600)
	}
	if err := writeLines("network.jsonl", func(e events.Event) bool {
		return e.Source == events.SourceProxy
	}); err != nil {
		return err
	}
	if err := writeLines("hook-events.jsonl", func(e events.Event) bool {
		return e.Source == events.SourceHook
	}); err != nil {
		return err
	}
	if err := writeLines("policy-decisions.jsonl", func(e events.Event) bool {
		return e.Source == events.SourcePolicy
	}); err != nil {
		return err
	}

	if len(b.InspectJSON) > 0 {
		if err := os.WriteFile(filepath.Join(r.SessionDir, "container-inspect.json"), b.InspectJSON, 0o600); err != nil {
			return err
		}
		os.Chmod(filepath.Join(r.SessionDir, "container-inspect.json"), 0o600)
	}
	if b.DiffText != "" {
		if err := os.WriteFile(filepath.Join(r.SessionDir, "workspace.diff"), []byte(b.DiffText), 0o600); err != nil {
			return err
		}
		os.Chmod(filepath.Join(r.SessionDir, "workspace.diff"), 0o600)
	}
	if len(b.PreflightFindings) > 0 {
		if err := os.WriteFile(filepath.Join(r.SessionDir, "preflight-findings.json"), b.PreflightFindings, 0o600); err != nil {
			return err
		}
		os.Chmod(filepath.Join(r.SessionDir, "preflight-findings.json"), 0o600)
	}
	ib, err := json.MarshalIndent(struct {
		EvidenceBundle
		PreflightFindings json.RawMessage `json:"preflight_findings"`
	}{b, b.PreflightFindings}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r.SessionDir, "incident.json"), append(ib, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(r.SessionDir, "incident.json"), 0o600)
}

func renderDiff(changes []workspace.Change) string {
	out := fmt.Sprintf("# workspace.diff at containment time (%d change(s))\n\n", len(changes))
	for _, ch := range changes {
		out += fmt.Sprintf("%s\t%s\n", ch.Kind, ch.Path)
	}
	return out
}

func eventIDs(evs []events.Event) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.EventID)
	}
	return out
}

func mustReadAll(dir string) []events.Event {
	evts, _ := events.ReadAll(dir)
	return evts
}

func shortID(id string) string {
	if len(id) > 8 {
		id = id[:8]
	}
	return id
}
