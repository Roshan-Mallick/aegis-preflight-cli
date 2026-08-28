package response

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/eth0x1/aegis/internal/correlate"
	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/session"
)

type fakeCtrl struct {
	killed      bool
	committed   string
	inspectJSON []byte
}

func (f *fakeCtrl) Inspect(ctx context.Context) ([]byte, error) {
	return f.inspectJSON, nil
}
func (f *fakeCtrl) Commit(ctx context.Context, ref string) error {
	f.committed = ref
	return nil
}
func (f *fakeCtrl) Kill(ctx context.Context) error {
	f.killed = true
	return nil
}

func newSessionAtRunning(t *testing.T) *session.Manager {
	t.Helper()
	stateRoot := t.TempDir()
	mgr, err := session.Create(stateRoot, "/tmp/proj", "claude", "strict")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []session.State{session.StateSnapshotting, session.StateStarting, session.StateRunning} {
		if err := mgr.Transition(s, nil); err != nil {
			t.Fatal(err)
		}
	}
	return mgr
}

func makeIncident() correlate.Incident {
	sensitive := events.New(events.SourceHook, events.TypeFileRead, events.SevLow, "claude",
		"aaaa1111-2222-3333-4444-555555555555",
		map[string]any{"path": "/workspace/.env", "sensitive": true})
	block := events.New(events.SourceProxy, events.TypeNetworkConnect, events.SevHigh, "egress-gateway",
		sensitive.SessionID,
		map[string]any{"domain": "evil.com", "decision": "block"})
	return correlate.Incident{
		ID:         uuid.NewString(),
		SessionID:  sensitive.SessionID,
		RuleID:     correlate.RuleSensitiveEgress,
		DetectedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Summary:    "test incident",
		Events:     []events.Event{sensitive, block},
	}
}

func TestContainCriticalFullFlow(t *testing.T) {
	mgr := newSessionAtRunning(t)
	defer mgr.Close()
	storeDir := mgr.Dir()
	store, err := events.Open(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctrl := &fakeCtrl{inspectJSON: []byte(`[{"Name":"fake"}]`)}
	r := &Responder{
		Ctrl:       ctrl,
		Mgr:        mgr,
		Store:      store,
		SessionDir: storeDir,
	}
	inc := makeIncident()
	for _, e := range inc.Events {
		if err := store.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.ContainCritical(context.Background(), inc); err != nil {
		t.Fatalf("containment failed: %v", err)
	}

	if !ctrl.killed {
		t.Error("sandbox not killed")
	}
	if ctrl.committed == "" || !strings.HasPrefix(ctrl.committed, "aegis-evidence-") {
		t.Errorf("evidence commit ref = %q", ctrl.committed)
	}
	if r.EvidenceRef != ctrl.committed {
		t.Errorf("responder ref mismatch: %q vs %q", r.EvidenceRef, ctrl.committed)
	}
	if mgr.Snapshot().State != session.StateTerminated {
		t.Errorf("state = %s, want TERMINATED", mgr.Snapshot().State)
	}
	if mgr.Snapshot().Outcome != "compromised" {
		t.Errorf("outcome = %s", mgr.Snapshot().Outcome)
	}
	if ids := mgr.Snapshot().IncidentIDs; len(ids) != 1 || ids[0] != inc.ID {
		t.Errorf("incident ids = %v", mgr.Snapshot().IncidentIDs)
	}

	for _, name := range []string{
		"network.jsonl", "hook-events.jsonl", "policy-decisions.jsonl",
		"container-inspect.json", "incident.json", "report.md",
	} {
		fi, err := os.Stat(filepath.Join(storeDir, name))
		if err != nil {
			t.Errorf("bundle file %s missing: %v", name, err)
			continue
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s perms = %v", name, fi.Mode().Perm())
		}
	}
	netRaw, _ := os.ReadFile(filepath.Join(storeDir, "network.jsonl"))
	if !strings.Contains(string(netRaw), "evil.com") {
		t.Error("network.jsonl view lost the blocked connect")
	}
	if strings.Contains(string(netRaw), `"file.read"`) {
		t.Error("network.jsonl must contain only proxy-sourced events")
	}
	hookRaw, _ := os.ReadFile(filepath.Join(storeDir, "hook-events.jsonl"))
	if !strings.Contains(string(hookRaw), ".env") {
		t.Error("hook view lost sensitive read")
	}

	evts, _ := events.ReadAll(storeDir)
	var incidentEv *events.Event
	for i := range evts {
		if evts[i].Type == events.TypeIncident {
			incidentEv = &evts[i]
		}
	}
	if incidentEv == nil {
		t.Fatal("no canonical incident event appended")
	}
	if incidentEv.Severity != events.SevCritical || incidentEv.Source != events.SourcePolicy {
		t.Errorf("incident event sev/source wrong: %+v", incidentEv)
	}
	md, _ := os.ReadFile(filepath.Join(storeDir, "report.md"))
	for _, want := range []string{"COMPROMISED", inc.RuleID, "evil.com", "Evidence image"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("report.md missing %q", want)
		}
	}
}

func TestContainCriticalWithoutControllerStillRecords(t *testing.T) {
	mgr := newSessionAtRunning(t)
	defer mgr.Close()
	r := &Responder{Mgr: mgr, SessionDir: mgr.Dir()}
	if err := r.ContainCritical(context.Background(), makeIncident()); err != nil {
		t.Fatalf("headless containment failed: %v", err)
	}
	if mgr.Snapshot().State != session.StateTerminated {
		t.Errorf("state=%s", mgr.Snapshot().State)
	}
	if _, err := os.Stat(filepath.Join(mgr.Dir(), "incident.json")); err != nil {
		t.Error("incident.json missing in headless mode")
	}
}

func TestActionsForSeverityPolicy(t *testing.T) {
	cases := map[string][]Action{
		events.SevInfo:     {ActionLog},
		events.SevLow:      {ActionLog},
		events.SevMedium:   {ActionBlock},
		events.SevHigh:     {ActionBlock, ActionPause},
		events.SevCritical: {ActionKill},
		"bogus":            {ActionLog},
	}
	for sev, want := range cases {
		got := ActionsFor(sev)
		if len(got) != len(want) || got[0] != want[0] {
			t.Errorf("ActionsFor(%s) = %v, want %v", sev, got, want)
		}
	}
	if len(ActionsFor(events.SevHigh)) < 2 {
		t.Error("high must include pause")
	}
}

func TestStateGateBlocksContainmentOnFreshSession(t *testing.T) {
	stateRoot := t.TempDir()
	mgr, _ := session.Create(stateRoot, "", "claude", "strict")
	defer mgr.Close()
	r := &Responder{Mgr: mgr, SessionDir: mgr.Dir()}
	err := r.ContainCritical(context.Background(), makeIncident())
	if err == nil {
		t.Fatal("CREATED -> PRESERVING_EVIDENCE must be rejected by state machine")
	}
	if mgr.Snapshot().Outcome == "compromised" {
		t.Error("outcome must not be set when containment is refused")
	}
}
