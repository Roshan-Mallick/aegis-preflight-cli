package session

import (
	"path/filepath"
	"testing"

	"github.com/eth0x1/aegis/internal/events"
)

func TestCanTransition(t *testing.T) {
	legal := [][2]State{
		{StateCreated, StateSnapshotting},
		{StateSnapshotting, StateStarting},
		{StateSnapshotting, StateFailed},
		{StateStarting, StateRunning},
		{StateRunning, StateMonitoring},
		{StateRunning, StateBlocked},
		{StateRunning, StatePreservingEvidence},
		{StateRunning, StateAgentExited},
		{StateMonitoring, StatePreservingEvidence},
		{StateBlocked, StatePreservingEvidence},
		{StateBlocked, StateRunning},
		{StatePreservingEvidence, StateTerminated},
		{StateAgentExited, StatePreflight},
		{StatePreflight, StateFixing},
		{StatePreflight, StateVerified},
		{StatePreflight, StateFailed},
		{StateFixing, StatePreflight},
		{StateVerified, StateReleaseReady},
	}
	for _, p := range legal {
		if !CanTransition(p[0], p[1]) {
			t.Errorf("expected legal: %s -> %s", p[0], p[1])
		}
	}
	illegal := [][2]State{
		{StateCreated, StateRunning},
		{StateCreated, StateVerified},
		{StateRunning, StateVerified},
		{StateRunning, StatePreflight},
		{StateAgentExited, StateRunning},
		{StateVerified, StateRunning},
		{StateTerminated, StateRunning},
		{StateTerminated, StateCreated},
		{StateReleaseReady, StatePreflight},
		{StateFailed, StateRunning},
		{StatePreservingEvidence, StateAgentExited},
		{StateSnapshotting, StateSnapshotting},
	}
	for _, p := range illegal {
		if CanTransition(p[0], p[1]) {
			t.Errorf("expected illegal: %s -> %s", p[0], p[1])
		}
	}
}

func TestTerminalStates(t *testing.T) {
	for _, s := range []State{StateTerminated, StateReleaseReady, StateFailed} {
		if !IsTerminal(s) {
			t.Errorf("%s should be terminal", s)
		}
	}
	for _, s := range []State{StateRunning, StatePreflight, StateFixing} {
		if IsTerminal(s) {
			t.Errorf("%s should not be terminal", s)
		}
	}
}

func fullHappyPath() []State {
	return []State{
		StateSnapshotting, StateStarting, StateRunning, StateAgentExited,
		StatePreflight, StateFixing, StatePreflight, StateVerified, StateReleaseReady,
	}
}

func TestManagerLifecycleHappyPath(t *testing.T) {
	stateRoot := t.TempDir()
	mgr, err := Create(stateRoot, "/tmp/project", "claude", "strict")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer mgr.Close()

	if mgr.Meta.State != StateCreated {
		t.Fatalf("initial state = %s", mgr.Meta.State)
	}
	for _, next := range fullHappyPath() {
		if err := mgr.Transition(next, nil); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if mgr.Meta.State != StateReleaseReady {
		t.Fatalf("final state = %s", mgr.Meta.State)
	}
	if err := mgr.Transition(StateFailed, nil); err == nil {
		t.Fatal("terminal state must be locked")
	}

	evts, err := events.ReadAll(mgr.Dir())
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if len(evts) != 1+len(fullHappyPath()) {
		t.Fatalf("event count = %d, want %d", len(evts), 1+len(fullHappyPath()))
	}
	if evts[0].Type != events.TypeSessionCreated {
		t.Fatalf("first event = %s", evts[0].Type)
	}
	last := evts[len(evts)-1]
	if last.Type != events.TypeSessionState || last.Data["to"] != string(StateReleaseReady) {
		t.Fatalf("last event wrong: %+v", last)
	}
}

func TestManagerRejectsIllegalTransitionAndLeavesTrailClean(t *testing.T) {
	stateRoot := t.TempDir()
	mgr, _ := Create(stateRoot, "/tmp/project", "claude", "strict")
	defer mgr.Close()

	err := mgr.Transition(StateRunning, nil)
	if err == nil {
		t.Fatal("CREATED -> RUNNING must be rejected")
	}
	if _, ok := err.(*IllegalTransitionError); !ok {
		t.Fatalf("error type = %T", err)
	}
	if mgr.Meta.State != StateCreated {
		t.Fatalf("state mutated on rejection: %s", mgr.Meta.State)
	}
	evts, _ := events.ReadAll(mgr.Dir())
	if len(evts) != 1 {
		t.Fatalf("rejected transition must not log an event, log has %d", len(evts))
	}
}

func TestManagerIncidentPathSeverities(t *testing.T) {
	stateRoot := t.TempDir()
	mgr, _ := Create(stateRoot, "/tmp/project", "claude", "strict")
	defer mgr.Close()

	for _, next := range []State{StateSnapshotting, StateStarting, StateRunning} {
		if err := mgr.Transition(next, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := mgr.SetOutcome("compromised"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.AddIncident("inc-123"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Transition(StatePreservingEvidence, nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Transition(StateTerminated, nil); err != nil {
		t.Fatal(err)
	}

	evts, _ := events.ReadAll(mgr.Dir())
	var presEv *events.Event
	for i := range evts {
		if evts[i].Data["to"] == string(StatePreservingEvidence) {
			presEv = &evts[i]
		}
	}
	if presEv == nil {
		t.Fatal("preserving-evidence event missing")
	}
	if presEv.Severity != events.SevCritical {
		t.Fatalf("evidence preservation severity = %s, want critical", presEv.Severity)
	}
}

func TestLoadRestoresSession(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state")
	mgr, _ := Create(stateRoot, "/tmp/project", "claude", "dev")
	mgr.Transition(StateSnapshotting, nil)
	mgr.Transition(StateStarting, nil)
	mgr.Close()

	loaded, err := Load(stateRoot, mgr.Meta.SessionID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer loaded.Close()
	if loaded.Meta.State != StateStarting {
		t.Fatalf("restored state = %s", loaded.Meta.State)
	}
	if loaded.Meta.NetProfile != "dev" {
		t.Fatalf("net profile lost: %s", loaded.Meta.NetProfile)
	}
	if loaded.Dir() != mgr.Dir() {
		t.Fatal("dir mismatch after load")
	}
}

func TestLoadUnknownSessionFails(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "state"), "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("loading unknown session must fail")
	}
}
