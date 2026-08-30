package pipeline_test

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/eth0x1/aegis/internal/correlate"
	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/preflight"
	"github.com/eth0x1/aegis/internal/session"
	"github.com/eth0x1/aegis/internal/workspace"
)

func TestSessionIDPropagationAcrossAllComponents(t *testing.T) {
	stateRoot := t.TempDir()
	projectRoot := t.TempDir()

	mgr, err := session.Create(stateRoot, projectRoot, "opencode", "dev")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	snap := mgr.Snapshot()

	sid := snap.SessionID
	if _, err := uuid.Parse(sid); err != nil {
		t.Fatalf("session ID is not a valid UUID: %s", sid)
	}

	if err := mgr.Transition(session.StateSnapshotting, nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Transition(session.StateSandboxStarted, nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Transition(session.StateAgentStarted, nil); err != nil {
		t.Fatal(err)
	}

	gwSessionID := sid
	sbSessionID := sid
	corrSessionID := sid

	if gwSessionID != sid {
		t.Errorf("gateway session ID mismatch: %s != %s", gwSessionID, sid)
	}
	if sbSessionID != sid {
		t.Errorf("sandbox session ID mismatch: %s != %s", sbSessionID, sid)
	}
	if corrSessionID != sid {
		t.Errorf("correlate session ID mismatch: %s != %s", corrSessionID, sid)
	}

	store := mgr.Store()
	if store == nil {
		t.Fatal("store is nil")
	}

	fileEv := events.New(events.SourceHook, events.TypeFileRead, events.SevInfo, "opencode", sid, map[string]any{
		"path": "/workspace/main.go",
	})
	if err := store.Append(fileEv); err != nil {
		t.Fatal(err)
	}

	cmdEv := events.New(events.SourceHook, events.TypeCommandExec, events.SevInfo, "opencode", sid, map[string]any{
		"command": "go build ./...",
	})
	if err := store.Append(cmdEv); err != nil {
		t.Fatal(err)
	}

	netEv := events.New(events.SourceProxy, events.TypeNetworkConnect, events.SevInfo, "proxy", sid, map[string]any{
		"domain":   "api.anthropic.com",
		"decision": "allow",
	})
	if err := store.Append(netEv); err != nil {
		t.Fatal(err)
	}

	modelEv := events.New(events.SourceModel, events.TypeModelRequest, events.SevInfo, "aegis", sid, map[string]any{
		"model":      "qwen2.5-coder-1.5b",
		"prompt":     "analyze code",
		"latency_ms": 150,
	})
	if err := store.Append(modelEv); err != nil {
		t.Fatal(err)
	}

	modelRespEv := events.New(events.SourceModel, events.TypeModelResponse, events.SevInfo, "aegis", sid, map[string]any{
		"model":      "qwen2.5-coder-1.5b",
		"tokens":     42,
		"latency_ms": 150,
	})
	if err := store.Append(modelRespEv); err != nil {
		t.Fatal(err)
	}

	allEvents, err := events.ReadAll(mgr.Dir())
	if err != nil {
		t.Fatal(err)
	}

	sessionEvents := 0
	fileEvents := 0
	cmdEvents := 0
	netEvents := 0
	modelEvents := 0

	for _, ev := range allEvents {
		if ev.SessionID != sid {
			t.Errorf("event %s has wrong session ID: %s != %s", ev.EventID, ev.SessionID, sid)
		}
		switch ev.Type {
		case events.TypeSessionCreated, events.TypeSessionState:
			sessionEvents++
		case events.TypeFileRead:
			fileEvents++
		case events.TypeCommandExec:
			cmdEvents++
		case events.TypeNetworkConnect:
			netEvents++
		case events.TypeModelRequest, events.TypeModelResponse, events.TypeModelError, events.TypeModelLatency:
			modelEvents++
		}
	}

	if sessionEvents < 1 {
		t.Errorf("expected at least 1 session event, got %d", sessionEvents)
	}
	if fileEvents < 1 {
		t.Errorf("expected at least 1 file event, got %d", fileEvents)
	}
	if cmdEvents < 1 {
		t.Errorf("expected at least 1 command event, got %d", cmdEvents)
	}
	if netEvents < 1 {
		t.Errorf("expected at least 1 network event, got %d", netEvents)
	}
	if modelEvents < 1 {
		t.Errorf("expected at least 1 model event, got %d", modelEvents)
	}
}

func TestConcurrentEventWriting(t *testing.T) {
	stateRoot := t.TempDir()
	projectRoot := t.TempDir()

	mgr, err := session.Create(stateRoot, projectRoot, "opencode", "dev")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	snap := mgr.Snapshot()
	sid := snap.SessionID

	store := mgr.Store()
	if store == nil {
		t.Fatal("store is nil")
	}

	var wg sync.WaitGroup
	sources := []string{events.SourceHook, events.SourceProxy, events.SourceSandbox, events.SourceModel}
	types := []string{events.TypeFileRead, events.TypeNetworkConnect, events.TypeCommandExec, events.TypeModelRequest}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			src := sources[idx%len(sources)]
			typ := types[idx%len(types)]
			ev := events.New(src, typ, events.SevInfo, "test", sid, map[string]any{
				"index": idx,
			})
			_ = store.Append(ev)
		}(i)
	}
	wg.Wait()

	allEvents, err := events.ReadAll(mgr.Dir())
	if err != nil {
		t.Fatal(err)
	}

	totalEvents := 0
	for _, ev := range allEvents {
		if ev.SessionID == sid && (ev.Source == events.SourceHook || ev.Source == events.SourceProxy ||
			ev.Source == events.SourceSandbox || ev.Source == events.SourceModel) {
			totalEvents++
		}
	}

	if totalEvents != 100 {
		t.Errorf("expected 100 concurrent events, got %d", totalEvents)
	}
}

func TestCorrelationEngineWithSessionID(t *testing.T) {
	sid := uuid.NewString()
	engine := correlate.NewEngine(sid, 5*time.Minute)

	armingEv := events.Event{
		EventID:   uuid.NewString(),
		SessionID: sid,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Source:    events.SourceHook,
		Type:      events.TypeFileRead,
		Severity:  events.SevInfo,
		Data:      map[string]any{"path": "/workspace/.env", "sensitive": true},
	}
	inc := engine.Observe(armingEv)
	if inc != nil {
		t.Fatal("arming event should not fire incident")
	}

	blockedEv := events.Event{
		EventID:   uuid.NewString(),
		SessionID: sid,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Source:    events.SourceProxy,
		Type:      events.TypeNetworkConnect,
		Severity:  events.SevMedium,
		Data:      map[string]any{"domain": "evil.com", "decision": "block"},
	}
	inc = engine.Observe(blockedEv)
	if inc == nil {
		t.Fatal("blocked egress after sensitive access should fire incident")
	}
	if inc.SessionID != sid {
		t.Errorf("incident session ID mismatch: %s != %s", inc.SessionID, sid)
	}
	if inc.RuleID != correlate.RuleSensitiveEgress {
		t.Errorf("unexpected rule: %s", inc.RuleID)
	}
}

func TestPreflightPipelineIntegration(t *testing.T) {
	stateRoot := t.TempDir()
	projectRoot := t.TempDir()
	ws := t.TempDir()

	mgr, err := session.Create(stateRoot, projectRoot, "opencode", "dev")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	snap := mgr.Snapshot()
	sid := snap.SessionID

	store := mgr.Store()

	ev := events.New(events.SourceScanner, events.TypeFinding, events.SevInfo, "scanner:gitleaks", sid, map[string]any{
		"finding_id": "test-finding-1",
		"blocking":   false,
		"message":    "test finding",
	})
	_ = store.Append(ev)

	opts := preflight.RunOptions{
		SessionID: sid,
		Store:     store,
		Scanners:  []preflight.Scanner{},
	}
	final, err := preflight.RunLoop(nil, ws, opts, preflight.LoopCallbacks{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !final.Passed {
		t.Error("empty workspace should pass preflight")
	}
	if final.Cycles != 1 {
		t.Errorf("expected 1 cycle, got %d", final.Cycles)
	}
}

// TestWorkspaceManifestAndDiff pins the direct-mount baseline: the audit
// manifest is built from the live project root itself (BuildManifest, no
// copy), the agent edits the project directory in place, and ComputeDiff
// resolves the session change set against that same live project.
func TestWorkspaceManifestAndDiff(t *testing.T) {
	projectRoot := t.TempDir()

	writeFile(t, projectRoot, "main.go", "package main\n\nfunc main() {}\n")
	writeFile(t, projectRoot, "README.md", "# Test\n")

	before, err := workspace.BuildManifest(projectRoot)
	if err != nil {
		t.Fatal(err)
	}

	stateRoot := t.TempDir()
	mgr, err := session.Create(stateRoot, projectRoot, "opencode", "dev")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	if err := workspace.SaveManifest(mgr.Dir(), before); err != nil {
		t.Fatal(err)
	}

	// The agent edits the live project (via the container's /workspace mount).
	writeFile(t, projectRoot, "main.go", "package main\n\nfunc main() { println(\"hello\") }\n")
	writeFile(t, projectRoot, "new.go", "package main\n")

	changes, _, err := workspace.ComputeDiff(before, projectRoot)
	if err != nil {
		t.Fatal(err)
	}

	if len(changes) == 0 {
		t.Fatal("expected changes after modifying the project in place")
	}

	foundModify := false
	foundCreate := false
	for _, ch := range changes {
		switch ch.Kind {
		case workspace.KindModified:
			foundModify = true
		case workspace.KindAdded:
			foundCreate = true
		}
	}
	if !foundModify {
		t.Error("expected a modified file change")
	}
	if !foundCreate {
		t.Error("expected a created file change")
	}
}

func TestModelEventTypesValid(t *testing.T) {
	modelTypes := []string{
		events.TypeModelRequest,
		events.TypeModelResponse,
		events.TypeModelError,
		events.TypeModelLatency,
	}
	for _, typ := range modelTypes {
		if !events.ValidType(typ) {
			t.Errorf("model event type %q should be valid", typ)
		}
	}

	sid := uuid.NewString()
	for _, typ := range modelTypes {
		ev := events.New(events.SourceModel, typ, events.SevInfo, "aegis", sid, map[string]any{
			"model": "qwen2.5-coder-1.5b",
		})
		if err := ev.Validate(); err != nil {
			t.Errorf("model event %q failed validation: %v", typ, err)
		}
	}
}

func TestTimelineReconstruction(t *testing.T) {
	stateRoot := t.TempDir()
	projectRoot := t.TempDir()

	mgr, err := session.Create(stateRoot, projectRoot, "opencode", "dev")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	mgr.Snapshot()

	transitions := []session.State{
		session.StateSnapshotting,
		session.StateSandboxStarted,
		session.StateAgentStarted,
		session.StateActive,
		session.StateAgentFinished,
		session.StateSecurityScan,
		session.StatePreflight,
		session.StatePass,
		session.StateCleanup,
		session.StateClosed,
	}
	for _, s := range transitions {
		if err := mgr.Transition(s, nil); err != nil {
			t.Fatalf("transition to %s failed: %v", s, err)
		}
	}

	allEvents, err := events.ReadAll(mgr.Dir())
	if err != nil {
		t.Fatal(err)
	}

	var stateEvents []string
	for _, ev := range allEvents {
		if ev.Type == events.TypeSessionState {
			if to, ok := ev.Data["to"].(string); ok {
				stateEvents = append(stateEvents, to)
			}
		}
	}

	expected := []string{
		"SNAPSHOTTING_PROJECT", "SANDBOX_STARTED", "AGENT_STARTED", "ACTIVE",
		"AGENT_FINISHED", "SECURITY_SCAN", "PREFLIGHT", "PASS", "CLEANUP", "CLOSED",
	}
	if len(stateEvents) != len(expected) {
		t.Fatalf("expected %d state events, got %d", len(expected), len(stateEvents))
	}
	for i, exp := range expected {
		if stateEvents[i] != exp {
			t.Errorf("state event %d: expected %s, got %s", i, exp, stateEvents[i])
		}
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(dir+"/"+name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
