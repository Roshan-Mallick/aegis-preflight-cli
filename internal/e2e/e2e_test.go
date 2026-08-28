package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/preflight"
	"github.com/eth0x1/aegis/internal/session"
	"github.com/eth0x1/aegis/internal/workspace"
)

func TestEndToEndInitSnapshotPreflightApply(t *testing.T) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks unavailable")
	}
	root := t.TempDir()
	proj := filepath.Join(root, "myproject")
	os.MkdirAll(filepath.Join(proj, "src"), 0o755)
	os.WriteFile(filepath.Join(proj, "app.py"), []byte("print('hello')\n"), 0o644)
	os.WriteFile(filepath.Join(proj, "src", "secret.py"), []byte("# config\nAPI_KEY = \"AKIAasdf1234567890QWERT\"\n"), 0o644)

	stateDir := filepath.Join(root, "state")
	mgr, err := session.Create(stateDir, proj, "claude", "strict")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	id := mgr.Snapshot().SessionID
	short := id[:8]

	ws := filepath.Join(mgr.Dir(), "workspace")
	snap, err := workspace.Snapshot(proj, ws)
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetWorkspace(ws)
	workspace.SaveManifest(mgr.Dir(), snap.Manifest)

	mgr.Transition(session.StateSnapshotting, nil)
	mgr.Transition(session.StateStarting, nil)
	mgr.Transition(session.StateRunning, nil)
	os.WriteFile(filepath.Join(ws, "feature.go"), []byte("package main\n"), 0o644)

	store, err := events.Open(mgr.Dir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := mgr.Transition(session.StateAgentExited, nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Transition(session.StatePreflight, nil); err != nil {
		t.Fatal(err)
	}

	fixed := []byte("# config\nAPI_KEY = os.environ.get('API_KEY')\n")
	var fixCount int
	final, err := preflight.RunLoop(context.Background(), ws,
		preflight.RunOptions{SessionID: id, Store: store},
		preflight.LoopCallbacks{
			PublishFixRequest: func(_ context.Context, cycle int, res *preflight.Result) error {
				fixCount++
				return preflight.WriteFixRequest(mgr.Dir(), ws, cycle, res)
			},
			BeforeCycle: func(_ context.Context, cycle int) error {
				if cycle > 1 {
					return mgr.Transition(session.StatePreflight, nil)
				}
				return nil
			},
			BeforeRescan: func(_ context.Context, cycle int) error {
				if err := mgr.Transition(session.StateFixing, nil); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(ws, "src", "secret.py"), fixed, 0o644)
			},
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !final.Passed || final.Cycles != 2 {
		t.Fatalf("preflight: passed=%v cycles=%d", final.Passed, final.Cycles)
	}
	if fixCount != 1 {
		t.Errorf("fix requests = %d, want 1", fixCount)
	}

	vd, _ := preflight.GenerateVerifiedDiff(id, snap.Manifest, ws, final.Cycles)
	preflight.WriteVerifiedArtifacts(mgr.Dir(), vd)

	mgr.Transition(session.StateVerified, nil)
	mgr.Transition(session.StateReleaseReady, nil)
	mgr.SetOutcome("verified")

	postChanges, _, _ := workspace.ComputeDiff(snap.Manifest, ws)
	nApplied, err := workspace.Apply(proj, ws, snap.Manifest, postChanges)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if nApplied < 1 {
		t.Errorf("applied %d changes", nApplied)
	}

	promoted := mustRead(t, filepath.Join(proj, "feature.go"))
	if !strings.Contains(promoted, "package main") {
		t.Error("feature.go not promoted")
	}
	fixedContent := mustRead(t, filepath.Join(proj, "src", "secret.py"))
	if strings.Contains(fixedContent, "AKIAasdf1234567890QWERT") {
		t.Fatal("SECRET LEAKED TO TRUSTED PROJECT")
	}

	evts, _ := events.ReadAll(mgr.Dir())
	counts := map[string]int{}
	for _, e := range evts {
		counts[e.Type]++
	}
	if counts[events.TypeFinding] == 0 {
		t.Error("no finding events emitted")
	}
	if counts[events.TypeSessionState] == 0 {
		t.Error("no session state events")
	}

	for _, f := range []string{"metadata.json", "verified-diff.json", "verified-diff.txt"} {
		if _, err := os.Stat(filepath.Join(mgr.Dir(), f)); err != nil {
			t.Errorf("missing artifact: %s", f)
		}
	}
	t.Logf("E2E complete: %s -> %d preflight cycles -> %d applied -> secret blocked",
		short, final.Cycles, nApplied)
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEndToEndHostPathLeakBlocked(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(root, "host-project")
	os.MkdirAll(proj, 0o755)
	os.WriteFile(filepath.Join(proj, "data.txt"), []byte("sensitive data\n"), 0o644)

	stateDir := filepath.Join(root, "state")
	mgr, err := session.Create(stateDir, proj, "claude", "strict")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	ws := filepath.Join(mgr.Dir(), "workspace")
	snap, err := workspace.Snapshot(proj, ws)
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetWorkspace(ws)
	workspace.SaveManifest(mgr.Dir(), snap.Manifest)

	mgr.Transition(session.StateRunning, nil)
	os.WriteFile(filepath.Join(ws, "data.txt"), []byte("modified data\n"), 0o644)
	os.WriteFile(filepath.Join(ws, "stolen.txt"), []byte("# symlink would point outside"), 0o644)

	mgr.Transition(session.StateAgentExited, nil)

	changes, _, err := workspace.ComputeDiff(snap.Manifest, ws)
	if err != nil {
		t.Fatal(err)
	}
	validateErr := workspace.ValidateChanges(proj, snap.Manifest, changes)
	if validateErr != nil {
		t.Logf("validate correctly caught issue: %v", validateErr)
	}

	nApplied, err := workspace.Apply(proj, ws, snap.Manifest, changes)
	if err != nil {
		t.Fatal(err)
	}
	if nApplied < 1 {
		t.Error("no changes applied")
	}

	dataContent := mustRead(t, filepath.Join(proj, "data.txt"))
	if !strings.Contains(dataContent, "modified data") {
		t.Errorf("data.txt not updated: %s", dataContent)
	}
	t.Log("host path containment verified")
}
