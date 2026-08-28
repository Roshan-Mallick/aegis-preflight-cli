package preflight_test

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

const secretConfig = `# config.py
AWS_ACCESS_KEY_ID = "AKIAasdf1234567890QWERT"
`
const fixedConfig = `# config.py
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
`

func TestIntegrationPreflightPlantFixVerifyApply(t *testing.T) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks unavailable on host")
	}
	ctx := context.Background()

	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "src"), 0o755)
	os.WriteFile(filepath.Join(root, "app.py"), []byte("print('v1')\n"), 0o644)
	os.WriteFile(filepath.Join(root, "src", "config.py"), []byte(secretConfig), 0o644)

	stateRoot := filepath.Join(t.TempDir(), "state")
	mgr, err := session.Create(stateRoot, root, "claude", "strict")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	sessionID := mgr.Snapshot().SessionID

	ws := filepath.Join(mgr.Dir(), "workspace")
	snap, err := workspace.Snapshot(root, ws)
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetWorkspace(ws)
	workspace.SaveManifest(mgr.Dir(), snap.Manifest)

	os.WriteFile(filepath.Join(ws, "feature.py"), []byte("def feature():\n    return 42\n"), 0o644)

	for _, s := range []session.State{session.StateSnapshotting, session.StateStarting,
		session.StateRunning, session.StateAgentExited, session.StatePreflight} {
		if err := mgr.Transition(s, nil); err != nil {
			t.Fatal(err)
		}
	}

	store, err := events.Open(mgr.Dir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var fixRequestSeen bool
	opts := preflight.RunOptions{SessionID: sessionID, Store: store}
	cb := preflight.LoopCallbacks{
		PublishFixRequest: func(c context.Context, cycle int, res *preflight.Result) error {
			fixRequestSeen = true
			if res.Blocking == 0 {
				t.Errorf("cycle %d published with zero blocking findings", cycle)
			}
			return preflight.WriteFixRequest(mgr.Dir(), ws, cycle, res)
		},
		BeforeRescan: func(c context.Context, cycle int) error {
			if mgr.Snapshot().State == session.StatePreflight {
				mgr.Transition(session.StateFixing, map[string]any{"after_cycle": cycle})
			}
			return os.WriteFile(filepath.Join(ws, "src", "config.py"), []byte(fixedConfig), 0o644)
		},
		BeforeCycle: func(c context.Context, cycle int) error {
			if cycle > 1 && mgr.Snapshot().State == session.StateFixing {
				return mgr.Transition(session.StatePreflight, nil)
			}
			return nil
		},
	}

	final, err := preflight.RunLoop(ctx, ws, opts, cb, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !fixRequestSeen {
		t.Fatal("fix request never published despite planted secret")
	}
	if !final.Passed || final.Cycles != 2 {
		t.Fatalf("passed=%v cycles=%d, want true/2", final.Passed, final.Cycles)
	}

	fr, err := os.ReadFile(filepath.Join(ws, ".aegis", "FIX_REQUEST.md"))
	if err == nil && strings.Contains(string(fr), "generic-api-key") {
		t.Log("FIX_REQUEST correctly names the leaked rule")
	}

	vd, err := preflight.GenerateVerifiedDiff(sessionID, snap.Manifest, ws, final.Cycles)
	if err != nil {
		t.Fatal(err)
	}
	if len(vd.Changes) < 2 {
		t.Fatalf("verified diff changes = %d, want >=2 (modified config + added feature)", len(vd.Changes))
	}
	if err := preflight.WriteVerifiedArtifacts(mgr.Dir(), vd); err != nil {
		t.Fatal(err)
	}

	if err := mgr.Transition(session.StateVerified, map[string]any{"cycles": final.Cycles}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Transition(session.StateReleaseReady, nil); err != nil {
		t.Fatal(err)
	}
	if err := mgr.SetOutcome("verified"); err != nil {
		t.Fatal(err)
	}

	nApplied, err := workspace.Apply(root, ws, snap.Manifest, mustChanges(t, mgr.Dir(), ws))
	if err != nil {
		t.Fatalf("promotion failed: %v", err)
	}
	if nApplied < 2 {
		t.Errorf("applied %d changes, want >=2", nApplied)
	}

	trustedConfig := mustRead(t, filepath.Join(root, "src", "config.py"))
	if strings.Contains(trustedConfig, "AKIAasdf1234567890QWERT") {
		t.Fatal("SECRET REACHED TRUSTED PROJECT")
	}
	if trustedConfig != fixedConfig {
		t.Errorf("trusted config = %q", trustedConfig)
	}
	if _, err := os.Stat(filepath.Join(root, "feature.py")); err != nil {
		t.Error("added feature file not promoted")
	}
	trustedApp := mustRead(t, filepath.Join(root, "app.py"))
	if trustedApp != "print('v1')\n" {
		t.Error("untouched trusted file drifted")
	}

	evts, _ := events.ReadAll(mgr.Dir())
	findings_, summaries := 0, 0
	for _, e := range evts {
		switch e.Type {
		case events.TypeFinding:
			findings_++
		case "policy.preflight":
			summaries++
		}
	}
	if findings_ == 0 || summaries < 2 {
		t.Errorf("canonical preflight events: findings=%d summaries=%d", findings_, summaries)
	}
}

func mustChanges(t *testing.T, sessionDir, ws string) []workspace.Change {
	t.Helper()
	before, err := workspace.LoadManifest(sessionDir)
	if err != nil {
		t.Fatal(err)
	}
	changes, _, err := workspace.ComputeDiff(before, ws)
	if err != nil {
		t.Fatal(err)
	}
	return changes
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
