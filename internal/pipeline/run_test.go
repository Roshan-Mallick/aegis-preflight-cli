package pipeline_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/network"
	"github.com/eth0x1/aegis/internal/pipeline"
	"github.com/eth0x1/aegis/internal/preflight"
	"github.com/eth0x1/aegis/internal/session"
)

type fakeSandbox struct {
	sid         string
	ws          string
	networkArgs []string
	mu          sync.Mutex
	sessionID   string
}

func NewFakeSandbox(sid, ws string, store *events.Store) pipeline.Sandbox {
	return &fakeSandbox{sid: sid, ws: ws}
}

func (f *fakeSandbox) Start(ctx context.Context) error      { return nil }
func (f *fakeSandbox) Kill(ctx context.Context) error       { return nil }
func (f *fakeSandbox) SetupWorkspaceJail() error            { return nil }
func (f *fakeSandbox) ExecInteractive(command []string) int { return 0 }
func (f *fakeSandbox) Inspect(ctx context.Context) ([]byte, error) {
	return []byte(`{"State":{"Running":true}}`), nil
}
func (f *fakeSandbox) Commit(ctx context.Context, ref string) error { return nil }
func (f *fakeSandbox) ContainerName() string                        { return "aegis-test-" + f.sid[:8] }
func (f *fakeSandbox) SetNetworkArgs(args []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.networkArgs = args
}
func (f *fakeSandbox) NetworkArgs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.networkArgs
}

type fakeGateway struct {
	profile network.Profile
	mu      sync.Mutex
	gotUp   bool
	gotDown bool
	onEvent func(events.Event)
}

func NewFakeGateway(sid string, profile network.Profile, store *events.Store) (pipeline.Gateway, error) {
	return &fakeGateway{profile: profile}, nil
}

func (g *fakeGateway) Up(ctx context.Context) error {
	g.mu.Lock()
	g.gotUp = true
	g.mu.Unlock()
	return nil
}
func (g *fakeGateway) Down(ctx context.Context) error {
	g.mu.Lock()
	g.gotDown = true
	g.mu.Unlock()
	return nil
}
func (g *fakeGateway) AgentNetworkArgs() []string { return []string{"--test-active"} }
func (g *fakeGateway) SetOnEvent(fn func(events.Event)) {
	g.mu.Lock()
	g.onEvent = fn
	g.mu.Unlock()
}

func TestRunPipelinePass(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "main.go", "package main\n\nfunc main() {}\n")

	gw := &fakeGateway{}
	sb := &fakeSandbox{}
	sb.sid = "ffffffff-0000-0000-0000-000000000001"

	onPass := make(chan struct{}, 1)
	seen := make(map[string]bool)
	stateRoot := t.TempDir()

	opts := pipeline.RunOptions{
		ProjectRoot: projectRoot,
		Agent:       "test-agent",
		Profile:     "strict",
		StateRoot:   stateRoot,
		Print:       func(string, ...any) {},
		NewGateway: func(sid string, p network.Profile, s *events.Store) (pipeline.Gateway, error) {
			gw.profile = p
			return gw, nil
		},
		NewSandbox: func(sid, ws string, s *events.Store) pipeline.Sandbox {
			sb.sid = sid
			sb.ws = ws
			return sb
		},
		Interactive: func(ctx context.Context, o pipeline.InteractiveOptions) int { return 0 },
		PreflightExec: func(ctx context.Context, cmd string) (string, string, int, error) {
			return "", "", 0, nil
		},
		OnPass: func(ctx context.Context, mgr *session.Manager, ws string, final *preflight.FinalResult) {
			seen["pass"] = true
			if final.Passed {
				onPass <- struct{}{}
			}
		},
	}

	res, err := pipeline.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.State != session.StatePass {
		t.Errorf("state = %s, want %s", res.State, session.StatePass)
	}
	if res.Outcome != "verified" {
		t.Errorf("outcome = %q, want verified", res.Outcome)
	}
	if !seen["pass"] {
		t.Error("OnPass not invoked")
	}
	select {
	case <-onPass:
	default:
		t.Error("OnPass reported non-passed final")
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d", res.ExitCode)
	}
	if sb.NetworkArgs()[0] != "--test-active" {
		t.Errorf("sandbox did not receive gateway agent network args: %v", sb.NetworkArgs())
	}
	gw.mu.Lock()
	up := gw.gotUp
	down := gw.gotDown
	gw.mu.Unlock()
	if !up || !down {
		t.Errorf("gateway lifecycle incomplete: up=%v down=%v", up, down)
	}

	// Single session id across all components.
	sessions := loadSessions(t, stateRoot)
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].SessionID == "" {
		t.Error("session id empty")
	}
}

func TestRunPipelineBlock(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "package.json", `{"name":"demo","version":"1.0.0"}`)
	writeFile(t, projectRoot, "package-lock.json", `{"name":"demo","lockfileVersion":2}`)

	// npm-audit runs via the preflight ExecFunc; inject a critical vuln so
	// the exit gate blocks.
	npmVuln := `{"vulnerabilities":{"tar":{"name":"tar","severity":"critical","via":["high","critical"]}}}`

	onBlock := make(chan struct{}, 1)
	sb := &fakeSandbox{}
	sb.sid = "eeeeeeee-0000-0000-0000-000000000002"

	opts := pipeline.RunOptions{
		ProjectRoot: projectRoot,
		Agent:       "test-agent",
		Profile:     "strict",
		StateRoot:   t.TempDir(),
		Print:       func(string, ...any) {},
		NewGateway:  NewFakeGateway,
		NewSandbox: func(sid, ws string, s *events.Store) pipeline.Sandbox {
			sb.sid = sid
			sb.ws = ws
			return sb
		},
		Interactive: func(ctx context.Context, o pipeline.InteractiveOptions) int { return 7 },
		PreflightExec: func(ctx context.Context, cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "npm audit") {
				return npmVuln, "", 0, nil
			}
			return "", "", 0, nil
		},
		OnBlock: func(ctx context.Context, mgr *session.Manager, ws string, final *preflight.FinalResult) {
			if final.Last.Blocking > 0 {
				onBlock <- struct{}{}
			}
		},
	}

	res, err := pipeline.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("expected BLOCK error")
	}
	if res.State != session.StateBlock {
		t.Errorf("state = %s, want %s", res.State, session.StateBlock)
	}
	if res.Outcome != "blocked" {
		t.Errorf("outcome = %q, want blocked", res.Outcome)
	}
	select {
	case <-onBlock:
	default:
		t.Error("OnBlock not invoked with blocking findings")
	}
	if res.ExitCode != 7 {
		t.Errorf("interactive exit code not propagated: %d", res.ExitCode)
	}
}

// TestRunPipelineRemediationRounds proves the BLOCK remediation loop: after
// the first scan blocks, the agent is relaunched in the SAME session_id and
// SAME workspace (FIX_REQUEST.md visible to it), the rescan passes, and the
// whole lifecycle uses a single session.
func TestRunPipelineRemediationRounds(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "package.json", `{"name":"demo","version":"1.0.0"}`)
	writeFile(t, projectRoot, "package-lock.json", `{"name":"demo","lockfileVersion":2}`)

	npmVuln := `{"vulnerabilities":{"tar":{"name":"tar","severity":"critical","via":["high","critical"]}}}`
	scanCalls := 0
	interactiveCalls := 0
	firstSID := ""
	secondSID := ""
	onPass := make(chan struct{}, 1)
	var fixRequestPath string

	sb := &fakeSandbox{}
	sb.sid = "dddddddd-0000-0000-0000-000000000003"

	opts := pipeline.RunOptions{
		ProjectRoot: projectRoot,
		Agent:       "opencode",
		Args:        []string{"opencode"},
		Profile:     "strict",
		StateRoot:   t.TempDir(),
		Print:       func(string, ...any) {},
		NewGateway:  NewFakeGateway,
		NewSandbox: func(sid, ws string, s *events.Store) pipeline.Sandbox {
			sb.sid = sid
			sb.ws = ws
			fixRequestPath = filepath.Join(ws, ".aegis", "FIX_REQUEST.md")
			return sb
		},
		Interactive: func(ctx context.Context, o pipeline.InteractiveOptions) int {
			interactiveCalls++
			sid := o.Manager.Snapshot().SessionID
			if interactiveCalls == 1 {
				firstSID = sid
			} else {
				secondSID = sid
			}
			return 0
		},
		PreflightExec: func(ctx context.Context, cmd string) (string, string, int, error) {
			scanCalls++
			if strings.Contains(cmd, "npm audit") {
				if scanCalls >= 2 {
					// Remediation round fixed the workspace.
					return "", "", 0, nil
				}
				return npmVuln, "", 0, nil
			}
			return "", "", 0, nil
		},
		OnPass: func(ctx context.Context, mgr *session.Manager, ws2 string, final *preflight.FinalResult) {
			onPass <- struct{}{}
		},
	}

	res, err := pipeline.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.State != session.StatePass {
		t.Errorf("state = %s, want %s", res.State, session.StatePass)
	}
	if res.Outcome != "verified" {
		t.Errorf("outcome = %q, want verified", res.Outcome)
	}
	if res.Final == nil || !res.Final.Passed {
		t.Fatal("final result not passed")
	}
	if res.Final.Cycles != 2 {
		t.Errorf("cycles = %d, want 2 (block then remediation pass)", res.Final.Cycles)
	}
	if interactiveCalls != 2 {
		t.Errorf("interactive launches = %d, want 2 (initial + remediation)", interactiveCalls)
	}
	if firstSID == "" || firstSID != secondSID {
		t.Errorf("remediation used a different session: %q vs %q", firstSID, secondSID)
	}
	if res.SessionID != firstSID {
		t.Errorf("run session %q != interactive session %q", res.SessionID, firstSID)
	}
	if fixRequestPath == "" {
		t.Fatal("fix request path not captured")
	}
	if _, err := os.Stat(fixRequestPath); err != nil {
		t.Errorf("FIX_REQUEST.md not returned to the agent workspace: %v", err)
	}
	select {
	case <-onPass:
	default:
		t.Error("OnPass not invoked")
	}
}

// TestRunPipelineShellBlockStops tests that a bare shell session (no agent
// command) blocks after the first scan instead of re-scanning an unchanged
// workspace and does not relaunch the shell automatically.
func TestRunPipelineShellBlockStops(t *testing.T) {
	projectRoot := t.TempDir()
	writeFile(t, projectRoot, "package.json", `{"name":"demo","version":"1.0.0"}`)
	writeFile(t, projectRoot, "package-lock.json", `{"name":"demo","lockfileVersion":2}`)

	npmVuln := `{"vulnerabilities":{"tar":{"name":"tar","severity":"critical","via":["high","critical"]}}}`
	scanCalls := 0
	interactiveCalls := 0

	opts := pipeline.RunOptions{
		ProjectRoot: projectRoot,
		Agent:       "shell",
		Profile:     "strict",
		StateRoot:   t.TempDir(),
		Print:       func(string, ...any) {},
		NewGateway:  NewFakeGateway,
		NewSandbox:  NewFakeSandbox,
		Interactive: func(ctx context.Context, o pipeline.InteractiveOptions) int {
			interactiveCalls++
			return 0
		},
		PreflightExec: func(ctx context.Context, cmd string) (string, string, int, error) {
			scanCalls++
			if strings.Contains(cmd, "npm audit") {
				return npmVuln, "", 0, nil
			}
			return "", "", 0, nil
		},
	}

	res, err := pipeline.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("expected BLOCK error")
	}
	if res.State != session.StateBlock {
		t.Errorf("state = %s, want %s", res.State, session.StateBlock)
	}
	if res.Final.Cycles != 1 {
		t.Errorf("cycles = %d, want 1 (no unchanged-workspace rescans for a shell)", res.Final.Cycles)
	}
	if interactiveCalls != 1 {
		t.Errorf("interactive launches = %d, want 1 (shell must not auto-relaunch)", interactiveCalls)
	}
	if scanCalls != 1 {
		t.Errorf("scans = %d, want 1", scanCalls)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d", res.ExitCode)
	}
}

func loadSessions(t *testing.T, stateRoot string) []session.Metadata {
	t.Helper()
	dir := filepath.Join(stateRoot, "sessions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []session.Metadata
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if mgr, err := session.Load(stateRoot, e.Name()); err == nil {
			out = append(out, mgr.Snapshot())
		}
	}
	return out
}
