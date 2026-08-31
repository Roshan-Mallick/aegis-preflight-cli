package exitgate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/findings"
	"github.com/eth0x1/aegis/internal/workspace"
)

const (
	rawSecret      = "sk-ant-api03-1234567890abcdefGHIJKLMNOPQRSTUVWXYZ"
	rawSecretAWS   = "AKIAIOSFODNN7EXAMPLE"
	basicManifest  = "README.md"
	snippetContent = "package app\nconst apiKey = \"" + rawSecret + "\"\n"
)

func newTestEvidence(t *testing.T, eventsToAppend []events.Event, fnds []findings.Finding,
	preMutate, mutate func(ws string)) (*Evidence, string) {
	t.Helper()
	ws := t.TempDir()
	stateDir := t.TempDir()

	if preMutate != nil {
		preMutate(ws)
	}
	before, err := workspace.BuildManifest(ws)
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	if err := workspace.SaveManifest(stateDir, before); err != nil {
		t.Fatalf("save manifest: %v", err)
	}

	store, err := events.Open(stateDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	for _, e := range eventsToAppend {
		if err := store.Append(e); err != nil {
			t.Fatalf("append event: %v", err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	if mutate != nil {
		mutate(ws)
	}

	ev, err := BuildEvidence(context.Background(), Input{
		SessionDir: stateDir,
		Workspace:  ws,
		Task:       "opencode implement security improvements to the login flow",
		Profile:    "strict",
		Findings:   fnds,
	})
	if err != nil {
		t.Fatalf("build evidence: %v", err)
	}
	return ev, stateDir
}

func mkEvent(src, typ, sev, sid string, data map[string]any) events.Event {
	return events.New(src, typ, sev, "test", sid, data)
}

func TestEvidenceCapturesChangesCommandsAndNetwork(t *testing.T) {
	sid := "00000000-0000-4000-8000-000000000001"
	ev, _ := newTestEvidence(t,
		[]events.Event{
			mkEvent(events.SourceHook, events.TypeCommandExec, events.SevInfo, sid,
				map[string]any{"command": "go build ./..."}),
			mkEvent(events.SourceProxy, events.TypeNetworkConnect, events.SevInfo, sid,
				map[string]any{"domain": "api.example.com", "port": 443, "decision": "allow", "reason": "allowlisted"}),
		},
		nil,
		func(ws string) { mustWrite(t, ws, basicManifest, "# hi\n") },
		func(ws string) { mustWrite(t, ws, basicManifest, "# hi\n\nchanged\n") },
	)

	if ev.ChangeCounts["modified"] != 1 {
		t.Errorf("missing modified change: %+v", ev.ChangeCounts)
	}
	if len(ev.Commands) != 1 || ev.Commands[0] != "go build ./..." {
		t.Errorf("commands = %v", ev.Commands)
	}
	if ev.Network.ExternalAccess != "observed (1 destination(s))" {
		t.Errorf("external access = %q", ev.Network.ExternalAccess)
	}
	if len(ev.Network.Destinations) != 1 || ev.Network.Destinations[0].Domain != "api.example.com" {
		t.Errorf("destinations = %+v", ev.Network.Destinations)
	}
	if ev.ScreenOrUI != "none observed" {
		t.Errorf("screen_ui_access = %q, want none observed", ev.ScreenOrUI)
	}
	if ev.ReviewID == "" {
		t.Error("review_id must be populated")
	}
}

func TestEvidenceExplicitlyReportsNoExternalAccess(t *testing.T) {
	sid := "00000000-0000-4000-8000-000000000002"
	ev, _ := newTestEvidence(t,
		[]events.Event{
			mkEvent(events.SourceHook, events.TypeFileRead, events.SevLow, sid,
				map[string]any{"path": "/workspace/main.go", "sensitive": false}),
		},
		nil,
		nil,
		func(ws string) { mustWrite(t, ws, "main.go", "package main\nfunc main() {}\n") },
	)

	if ev.Network.ExternalAccess != "none" {
		t.Errorf("external access = %q, want none", ev.Network.ExternalAccess)
	}
	if ev.ScreenOrUI != "none observed" {
		t.Errorf("screen_ui_access = %q, want none observed", ev.ScreenOrUI)
	}
	if len(ev.Network.Destinations) != 0 {
		t.Errorf("unexpected destinations: %+v", ev.Network.Destinations)
	}
}

func TestEvidenceSecretsNeverReachThePrompt(t *testing.T) {
	sid := "00000000-0000-4000-8000-000000000003"
	secretSnippet := "package app\nconst key = \"" + rawSecret + "\"\n"
	ev, _ := newTestEvidence(t,
		[]events.Event{
			mkEvent(events.SourceHook, events.TypeCommandExec, events.SevInfo, sid,
				map[string]any{"command": "curl -H \"Authorization: Bearer " + rawSecret + "\" https://api.example.com"}),
		},
		[]findings.Finding{
			findings.New("gitleaks", findings.SevHigh, "app/config.go", 7, "generic-api-key",
				"hardcoded key "+rawSecretAWS+" found", true),
		},
		func(ws string) { mustWrite(t, ws, "app/config.go", secretSnippet) },
		func(ws string) { mustWrite(t, ws, "app/config.go", secretSnippet+"\n// edited\n") },
	)

	b, _ := json.Marshal(ev)
	if strings.Contains(string(b), rawSecret) {
		t.Fatal("evidence JSON contains a raw API secret")
	}
	if strings.Contains(string(b), rawSecretAWS) {
		t.Fatal("evidence JSON contains a raw AWS access key")
	}
	if len(ev.Snippets) == 0 {
		t.Fatal("expected a snippet for the flagged file")
	}
	if strings.Contains(strings.Join(ev.Snippets[0].Lines, "\n"), rawSecret) {
		t.Fatal("snippet leaks the raw secret")
	}

	// The prompt that reaches the model is only this redacted evidence.
	system, user := PromptForReview(ev)
	_ = system
	if strings.Contains(user, rawSecret) || strings.Contains(user, rawSecretAWS) {
		t.Fatal("model prompt leaks a secret")
	}
	if strings.Contains(user, "conversation") {
		t.Fatal("prompt unexpectedly references the conversation")
	}
}

func TestEvidenceTracksSensitiveAccesses(t *testing.T) {
	sid := "00000000-0000-4000-8000-000000000004"
	ev, _ := newTestEvidence(t,
		[]events.Event{
			mkEvent(events.SourceHook, events.TypeFileRead, events.SevLow, sid,
				map[string]any{"path": "/workspace/.aws/credentials", "sensitive": true}),
			mkEvent(events.SourceHook, events.TypeFileWrite, events.SevInfo, sid,
				map[string]any{"path": "/workspace/.env", "sensitive": true}),
		},
		nil,
		nil,
		func(ws string) {
			mustWrite(t, ws, ".env", "A=1\n")
			mustWrite(t, ws, "main.go", "package main\n")
		},
	)

	if len(ev.SensitiveAccesses) != 2 {
		t.Fatalf("sensitive accesses = %v", ev.SensitiveAccesses)
	}
	joined := strings.Join(ev.SensitiveAccesses, " ")
	if !strings.Contains(joined, ".aws/credentials") || !strings.Contains(joined, ".env") {
		t.Errorf("missing sensitive paths in %v", ev.SensitiveAccesses)
	}
}

func TestEvidenceTracksBlockedDestinationsAndIncidents(t *testing.T) {
	sid := "00000000-0000-4000-8000-000000000005"
	ev, _ := newTestEvidence(t,
		[]events.Event{
			mkEvent(events.SourceProxy, events.TypeNetworkConnect, events.SevMedium, sid,
				map[string]any{"domain": "evil.com", "port": 443, "decision": "block", "reason": "domain not in allowlist"}),
			mkEvent(events.SourcePolicy, events.TypeIncident, events.SevCritical, sid,
				map[string]any{"rule_id": "SENSITIVE_EGRESS_ATTEMPT_V1", "summary": "sensitive read then blocked egress"}),
		},
		nil,
		nil,
		func(ws string) { mustWrite(t, ws, "main.go", "package main\n") },
	)

	if len(ev.Network.Destinations) != 1 || !ev.Network.Destinations[0].Blocked {
		t.Fatalf("blocked destination missing: %+v", ev.Network.Destinations)
	}
	if len(ev.Incidents) != 1 || !strings.Contains(ev.Incidents[0], "SENSITIVE_EGRESS_ATTEMPT_V1") {
		t.Fatalf("incidents = %v", ev.Incidents)
	}
}

func TestEvidenceStaysUnderTokenBudgetWithABigSession(t *testing.T) {
	sid := "00000000-0000-4000-8000-000000000006"
	var evs []events.Event
	for i := 0; i < 300; i++ {
		evs = append(evs, mkEvent(events.SourceHook, events.TypeCommandExec, events.SevInfo, sid,
			map[string]any{"command": "run --flag value " + strings.Repeat("x", 40) + " " + rawSecret}))
		evs = append(evs, mkEvent(events.SourceProxy, events.TypeNetworkConnect, events.SevInfo, sid,
			map[string]any{"domain": "api" + string(rune('a'+i%26)) + ".example.com", "port": 443, "decision": "allow"}))
	}
	ev, _ := newTestEvidence(t, evs, nil,
		nil,
		func(ws string) {
			for i := 0; i < 50; i++ {
				mustWrite(t, ws, "f"+string(rune('a'+i%26))+".go", "package f\n")
			}
		},
	)

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxEvidenceJSON {
		t.Errorf("evidence too large: %d bytes > %d", len(b), MaxEvidenceJSON)
	}
	if strings.Contains(string(b), rawSecret) || strings.Contains(string(b), "sk-ant") {
		t.Fatal("evidence leaked a secret under load")
	}
}

func TestRedact(t *testing.T) {
	if got := Redact("go build ./..."); got != "go build ./..." {
		t.Errorf("benign command was altered: %q", got)
	}
	for _, in := range []string{
		"ANTHROPIC_API_KEY=" + rawSecret,
		"key:" + rawSecret,
		rawSecretAWS,
		"ghp_1234567890123456789012abcdef",
		"xoxb-1234567890-abcdefghij",
		"bot12345678:AABBCCDDEEFFGGHHIIJJKK",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
	} {
		if got := Redact(in); !strings.Contains(got, "[REDACTED]") || strings.Contains(got, rawSecret[:12]) {
			t.Errorf("Redact(%q) = %q, want secret fully masked", in, got)
		}
	}
	urlMasked := Redact("https://user:" + rawSecret + "@host/path")
	if urlMasked != "[REDACTED]host/path" {
		t.Errorf("url redaction = %q", urlMasked)
	}
	bearer := Redact("Authorization: Bearer " + rawSecret)
	if strings.Contains(bearer, rawSecret) || !strings.Contains(bearer, "[REDACTED]") {
		t.Errorf("bearer redaction = %q", bearer)
	}
}

func writeFile(t *testing.T, dir, name, content string) error {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
}

func mustWrite(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := writeFile(t, dir, name, content); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}