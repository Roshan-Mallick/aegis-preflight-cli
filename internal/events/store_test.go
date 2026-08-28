package events

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestAppendReadAllRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sid := uuid.NewString()
	e1 := New(SourceHook, TypeFileRead, SevLow, "claude", sid, map[string]any{"path": "/w/src/main.go"})
	corr := uuid.NewString()
	e2 := WithCorrelation(New(SourceProxy, TypeNetworkConnect, SevCritical, "claude", sid, map[string]any{"domain": "evil.com"}), corr)
	e3 := New(SourcePolicy, TypeIncident, SevCritical, "aegis", sid, nil)

	for _, e := range []Event{e1, e2, e3} {
		if err := st.Append(e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := ReadAll(dir)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 events, got %d", len(got))
	}
	if got[0].Type != TypeFileRead || got[2].Type != TypeIncident {
		t.Fatal("order not preserved")
	}
	if got[1].CorrelationID == nil || *got[1].CorrelationID != corr {
		t.Fatal("correlation_id lost in round trip")
	}
	for _, e := range got {
		if err := e.Validate(); err != nil {
			t.Fatalf("stored event invalid: %v", err)
		}
	}
}

func TestStoreEnforcesPermissions(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	info, err := os.Stat(LogPath(dir))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("authoritative log perms = %v, want 0600", got)
	}
}

func TestAppendRejectsInvalidEventWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	good := New(SourceSandbox, TypeSessionCreated, SevInfo, "aegis", uuid.NewString(), nil)
	if err := st.Append(good); err != nil {
		t.Fatalf("append good: %v", err)
	}
	bad := good
	bad.Source = "unauthorized-source"
	if err := st.Append(bad); err == nil {
		t.Fatal("expected append of invalid event to fail")
	}
	got, err := ReadAll(dir)
	if err != nil {
		t.Fatalf("readall after rejected append: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("log must contain only valid events, got %d", len(got))
	}
}

func TestReadAllDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	if err := st.Append(New(SourceScanner, TypeFinding, SevHigh, "gitleaks", uuid.NewString(), nil)); err != nil {
		t.Fatal(err)
	}
	st.Close()

	path := LogPath(dir)
	raw, _ := os.ReadFile(path)
	tampered := []byte(`{"event_id":"nope","session_id":"nope","timestamp":"x","source":"agent","type":"lie","severity":"none","data":{}}` + "\n")
	if err := os.WriteFile(path, append(raw, tampered...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAll(dir); err == nil {
		t.Fatal("ReadAll must reject malformed/injected lines")
	}
}

func TestReadAllMissingLogIsEmpty(t *testing.T) {
	got, err := ReadAll(filepath.Join(t.TempDir(), "nonexistent-session"))
	if err != nil {
		t.Fatalf("missing log should not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 events, got %d", len(got))
	}
}
