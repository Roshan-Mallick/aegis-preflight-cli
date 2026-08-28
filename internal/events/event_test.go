package events

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func validEvent() Event {
	return New(SourceProxy, TypeNetworkConnect, SevMedium, "claude", uuid.NewString(), map[string]any{"domain": "evil.com", "decision": "block"})
}

func TestNewGeneratesCanonicalFields(t *testing.T) {
	e := validEvent()
	if _, err := uuid.Parse(e.EventID); err != nil {
		t.Fatalf("event_id not a uuid: %v", err)
	}
	if _, err := uuid.Parse(e.SessionID); err != nil {
		t.Fatalf("session_id not a uuid: %v", err)
	}
	if e.Timestamp == "" {
		t.Fatal("timestamp empty")
	}
	if e.Data == nil {
		t.Fatal("data must never be nil")
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("generated event failed validation: %v", err)
	}
}

func TestValidateAcceptsMinimalNullableCorrelation(t *testing.T) {
	e := validEvent()
	if e.CorrelationID != nil {
		t.Fatal("correlation_id must default to null")
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	e = WithCorrelation(e, uuid.NewString())
	if err := e.Validate(); err != nil {
		t.Fatalf("validate with correlation: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Event)
	}{
		{"missing event id", func(e *Event) { e.EventID = "" }},
		{"malformed event id", func(e *Event) { e.EventID = "not-a-uuid" }},
		{"missing session id", func(e *Event) { e.SessionID = "" }},
		{"bad timestamp", func(e *Event) { e.Timestamp = "yesterday" }},
		{"unknown source", func(e *Event) { e.Source = "kernel" }},
		{"empty source", func(e *Event) { e.Source = "" }},
		{"unknown severity", func(e *Event) { e.Severity = "warn" }},
		{"empty type", func(e *Event) { e.Type = "" }},
		{"type without namespace", func(e *Event) { e.Type = "file_read" }},
		{"uppercase type", func(e *Event) { e.Type = "File.Read" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEvent()
			tc.mutate(&e)
			if err := e.Validate(); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestValidTypeNamespaced(t *testing.T) {
	for _, ok := range []string{"file.read", "network.connect", "session.state_changed_2", "policy.block"} {
		if !ValidType(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"read", "", "File.Read", "file.", ".read", "file read"} {
		if ValidType(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestSeverityConstants(t *testing.T) {
	want := []string{SevInfo, SevLow, SevMedium, SevHigh, SevCritical}
	for i, s := range want {
		if s == "" || strings.ContainsAny(s, " ") {
			t.Errorf("severity %d invalid: %q", i, s)
		}
	}
}
