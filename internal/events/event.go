package events

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	SourceHook    = "hook"
	SourceProxy   = "proxy"
	SourceSandbox = "sandbox"
	SourceScanner = "scanner"
	SourcePolicy  = "policy"
	SourceModel   = "model"

	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"

	TypeFileRead       = "file.read"
	TypeFileWrite      = "file.write"
	TypeFileDelete     = "file.delete"
	TypeNetworkConnect = "network.connect"
	TypeCommandExec    = "command.exec"
	TypeFinding        = "finding"
	TypeIncident       = "incident"
	TypeSessionCreated = "session.created"
	TypeSessionState   = "session.state"
	TypeModelRequest   = "model.request"
	TypeModelResponse  = "model.response"
	TypeModelError     = "model.error"
	TypeModelLatency   = "model.latency"
)

var validSources = map[string]bool{
	SourceHook:    true,
	SourceProxy:   true,
	SourceSandbox: true,
	SourceScanner: true,
	SourcePolicy:  true,
	SourceModel:   true,
}

var validSeverities = map[string]bool{
	SevInfo:     true,
	SevLow:      true,
	SevMedium:   true,
	SevHigh:     true,
	SevCritical: true,
}

var typeRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)

var reservedBareTypes = map[string]bool{
	TypeFinding:  true,
	TypeIncident: true,
}

type Event struct {
	EventID       string         `json:"event_id"`
	SessionID     string         `json:"session_id"`
	Timestamp     string         `json:"timestamp"`
	Source        string         `json:"source"`
	Type          string         `json:"type"`
	Severity      string         `json:"severity"`
	Actor         string         `json:"actor,omitempty"`
	Data          map[string]any `json:"data"`
	CorrelationID *string        `json:"correlation_id,omitempty"`
}

func New(source, typ, severity, actor, sessionID string, data map[string]any) Event {
	if data == nil {
		data = map[string]any{}
	}
	return Event{
		EventID:   uuid.NewString(),
		SessionID: sessionID,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Source:    source,
		Type:      typ,
		Severity:  severity,
		Actor:     actor,
		Data:      data,
	}
}

func WithCorrelation(e Event, correlationID string) Event {
	e.CorrelationID = &correlationID
	return e
}

func ValidType(t string) bool {
	if !typeRe.MatchString(t) {
		return false
	}
	if !strings.Contains(t, ".") {
		return reservedBareTypes[t]
	}
	return true
}

func (e Event) Validate() error {
	if _, err := uuid.Parse(e.EventID); err != nil {
		return fmt.Errorf("event_id: %w", err)
	}
	if _, err := uuid.Parse(e.SessionID); err != nil {
		return fmt.Errorf("session_id: %w", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, e.Timestamp); err != nil {
		return fmt.Errorf("timestamp: %w", err)
	}
	if !validSources[e.Source] {
		return fmt.Errorf("source: unknown source %q", e.Source)
	}
	if !ValidType(e.Type) {
		return fmt.Errorf("type: invalid event type %q", e.Type)
	}
	if !validSeverities[e.Severity] {
		return fmt.Errorf("severity: unknown severity %q", e.Severity)
	}
	if e.Data == nil {
		return fmt.Errorf("data: required non-nil object")
	}
	return nil
}
