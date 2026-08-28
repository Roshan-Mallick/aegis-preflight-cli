package correlate

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/policy"
)

const (
	RuleSensitiveEgress = "SENSITIVE_EGRESS_ATTEMPT_V1"
	DefaultWindow       = 5 * time.Minute
)

type Engine struct {
	window time.Duration

	mu        sync.Mutex
	armed     []events.Event
	firedIDs  map[string]bool
	sessionID string
}

func NewEngine(sessionID string, window time.Duration) *Engine {
	if window <= 0 {
		window = DefaultWindow
	}
	return &Engine{
		window:    window,
		firedIDs:  map[string]bool{},
		sessionID: sessionID,
	}
}

type Incident struct {
	ID         string         `json:"id"`
	SessionID  string         `json:"session_id"`
	RuleID     string         `json:"rule_id"`
	DetectedAt string         `json:"detected_at"`
	Summary    string         `json:"summary"`
	Events     []events.Event `json:"events"`
}

func isSensitiveAccess(ev events.Event) bool {
	switch ev.Type {
	case events.TypeFileRead, events.TypeFileWrite:
		if v, ok := ev.Data["sensitive"].(bool); ok && v {
			return true
		}
	case events.TypeCommandExec:
		cmd, _ := ev.Data["command"].(string)
		return CommandTouchesSensitive(cmd)
	}
	return false
}

func CommandTouchesSensitive(cmd string) bool {
	if cmd == "" {
		return false
	}
	fields := strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '"' || r == '\'' || r == '=' ||
			r == ',' || r == ';' || r == '|' || r == '(' || r == ')'
	})
	for _, f := range fields {
		if policy.IsSensitivePath(strings.Trim(f, "`'\"")) {
			return true
		}
	}
	return false
}

func isSuspiciousEgress(ev events.Event) bool {
	if ev.Type != events.TypeNetworkConnect {
		return false
	}
	d, _ := ev.Data["decision"].(string)
	return d == "block"
}

func (e *Engine) pruneArmed(now time.Time) {
	kept := e.armed[:0]
	for _, ev := range e.armed {
		ts, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
		if err == nil && now.Sub(ts) <= e.window {
			kept = append(kept, ev)
		}
	}
	e.armed = kept
}

func (e *Engine) Observe(ev events.Event) *Incident {
	if ev.SessionID != e.sessionID {
		return nil
	}
	now, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
	if err != nil {
		now = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneArmed(now)

	switch {
	case isSensitiveAccess(ev):
		e.armed = append(e.armed, ev)
		return nil
	case isSuspiciousEgress(ev):
		if len(e.armed) == 0 {
			return nil
		}
		if e.firedIDs[ev.EventID] {
			return nil
		}
		e.firedIDs[ev.EventID] = true
		contributing := append([]events.Event{}, e.armed...)
		contributing = append(contributing, ev)
		e.armed = nil
		return &Incident{
			ID:         uuid.NewString(),
			SessionID:  e.sessionID,
			RuleID:     RuleSensitiveEgress,
			DetectedAt: ev.Timestamp,
			Summary: fmt.Sprintf("sensitive resource access followed by blocked egress attempt (%d correlated event(s)) within %s",
				len(contributing), e.window),
			Events: contributing,
		}
	default:
		return nil
	}
}

func (e *Engine) ArmedCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneArmed(time.Now().UTC())
	return len(e.armed)
}

func EvaluateAll(sessionID string, all []events.Event, window time.Duration) []*Incident {
	eng := NewEngine(sessionID, window)
	var out []*Incident
	for _, ev := range all {
		if inc := eng.Observe(ev); inc != nil {
			out = append(out, inc)
		}
	}
	return out
}
