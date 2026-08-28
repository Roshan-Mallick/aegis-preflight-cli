package correlate

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/eth0x1/aegis/internal/events"
)

const sid = "aaaa1111-2222-3333-4444-555555555555"

func ts(offsetMS int) string {
	return time.Now().UTC().Add(time.Duration(offsetMS) * time.Millisecond).Format(time.RFC3339Nano)
}

func sensitiveReadEv(at int) events.Event {
	e := events.New(events.SourceHook, events.TypeFileRead, events.SevLow, "claude", sid,
		map[string]any{"path": "/workspace/.env", "sensitive": true})
	e.Timestamp = ts(at)
	return e
}

func blockedConnectEv(at int, domain string) events.Event {
	e := events.New(events.SourceProxy, events.TypeNetworkConnect, events.SevMedium, "egress-gateway", sid,
		map[string]any{"domain": domain, "decision": "block", "reason": "domain not in allowlist"})
	e.Timestamp = ts(at)
	return e
}

func benignEv(at int) events.Event {
	e := events.New(events.SourceHook, events.TypeFileRead, events.SevLow, "claude", sid,
		map[string]any{"path": "/workspace/src/main.go", "sensitive": false})
	e.Timestamp = ts(at)
	return e
}

func TestCorrelatorFiresOnSensitiveThenBlocked(t *testing.T) {
	eng := NewEngine(sid, time.Minute)
	if inc := eng.Observe(benignEv(0)); inc != nil {
		t.Fatal("benign read must not arm")
	}
	if inc := eng.Observe(blockedConnectEv(100, "evil.com")); inc != nil {
		t.Fatal("blocked connect without sensitive access must NOT fire")
	}
	if eng.ArmedCount() != 0 {
		t.Fatalf("armed=%d after benign traffic", eng.ArmedCount())
	}
	if inc := eng.Observe(sensitiveReadEv(200)); inc != nil {
		t.Fatal("arming must not itself fire")
	}
	if eng.ArmedCount() != 1 {
		t.Fatalf("armed=%d, want 1", eng.ArmedCount())
	}
	inc := eng.Observe(blockedConnectEv(300, "evil.com"))
	if inc == nil {
		t.Fatal("incident did not fire")
	}
	if inc.RuleID != RuleSensitiveEgress {
		t.Errorf("rule=%s", inc.RuleID)
	}
	if len(inc.Events) != 2 {
		t.Errorf("contributing=%d, want 2", len(inc.Events))
	}
	if inc.Events[0].Type != events.TypeFileRead || inc.Events[1].Data["domain"] != "evil.com" {
		t.Error("contributing events wrong")
	}
	if _, err := uuid.Parse(inc.ID); err != nil {
		t.Errorf("incident id invalid: %v", err)
	}
}

func TestCorrelatorDisarmsAfterFire(t *testing.T) {
	eng := NewEngine(sid, time.Minute)
	eng.Observe(sensitiveReadEv(0))
	if eng.Observe(blockedConnectEv(50, "evil.com")) == nil {
		t.Fatal("should fire once")
	}
	if eng.ArmedCount() != 0 {
		t.Fatal("must disarm after firing")
	}
	if eng.Observe(blockedConnectEv(60, "evil.com")) != nil {
		t.Fatal("second block without new sensitive access must not re-fire")
	}
}

func TestCorrelatorWindowExpiry(t *testing.T) {
	eng := NewEngine(sid, 200*time.Millisecond)
	eng.Observe(sensitiveReadEv(-10_000))
	time.Sleep(300 * time.Millisecond)
	if eng.ArmedCount() != 0 {
		t.Fatal("armed entry should expire outside window")
	}
	if eng.Observe(blockedConnectEv(0, "evil.com")) != nil {
		t.Fatal("stale arming must not correlate")
	}
}
func TestCorrelatorBashSensitiveDetection(t *testing.T) {
	eng := NewEngine(sid, time.Minute)
	ev := events.New(events.SourceHook, events.TypeCommandExec, events.SevInfo, "claude", sid,
		map[string]any{"command": "cat /workspace/.env.production"})
	ev.Timestamp = ts(0)
	eng.Observe(ev)
	if eng.ArmedCount() != 1 {
		t.Fatalf("bash cat .env must arm, armed=%d", eng.ArmedCount())
	}

	ev2 := events.New(events.SourceHook, events.TypeCommandExec, events.SevInfo, "claude", sid,
		map[string]any{"command": "go test ./..."})
	ev2.Timestamp = ts(10)
	eng.Observe(ev2)
	if eng.ArmedCount() != 1 {
		t.Fatalf("benign command must not arm, armed=%d", eng.ArmedCount())
	}
}

func TestCorrelatorIgnoresOtherSessions(t *testing.T) {
	eng := NewEngine(sid, time.Minute)
	other := events.New(events.SourceHook, events.TypeFileRead, events.SevLow, "claude",
		uuid.NewString(), map[string]any{"sensitive": true})
	eng.Observe(other)
	if eng.ArmedCount() != 0 {
		t.Fatal("cross-session event leaked into correlator")
	}
}

func TestEvaluateAllBatch(t *testing.T) {
	all := []events.Event{benignEv(0), sensitiveReadEv(10), blockedConnectEv(20, "evil.com")}
	got := EvaluateAll(sid, all, time.Minute)
	if len(got) != 1 {
		t.Fatalf("batch incidents = %d, want 1", len(got))
	}
}
