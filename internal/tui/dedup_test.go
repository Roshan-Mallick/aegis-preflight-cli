package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/eth0x1/aegis/internal/events"
)

// Mirrors the user's reported "NETWORK.CONNECT egress-gateway" flood.
func TestNetworkConnectFlood(t *testing.T) {
	f := NewFeed(100)
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < 37; i++ {
		f.Push(events.Event{
			Timestamp: ts,
			Type:      events.TypeNetworkConnect,
			Source:    events.SourceProxy,
			Actor:     "egress-gateway",
			Data:      map[string]any{"dest": "api.openai.com"},
		})
	}
	if len(f.Lines()) != 1 {
		t.Fatalf("expected 1 deduped line, got %d: %v", len(f.Lines()), f.Lines())
	}
	line := f.Lines()[0]
	if !strings.Contains(line, "NETWORK.CONNECT") || !strings.Contains(line, "egress-gateway") || !strings.Contains(line, "×37") {
		t.Errorf("line missing elements: %s", line)
	}
	t.Logf("deduped line: %s", line)
}
