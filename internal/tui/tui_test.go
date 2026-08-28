package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/eth0x1/aegis/internal/events"
)

func TestFeedPushFinding(t *testing.T) {
	f := NewFeed(50)
	evt := events.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Type:      events.TypeFinding,
		Source:    events.SourceScanner,
		Severity:  "high",
		Actor:     "aegis",
		Data: map[string]any{
			"rule":    "generic-api-key",
			"file":    "src/config.py",
			"message": "detected a secret",
		},
	}
	f.Push(evt)
	lines := f.Lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	line := lines[0]
	if !strings.Contains(line, "FINDING") {
		t.Errorf("missing FINDING label: %s", line)
	}
	if !strings.Contains(line, "generic-api-key") {
		t.Errorf("missing rule: %s", line)
	}
}

func TestFeedPushCommandExec(t *testing.T) {
	f := NewFeed(50)
	evt := events.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Type:      events.TypeCommandExec,
		Source:    events.SourceHook,
		Severity:  "info",
		Actor:     "claude",
		Data: map[string]any{
			"tool": "Bash",
		},
	}
	f.Push(evt)
	lines := f.Lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "COMMAND.EXEC") {
		t.Errorf("missing COMMAND.EXEC: %s", lines[0])
	}
}

func TestFeedMaxLines(t *testing.T) {
	f := NewFeed(3)
	for i := 0; i < 10; i++ {
		f.Push(events.Event{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Type:      events.TypeCommandExec,
			Source:    events.SourceHook,
			Actor:     "test",
			Data:      map[string]any{"seq": i},
		})
	}
	if len(f.Lines()) != 3 {
		t.Errorf("expected 3 lines, got %d", len(f.Lines()))
	}
}

func TestFeedViewDimensions(t *testing.T) {
	f := NewFeed(10)
	f.Push(events.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Type:      events.TypeFinding,
		Severity:  "critical",
		Actor:     "test",
		Data:      map[string]any{"rule": "test-rule"},
	})
	v := f.View(80, 24)
	if !strings.Contains(v, "Security Feed") {
		t.Error("missing title")
	}
}

func TestStatusBarState(t *testing.T) {
	bar := StatusBar{
		SessionID: "aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee",
		State:     "running",
		Network:   "strict",
		Width:     80,
	}
	v := bar.View()
	if !strings.Contains(v, "aaaa1111") {
		t.Errorf("missing session prefix: %s", v)
	}
	if !strings.Contains(v, "strict") {
		t.Errorf("missing network: %s", v)
	}
}

func TestStatusBarBlocked(t *testing.T) {
	bar := StatusBar{
		SessionID: "aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee",
		State:     "blocked",
		Network:   "strict",
		Width:     80,
	}
	v := bar.View()
	if !strings.Contains(v, "BLOCKED") {
		t.Errorf("expected BLOCKED, got: %s", v)
	}
}

func TestStatusBarWidth(t *testing.T) {
	bar := StatusBar{
		SessionID: "aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee",
		State:     "running",
		Width:     120,
	}
	v := bar.View()
	if !strings.Contains(v, "120") {
		_ = v
	}
}

func TestExecSessionNotRunning(t *testing.T) {
	es := NewExecSession("fake-id")
	if es.Running() {
		t.Error("should not be running before start")
	}
	_, err := es.Write([]byte("hello"))
	if err == nil {
		t.Error("write should fail when not running")
	}
}

func TestExecSessionKillNotRunning(t *testing.T) {
	es := NewExecSession("fake-id")
	if err := es.Kill(); err != nil {
		t.Errorf("kill on non-running: %v", err)
	}
}

func TestFeedDeduplication(t *testing.T) {
	model := NewModel(Config{
		Session: nil,
		Network: "strict",
	})
	if model.lastEventIdx != 0 {
		t.Errorf("initial lastEventIdx = %d, want 0", model.lastEventIdx)
	}
	model.findingCount = 0
	for i := 0; i < 5; i++ {
		evt := events.Event{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Type:      events.TypeFinding,
			Severity:  "high",
			Actor:     "test",
			Data:      map[string]any{"rule": "test-rule"},
		}
		model.feed.Push(evt)
		model.findingCount++
	}
	if model.findingCount != 5 {
		t.Errorf("findingCount = %d, want 5", model.findingCount)
	}
}

// --- Escape sequence chunk-boundary tests ---

// helper: extract visible text from screen rows (strips trailing spaces)
func screenText(s *Screen) string {
	var b strings.Builder
	for _, row := range s.Rows() {
		b.WriteString(strings.TrimRight(row, " "))
		b.WriteString("\n")
	}
	return b.String()
}

func TestCSISplitAcrossChunks(t *testing.T) {
	// Simulate a CSI sequence split across two Feed calls.
	// ESC[38;5;196m is an SGR set foreground color — should be consumed silently.
	s := NewScreen(5, 80)

	// Chunk 1: partial CSI (no final byte)
	s.Feed([]byte("hello\x1b[38"))
	// No visible escape fragments should appear.
	text := screenText(s)
	if strings.Contains(text, "38") {
		t.Errorf("chunk 1 leaked CSI parameter as text: %q", text)
	}

	// Chunk 2: completes the CSI sequence, followed by visible text.
	s.Feed([]byte(";5;196m world"))
	text = screenText(s)
	if strings.Contains(text, "38") || strings.Contains(text, "196") {
		t.Errorf("completed CSI leaked parameters: %q", text)
	}
	if !strings.Contains(text, "hello") || !strings.Contains(text, "world") {
		t.Errorf("lost visible text around CSI: %q", text)
	}
}

func testCSISplitAcrossChunks(t *testing.T) {
	s := NewScreen(5, 80)
	s.Feed([]byte("A\x1b[2J"))
	text := screenText(s)
	// ESC[2J clears screen — only "A" should appear before the clear.
	// After clear, screen is blank.
	if strings.Contains(text, "\x1b") || strings.Contains(text, "[2J") {
		t.Errorf("CSI leaked as text: %q", text)
	}
}

func TestCSIWithoutFinalByteInBuffer(t *testing.T) {
	// ESC followed by [ but nothing else in one chunk, then the terminator
	// arrives in the next chunk. The CSI should be reassembled and consumed.
	s := NewScreen(5, 80)
	s.Feed([]byte("before\x1b["))
	s.Feed([]byte("1Aafter")) // ESC[1A = cursor up 1 (cosmetic only, won't erase text)
	text := screenText(s)
	if strings.Contains(text, "\x1b") || strings.Contains(text, "[1A") {
		t.Errorf("incomplete CSI leaked: %q", text)
	}
	if !strings.Contains(text, "before") || !strings.Contains(text, "after") {
		t.Errorf("lost text around CSI: %q", text)
	}
}

func TestCharSetDesignation(t *testing.T) {
	// ESC(B is a character set designation (3 bytes). Should be consumed silently.
	s := NewScreen(5, 80)
	s.Feed([]byte("hello\x1b(Bworld"))
	text := screenText(s)
	if strings.Contains(text, "(B") {
		t.Errorf("char set designation leaked: %q", text)
	}
	if !strings.Contains(text, "hello") || !strings.Contains(text, "world") {
		t.Errorf("lost text around char set: %q", text)
	}
}

func TestCharSetDesignationSplit(t *testing.T) {
	s := NewScreen(5, 80)
	s.Feed([]byte("A\x1b("))
	s.Feed([]byte("BZ"))
	text := screenText(s)
	// ESC( is incomplete, buffered. Then "BZ" arrives — the "B" is the
	// char-set byte, "Z" should be visible.
	if strings.Contains(text, "(B") {
		t.Errorf("char set leaked: %q", text)
	}
	if !strings.Contains(text, "Z") {
		t.Errorf("lost visible text after char set: %q", text)
	}
}

func TestOSCSplitAcrossChunks(t *testing.T) {
	// OSC sequences terminated by BEL (0x07).
	s := NewScreen(5, 80)
	s.Feed([]byte("before\x1b]0;title"))
	s.Feed([]byte("\x07after"))
	text := screenText(s)
	if strings.Contains(text, "\x1b") || strings.Contains(text, "]0") {
		t.Errorf("OSC leaked: %q", text)
	}
	if !strings.Contains(text, "before") || !strings.Contains(text, "after") {
		t.Errorf("lost text around OSC: %q", text)
	}
}

func TestNoEscapeLeakage(t *testing.T) {
	// Comprehensive test: real-world PTY output with multiple escape sequences
	// of varying lengths, some split across chunks.
	s := NewScreen(20, 120)

	// Simulate OpenCode-like output with SGR, cursor movement, and clear.
	chunks := [][]byte{
		[]byte("Welcome to OpenCode\x1b[1m\x1b[38;5;39m"),
		{0x1b, '[', '2', 'J'},               // clear screen
		[]byte("\x1b[1;1HLine 1\x1b[0m"),    // move to 1;1, write, reset SGR
		[]byte("\x1b[2;1HLine 2\x1b[38;5;"), // partial SGR
		[]byte("196mError\x1b[0m"),          // complete SGR
		[]byte("\x1b[?25l"),                 // hide cursor (private mode)
		[]byte("text after hidden cursor"),
	}

	for _, chunk := range chunks {
		s.Feed(chunk)
	}

	text := screenText(s)
	// Check for common escape sequence fragments.
	bad := []string{"\x1b", "[2J", "[1;1H", "[0m", "[38;5;", "[?25l"}
	for _, frag := range bad {
		if strings.Contains(text, frag) {
			t.Errorf("escape fragment leaked: %q (fragment: %q)", text, frag)
		}
	}
}

func TestFeedDeduplicationCount(t *testing.T) {
	// Test that consecutive identical events are deduped with count.
	f := NewFeed(50)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < 5; i++ {
		f.Push(events.Event{
			Timestamp: now,
			Type:      events.TypeNetworkConnect,
			Source:    events.SourceProxy,
			Actor:     "egress-gateway",
			Data:      map[string]any{"dest": "api.example.com"},
		})
	}
	lines := f.Lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 deduped line, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "×5") {
		t.Errorf("missing dedup count ×5: %s", lines[0])
	}
}

func TestFeedDedupDifferentData(t *testing.T) {
	// Events with same type+actor but different data should NOT be deduped.
	f := NewFeed(50)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	f.Push(events.Event{
		Timestamp: now, Type: events.TypeCommandExec, Actor: "test",
		Data: map[string]any{"tool": "Bash"},
	})
	f.Push(events.Event{
		Timestamp: now, Type: events.TypeCommandExec, Actor: "test",
		Data: map[string]any{"tool": "Read"},
	})
	lines := f.Lines()
	if len(lines) != 2 {
		t.Fatalf("expected 2 non-deduped lines, got %d", len(lines))
	}
}

// TestLoneESCAtChunkBoundary verifies that an ESC byte at the very end of a
// chunk is buffered and combined with the following byte in the next chunk,
// so a sequence split as ESC | [0;33m does not leak "[0;33m" as text.
func TestLoneESCAtChunkBoundary(t *testing.T) {
	s := NewScreen(5, 80)
	s.Feed([]byte("a\x1b")) // ESC is now the last byte
	s.Feed([]byte("[0;33mb\x1b[0m"))
	text := screenText(s)
	if strings.Contains(text, "[0;33m") {
		t.Errorf("lone-ESC-split SGR leaked: %q", text)
	}
	if !strings.Contains(text, "b") {
		t.Errorf("lost text after SGR: %q", text)
	}
	if strings.Contains(text, "\x1b") {
		t.Errorf("raw ESC leaked: %q", text)
	}
}

// TestLoneESCBeforeCharSet verifies ESC as last byte before a char-set
// designation (ESC ( B) that follows.
func TestLoneESCBeforeCharSet(t *testing.T) {
	s := NewScreen(5, 80)
	s.Feed([]byte("x\x1b"))
	s.Feed([]byte("(Byy"))
	text := screenText(s)
	if strings.Contains(text, "(B") || strings.Contains(text, "\x1b") {
		t.Errorf("char set after lone ESC leaked: %q", text)
	}
	if !strings.Contains(text, "yy") {
		t.Errorf("lost text after char set: %q", text)
	}
}

// TestUserReportedANSILeak regression: previously leaked fragments "8;2;10;10m"
// and "0;" across chunk boundaries.
func TestUserReportedANSILeak(t *testing.T) {
	// Simulate PTY reads splitting an SGR + color sequence at every position.
	// The exact fragments the user saw were "8;2;10;10m" and "0;". These are
	// the remainder of CSI sequences whose ESC[ prefix was consumed but whose
	// parameter bytes leaked as text because of incomplete-sequence handling.
	seq := []byte("text\x1b[8;2;10;10mmore\x1b[0;\x1b[38;5;196mEND")
	for split := 1; split < len(seq); split++ {
		s := NewScreen(5, 120)
		s.Feed(seq[:split])
		s.Feed(seq[split:])
		for _, row := range s.Rows() {
			if strings.Contains(row, "8;2;10;10m") {
				t.Fatalf("split=%d: leaked '8;2;10;10m': %q", split, row)
			}
			if strings.Contains(row, "0;") {
				t.Fatalf("split=%d: leaked '0;': %q", split, row)
			}
			if strings.Contains(row, "\x1b") {
				t.Fatalf("split=%d: raw ESC leaked: %q", split, row)
			}
		}
	}
}

func TestStatusBarFindingCount(t *testing.T) {
	bar := StatusBar{
		SessionID:    "aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee",
		State:        "running",
		FindingCount: 3,
		BlockCount:   2,
		Network:      "strict",
		Width:        80,
	}
	v := bar.View()
	if !strings.Contains(v, "3") {
		t.Errorf("missing finding count in: %s", v)
	}
	if !strings.Contains(v, "2 blocking") {
		t.Errorf("missing blocking count in: %s", v)
	}
}
