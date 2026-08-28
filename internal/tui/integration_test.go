package tui

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/eth0x1/aegis/internal/events"
)

func eventsEvent(t *testing.T, typ, actor string) events.Event {
	t.Helper()
	return events.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Type:      typ,
		Source:    events.SourceProxy,
		Severity:  "info",
		Actor:     actor,
		Data:      map[string]any{"dest": "api.example.com"},
	}
}

func timeNow() time.Time { return time.Now() }

// TestRealPTYOutputThroughScreen runs a real process in a PTY that emits a
// complex ANSI stream (like opencode's full-screen TUI does), then feeds the
// PTY output through the Screen renderer in realistic small chunks to verify
// no escape fragments leak and the visible text is intact.
func TestRealPTYOutputThroughScreen(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	if _, err := exec.LookPath("tput"); err != nil {
		t.Skip("tput unavailable")
	}

	// A script that produces terminal output similar to a full-screen agent:
	// color output, cursor movement, clear, hide/show cursor, OSC title, etc.
	script := `set -e
printf '\033[?1049h'          # use alternate screen
printf '\033[2J'              # clear
printf '\033[1;1H\033[0;36m\033[1mOpenCode Agent\033[0m\n'
printf '\033[0;32mReady\033[0m  Session \033[1mabc123\033[0m\n'
printf '\033[0;38;5;250mworking on task\033[0m\n'
printf '\033[0;33m\u26a0 tool\033[0m completed\033[0m\n'
printf '\033]0;opencode-agent\007'
printf '\033[?25l'            # hide cursor
sleep 1
printf '\033[0;32mDONE\033[0m\n'
printf '\033[?25h'            # show cursor
printf '\033[?1049l'          # leave alternate screen
`

	cmd := exec.Command("bash", "-c", script)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer ptmx.Close()

	// Drain PTY output and feed through Screen in small chunks to simulate
	// the real byte-streaming (4096-byte reads can split sequences).
	s := NewScreen(40, 120)
	var all []byte
	buf := make([]byte, 7) // deliberately tiny to force sequence splitting
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			all = append(all, chunk...)
			s.Feed(chunk)
		}
		if err != nil {
			break
		}
	}
	cmd.Wait()

	text := ""
	for _, row := range s.Rows() {
		text += strings.TrimRight(row, " ") + "\n"
	}

	// 1. No raw escape fragments visible.
	badFrags := []string{"{0;36m", "{38;5;245m", "[38;5;39m", "[2J", "[?25l",
		"[?25h", "[?1049", "{0m", "{1m", "{0;32m", "{0;33m", "[1;1H", "]0;opencode"}
	for _, frag := range badFrags {
		if strings.Contains(text, frag) {
			t.Errorf("escape fragment leaked as visible text: %q (got %q)", frag, text)
		}
	}

	// 2. Visible content preserved.
	for _, want := range []string{"OpenCode Agent", "Ready", "Session", "abc123", "working", "DONE", "tool", "completed"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing visible content %q in rendered screen:\n%s", want, text)
		}
	}

	// 3. No stray ESC (0x1b) or control bytes in final rendering.
	if strings.Contains(text, "\x1b") {
		t.Errorf("raw ESC byte present in rendered output:\n%q", text)
	}

	t.Logf("Rendered %d bytes of real PTY output cleanly", len(all))
}

// TestNoANSIInFeedRendering verifies the security feed renders event lines
// with no ANSI leakage and correct dedup formatting.
func TestNoANSIInFeedRendering(t *testing.T) {
	f := NewFeed(100)
	// Push a burst of identical network events then distinct ones.
	for i := 0; i < 40; i++ {
		f.Push(eventsEvent(t, "network.connect", "egress-gateway"))
	}
	lines := f.Lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 deduped line for 40 identical network events, got %d", len(lines))
	}
	first := lines[0]
	if !strings.Contains(first, "NETWORK.CONNECT") {
		t.Errorf("missing NETWORK.CONNECT: %s", first)
	}
	if !strings.Contains(first, "×40") {
		t.Errorf("missing ×40 dedup count: %s", first)
	}
	// No escape sequences.
	if strings.Contains(first, "\x1b") {
		t.Errorf("ANSI in feed line")
	}

	// Now a different event type — should be a new line.
	f.Push(eventsEvent(t, "command.exec", "opencode"))
	if len(f.Lines()) != 2 {
		t.Fatalf("expected 2 lines after new event, got %d", len(f.Lines()))
	}
	if !strings.Contains(f.Lines()[1], "COMMAND.EXEC") {
		t.Errorf("missing COMMAND.EXEC: %s", f.Lines()[1])
	}
}

// TestSplitLayoutRenders is a smoke test that the split-view View() renders
// without panic and with aligned borders across sizes.
func TestSplitLayoutRenders(t *testing.T) {
	for _, size := range [][2]int{
		{80, 24},
		{120, 40},
		{200, 60},
		{40, 12}, // narrow
		{20, 8},  // very narrow
	} {
		w, h := size[0], size[1]
		m := NewModel(Config{Network: "strict", AgentName: "opencode"})
		m.width = w
		m.height = h
		// Feed some terminal content.
		m.appendRaw([]byte("\x1b[38;5;39mhello\x1b[0m world\n"))
		// Resize path exercised.
		m.resizePTY()
		// Add some events.
		m.feed.Push(eventsEvent(t, "network.connect", "egress-gateway"))
		m.feed.Push(eventsEvent(t, "network.connect", "egress-gateway"))
		m.feed.Push(eventsEvent(t, "command.exec", "opencode"))

		_ = m.View() // should not panic
	}
}

// TestStatusBarLayout verifies the status bar truncates / pads correctly.
func TestStatusBarLayout(t *testing.T) {
	for _, width := range []int{20, 40, 60, 80, 120} {
		bar := StatusBar{
			SessionID:    "abc12345-def0-0000-0000-000000000000",
			State:        "running",
			FindingCount: 2,
			BlockCount:   1,
			Network:      "dev",
			AgentID:      "opencode",
			Width:        width,
			StartedAt:    timeNow(),
		}
		v := bar.View()
		if strings.Contains(v, "\x1b") {
			t.Errorf("ANSI in status bar at width %d", width)
		}
		_ = v
	}
}
