package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func feedStr(s *Screen, str string) {
	s.Feed([]byte(str))
}

func trimRows(rows []string) []string {
	var out []string
	for _, r := range rows {
		out = append(out, strings.TrimRight(r, " "))
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

func TestScreenBasicText(t *testing.T) {
	s := NewScreen(6, 20)
	feedStr(s, "hello world\r\nsecond line")
	rows := trimRows(s.Rows())
	if len(rows) != 2 {
		t.Fatalf("rows=%d, want 2 content lines, got %q", len(rows), rows)
	}
	if rows[0] != "hello world" {
		t.Errorf("expected 'hello world', got %q", rows[0])
	}
	if rows[1] != "second line" {
		t.Errorf("expected 'second line', got %q", rows[1])
	}
}

func TestScreenScroll(t *testing.T) {
	s := NewScreen(3, 20)
	feedStr(s, "line_1\r\n")
	feedStr(s, "line_2\r\n")
	feedStr(s, "line_3\r\n")
	feedStr(s, "line_4\r\n")
	feedStr(s, "line_5")
	rows := trimRows(s.Rows())
	joined := strings.Join(rows, "|")
	if joined != "line_3|line_4|line_5" {
		t.Errorf("scroll window wrong: %q", joined)
	}
}

func TestScreenClearScreen(t *testing.T) {
	s := NewScreen(5, 20)
	feedStr(s, "abcdef\r\nghijkl")
	feedStr(s, "\x1b[2J")
	rows := s.Rows()
	for _, r := range rows {
		if strings.TrimSpace(r) != "" {
			t.Errorf("expected blank screen after ED 2, got %q", r)
		}
	}
}

func TestScreenCUPWrite(t *testing.T) {
	s := NewScreen(5, 20)
	feedStr(s, "hello")
	feedStr(s, "\x1b[1;1HX") // home + overwrite first char
	rows := s.Rows()
	if !strings.Contains(rows[0], "Xello") {
		t.Errorf("expected 'Xello', got %q", rows[0])
	}
}

func TestScreenSGRStripped(t *testing.T) {
	s := NewScreen(5, 30)
	feedStr(s, "\x1b[31;1mred\x1b[0m text")
	rows := trimRows(s.Rows())
	if rows[len(rows)-1] != "red text" {
		t.Errorf("SGR should be stripped, got %q", rows[len(rows)-1])
	}
}

func TestScreenHyperlinkStripped(t *testing.T) {
	s := NewScreen(5, 40)
	feedStr(s, "\x1b]8;;http://example.com\x07link\x1b]8;;\x07")
	rows := trimRows(s.Rows())
	if rows[len(rows)-1] != "link" {
		t.Errorf("OSC hyperlink should be stripped, got %q", rows[len(rows)-1])
	}
}

func TestScreenUTF8(t *testing.T) {
	s := NewScreen(5, 30)
	feedStr(s, "日本語 ok")
	rows := trimRows(s.Rows())
	if rows[len(rows)-1] != "日本語 ok" {
		t.Errorf("expected runes preserved, got %q", rows[len(rows)-1])
	}
}

func TestScreenCRLFWrap(t *testing.T) {
	s := NewScreen(4, 10)
	feedStr(s, "a\r\nb\r\nc")
	rows := trimRows(s.Rows())
	if last := rows[len(rows)-1]; last != "c" {
		t.Errorf("expected 'c' on cursor row, got %q", last)
	}
}

func TestScreenInsertDelete(t *testing.T) {
	s := NewScreen(5, 20)
	feedStr(s, "abcdef")
	feedStr(s, "\x1b[2D\x1b[P") // cursor 2 left (over 'e'), delete char
	rows := trimRows(s.Rows())
	if rows[len(rows)-1] != "abcdf" {
		t.Errorf("DCH should remove 'e', got %q", rows[len(rows)-1])
	}
}

func TestANSIWrapperTerminalAppEndsBackAtBottom(t *testing.T) {
	// A full-screen-ish sequence (vim-style redraw) must not corrupt the pane.
	s := NewScreen(10, 40)
	feedStr(s, "\x1b[?1049h\x1b[22;0;0t")
	feedStr(s, "\x1b[2J\x1b[H")
	feedStr(s, "~ line one")
	feedStr(s, "\x1b[2;1H~ line two")
	feedStr(s, "\x1b[?1049l")
	rows := trimRows(s.Rows())
	joined := strings.Join(rows, "|")
	if !strings.Contains(joined, "line one") || !strings.Contains(joined, "line two") {
		t.Errorf("expected both lines in pane, got %q", joined)
	}
}

func TestTranslateKeyMappings(t *testing.T) {
	if b, ok := translateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}}); !ok || string(b) != "a" {
		t.Errorf("plain rune forward failed: %q ok=%v", b, ok)
	}
	if _, ok := translateKey(tea.KeyMsg{Type: tea.KeyCtrlQ}); ok {
		t.Error("ctrl+q must trigger quit, not forward")
	}
	if b, _ := translateKey(tea.KeyMsg{Type: tea.KeyCtrlC}); len(b) != 1 || b[0] != 3 {
		t.Errorf("ctrl+c should map to 0x03, got %v", b)
	}
	if b, ok := translateKey(tea.KeyMsg{Type: tea.KeyUp}); !ok || string(b) != "\x1b[A" {
		t.Errorf("up arrow mapping wrong: %q ok=%v", b, ok)
	}
	if b, ok := translateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}, Alt: true}); !ok || string(b) != "\x1bk" {
		t.Errorf("alt+k mapping wrong: %q ok=%v", b, ok)
	}
}
