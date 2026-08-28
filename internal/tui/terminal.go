package tui

import (
	"strings"
	"unicode/utf8"
)

// runeWidth reports the display width of a rune (2 for wide CJK, 1 otherwise).
func runeWidth(r rune) int {
	if r >= 0x1100 && (r <= 0x115f ||
		r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		(r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe10 && r <= 0xfe19) ||
		(r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1f64f) ||
		(r >= 0x1f900 && r <= 0x1f9ff) ||
		(r >= 0x20000 && r <= 0x2fffd) ||
		(r >= 0x30000 && r <= 0x3fffd)) {
		return 2
	}
	return 1
}

// Screen is a minimal VT100/ANSI renderer. It maintains a fixed-size cell
// buffer, tracks the cursor, understands cursor movement, clear, insert/delete
// and scroll operations, and ignores SGR styling (the pane renders plain text).
// It deliberately does not emulate the full terminal — escape sequences it does
// not recognise are safely discarded. Incomplete escape sequences that span
// multiple Feed calls are buffered and reassembled.
type Screen struct {
	rows, cols int
	cells      [][]rune
	curRow     int
	curCol     int
	scrollTop  int
	scrollAmt  int
	savedRow   int
	savedCol   int
	didCR      bool
	// escBuf holds bytes from an incomplete escape sequence that was split
	// across a chunk boundary. Prepended to the next Feed call.
	escBuf []byte
}

func NewScreen(rows, cols int) *Screen {
	if rows < 1 {
		rows = 1
	}
	if cols < 1 {
		cols = 1
	}
	screen := &Screen{
		rows:      rows,
		cols:      cols,
		scrollTop: 0,
	}
	screen.grow(rows)
	return screen
}

func (s *Screen) grow(n int) {
	for i := 0; i < n; i++ {
		s.cells = append(s.cells, make([]rune, s.cols))
	}
}

// visibleHeight is the number of buffer rows presented at once.
func (s *Screen) visibleHeight() int {
	return s.rows
}

// scroll shifts the whole buffer up by n rows, clearing the bottom and
// leaving the cursor on the last visible row (a real terminal's scroll).
func (s *Screen) scroll(n int) {
	if n <= 0 {
		return
	}
	if len(s.cells) > s.rows {
		copy(s.cells, s.cells[n:])
		s.grow(n)
	} else {
		copy(s.cells, s.cells[n:])
		for i := 0; i < n; i++ {
			s.cells[s.rows-1-i] = make([]rune, s.cols)
		}
	}
	s.curRow = s.rows - 1
}

// lineFeed advances (and scrolls) like a real terminal.
func (s *Screen) lineFeed() {
	if s.curRow+1 >= s.rows {
		s.scroll(1)
		return
	}
	s.curRow++
	s.didCR = false
}

func (s *Screen) clearLine(from, to int) {
	from = max(from, 0)
	if to > s.cols {
		to = s.cols
	}
	for c := from; c < to; c++ {
		s.cells[s.curRow][c] = 0
	}
}

func (s *Screen) clearScreen(fromRow int) {
	for r := fromRow; r < s.rows; r++ {
		s.cells[r] = make([]rune, s.cols)
	}
}

func (s *Screen) putRune(r rune) {
	if s.curCol >= s.cols {
		s.curCol = 0
		if s.curRow+1 >= s.rows {
			s.scroll(1)
		} else {
			s.curRow++
		}
	}
	s.cells[s.curRow][s.curCol] = r
	s.curCol++
}

// Feed consumes output bytes from the PTY and updates the screen. It
// reasplies escape sequences that span chunk boundaries.
func (s *Screen) Feed(data []byte) {
	// Prepend any leftover bytes from an incomplete escape sequence.
	if len(s.escBuf) > 0 {
		combined := make([]byte, 0, len(s.escBuf)+len(data))
		combined = append(combined, s.escBuf...)
		combined = append(combined, data...)
		data = combined
		s.escBuf = s.escBuf[:0]
	}

	i := 0
	for i < len(data) {
		b := data[i]
		switch {
		case b == 0x1b:
			s.didCR = false
			consumed, complete := s.feedEscape(data, &i)
			if !complete {
				// Incomplete escape sequence — buffer from ESC onward
				// and wait for the next chunk.
				if i < len(data) {
					s.escBuf = append(s.escBuf[:0], data[i:]...)
				}
				return
			}
			if !consumed {
				// Unhandled escape — discard the ESC byte.
				i++
			}
		case b == '\r':
			s.curCol = 0
			s.didCR = true
			i++
		case b == '\n':
			s.lineFeed()
			i++
		case b == '\b':
			if s.curCol > 0 {
				s.curCol--
			}
			i++
		case b == '\t':
			s.didCR = false
			next := (s.curCol/8 + 1) * 8
			if next > s.cols {
				next = s.cols
			}
			s.curCol = next
			i++
		case b < 0x20:
			i++ // other control chars: ignore
		default:
			r, sz := utf8.DecodeRune(data[i:])
			if r == utf8.RuneError && sz == 1 {
				i++
				continue
			}
			s.didCR = false
			s.putRune(r)
			i += sz
		}
	}
}

// feedEscape handles ESC-led sequences. Returns (consumed, complete):
//   - consumed=true, complete=true: sequence fully parsed, index advanced
//   - consumed=false, complete=true: ESC byte should be discarded
//   - complete=false: sequence is incomplete (buffered by caller)
func (s *Screen) feedEscape(data []byte, i *int) (bool, bool) {
	escIdx := *i
	rest := data[escIdx+1:]
	if len(rest) == 0 {
		// Lone ESC at end of buffer — could be the start of a multi-byte
		// escape sequence in the next chunk. Buffer it (return incomplete).
		return true, false
	}
	switch rest[0] {
	case '[':
		n, complete := s.feedCSI(rest)
		if !complete {
			return true, false
		}
		*i = escIdx + 1 + n
		return true, true
	case ']':
		n, complete := s.feedOSC(rest)
		if !complete {
			return true, false
		}
		*i = escIdx + 1 + n
		return true, true
	case 'c':
		*i = escIdx + 2
		s.reset()
		return true, true
	case '7':
		*i = escIdx + 2
		s.savedRow, s.savedCol = s.curRow, s.curCol
		return true, true
	case '8':
		*i = escIdx + 2
		s.curRow, s.curCol = s.savedRow, s.savedCol
		return true, true
	case '(', ')', '*', '+': // character set designation (ESC ( 0, ESC ( B, etc.)
		if len(rest) < 2 {
			return true, false
		}
		*i = escIdx + 3
		return true, true
	default:
		*i = escIdx + 2
		return true, true
	}
}

// feedCSI consumes from the '[' and returns (bytesConsumed, complete).
// complete=false means the sequence ran off the end of the buffer — the
// caller should buffer these bytes for the next Feed call.
func (s *Screen) feedCSI(rest []byte) (int, bool) {
	pos := 1
	params := []int{}
	n := 0
	haveNum := false
	for pos < len(rest) {
		c := rest[pos]
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
			haveNum = true
			pos++
			continue
		}
		if c == ';' {
			if !haveNum {
				n = 0
			}
			params = append(params, n)
			n = 0
			haveNum = false
			pos++
			continue
		}
		if csiFinalByte(c) {
			if !haveNum {
				n = 0
			}
			params = append(params, n)
			s.execCSI(c, params)
			return pos + 1, true
		}
		pos++
	}
	return len(rest), false
}

// csiFinalByte reports whether b is a valid CSI final byte (0x40-0x7e).
func csiFinalByte(b byte) bool {
	return b >= 0x40 && b <= 0x7e
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func pget(params []int, idx, def int) int {
	if idx < len(params) && params[idx] != 0 {
		return params[idx]
	}
	return def
}

// execCSI dispatches a fully-parsed CSI sequence.
func (s *Screen) execCSI(final byte, params []int) {
	switch final {
	case 'A': // CUU
		s.curRow = clamp(s.curRow-pget(params, 0, 1), 0, s.rows-1)
	case 'B': // CUD
		s.curRow = clamp(s.curRow+pget(params, 0, 1), 0, s.rows-1)
	case 'C': // CUF
		s.curCol = clamp(s.curCol+pget(params, 0, 1), 0, s.cols-1)
	case 'D': // CUB
		s.curCol = clamp(s.curCol-pget(params, 0, 1), 0, s.cols-1)
	case 'E': // CNL
		s.curRow = clamp(s.curRow+pget(params, 0, 1), 0, s.rows-1)
		s.curCol = 0
	case 'F': // CPL
		s.curRow = clamp(s.curRow-pget(params, 0, 1), 0, s.rows-1)
		s.curCol = 0
	case 'G': // CHA
		s.curCol = clamp(pget(params, 0, 1)-1, 0, s.cols-1)
	case 'H', 'f': // CUP / HVP
		s.curRow = clamp(pget(params, 0, 1)-1, 0, s.rows-1)
		s.curCol = clamp(pget(params, 1, 1)-1, 0, s.cols-1)
	case 'J': // ED
		switch pget(params, 0, 0) {
		case 2, 3:
			s.clearScreen(0)
			s.curRow, s.curCol = 0, 0
		case 1:
			for r := 0; r <= s.curRow; r++ {
				s.cells[r] = make([]rune, s.cols)
			}
		default:
			s.clearScreen(s.curRow + 1)
		}
	case 'K': // EL
		switch pget(params, 0, 0) {
		case 1:
			s.clearLine(0, s.curCol+1)
		case 2:
			s.clearLine(0, s.cols)
		default:
			s.clearLine(s.curCol, s.cols)
		}
	case '@': // ICH
		n := clamp(pget(params, 0, 1), 1, s.cols-s.curCol)
		row := s.cells[s.curRow]
		copy(row[s.curCol+n:], row[s.curCol:])
		for c := s.curCol; c < s.curCol+n; c++ {
			row[c] = 0
		}
	case 'P': // DCH
		n := clamp(pget(params, 0, 1), 1, s.cols-s.curCol)
		row := s.cells[s.curRow]
		copy(row[s.curCol:], row[s.curCol+n:])
		for c := s.cols - n; c < s.cols; c++ {
			row[c] = 0
		}
	case 'L': // IL
		n := clamp(pget(params, 0, 1), 1, s.rows-s.curRow)
		for r := s.rows - 1; r >= s.curRow+n; r-- {
			s.cells[r] = s.cells[r-n]
		}
		for r := s.curRow; r < s.curRow+n; r++ {
			s.cells[r] = make([]rune, s.cols)
		}
	case 'M': // DL
		n := clamp(pget(params, 0, 1), 1, s.rows-s.curRow)
		for r := s.curRow; r+n < s.rows; r++ {
			s.cells[r] = s.cells[r+n]
		}
		for r := s.rows - n; r < s.rows; r++ {
			s.cells[r] = make([]rune, s.cols)
		}
	case 'S': // SU
		s.scroll(clamp(pget(params, 0, 1), 1, s.rows))
	case 'T': // SD
		n := clamp(pget(params, 0, 1), 1, s.rows)
		copy(s.cells[n:], s.cells)
		for r := 0; r < n; r++ {
			s.cells[r] = make([]rune, s.cols)
		}
	case 'm', 's', 'u', 'h', 'l': // SGR / save / restore / mode: ignored
	default:
	}
}

// feedOSC parses OSC (ESC ] ... BEL or ESC \) and discards it, returning
// (bytesConsumed, complete). complete=false means the terminator was not
// found before the buffer ended.
func (s *Screen) feedOSC(rest []byte) (int, bool) {
	for i := 1; i < len(rest); i++ {
		if rest[i] == 0x07 {
			return i + 1, true
		}
		if rest[i] == 0x1b && i+1 < len(rest) && rest[i+1] == '\\' {
			return i + 2, true
		}
	}
	return len(rest), false
}

func (s *Screen) reset() {
	s.cells = s.cells[:0]
	s.grow(s.rows)
	s.curRow, s.curCol = 0, 0
	s.escBuf = s.escBuf[:0]
}

// Rows renders the visible window as strings (oldest first), each exactly
// cols wide, with wide runes left in place.
func (s *Screen) Rows() []string {
	start := 0
	if len(s.cells) > s.rows {
		start = len(s.cells) - s.rows
	}
	out := make([]string, 0, s.rows)
	for r := start; r < len(s.cells); r++ {
		var b strings.Builder
		b.Grow(s.cols)
		for c := 0; c < s.cols; c++ {
			ch := s.cells[r][c]
			if ch == 0 {
				b.WriteRune(' ')
			} else {
				b.WriteRune(ch)
			}
		}
		out = append(out, b.String())
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
