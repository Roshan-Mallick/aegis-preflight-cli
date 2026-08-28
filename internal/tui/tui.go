package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/observer"
	"github.com/eth0x1/aegis/internal/session"
)

var (
	ptyBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62")).Padding(0, 1)
	ptyTitle = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("62")).Bold(true).Padding(0, 1)
	helpLine = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	quitHint = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	sepHint  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

// Config configures the split-view TUI.
type Config struct {
	Session    *session.Manager
	Feed       *observer.Feed
	PTYSession *PTYSession
	PTYOut     <-chan []byte
	Network    string
	AgentName  string
	// ExitCode is written back when the PTY session ends.
	ExitCode int
}

// Model is the split-view bubbletea model: interactive PTY pane on the left
// (real terminal embedded), live security feed on the right, status bar on the
// bottom. Every key is forwarded to the PTY except Ctrl+Q (quit); Ctrl+C goes
// to the shell.
type Model struct {
	session      *session.Manager
	feed         *Feed
	feedSub      <-chan events.Event
	pty          *PTYSession
	ptyOut       <-chan []byte
	screen       *Screen
	raw          []byte
	rawMax       int
	network      string
	agentName    string
	state        string
	width        int
	height       int
	findingCount int
	blockCount   int
	lastEventIdx int
	startedAt    time.Time
	exited       bool
	exitCode     int
	ptyErr       error
	quitting     bool
}

const rawBufferMax = 256 * 1024

func NewModel(cfg Config) Model {
	net := cfg.Network
	if net == "" {
		net = "strict"
	}
	m := Model{
		session:   cfg.Session,
		feed:      NewFeed(400),
		pty:       cfg.PTYSession,
		ptyOut:    cfg.PTYOut,
		network:   net,
		agentName: cfg.AgentName,
		state:     "running",
		rawMax:    rawBufferMax,
		startedAt: time.Now(),
		exitCode:  -1,
	}
	m.screen = NewScreen(32, 120)
	if cfg.Feed != nil {
		m.feedSub = cfg.Feed.Subscribe()
	}
	return m
}

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{}
	if m.ptyOut != nil {
		cmds = append(cmds, m.readPTY())
	}
	if m.feedSub != nil {
		cmds = append(cmds, m.waitSecurityEvent())
	}
	if len(cmds) == 0 {
		return nil
	}
	return tea.Batch(cmds...)
}

type ptyBytesMsg struct{ data []byte }
type ptyExitedMsg struct{}
type securityEventMsg struct{ event events.Event }

func (m Model) readPTY() tea.Cmd {
	return func() tea.Msg {
		data, ok := <-m.ptyOut
		if !ok {
			return ptyExitedMsg{}
		}
		return ptyBytesMsg{data: data}
	}
}

func (m Model) waitSecurityEvent() tea.Cmd {
	return func() tea.Msg {
		evt, ok := <-m.feedSub
		if !ok {
			return nil
		}
		return securityEventMsg{event: evt}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizePTY()
		return m, nil

	case ptyBytesMsg:
		m.appendRaw(msg.data)
		return m, m.readPTY()

	case ptyExitedMsg:
		m.exited = true
		m.ptyErr = nil
		return m, nil

	case securityEventMsg:
		if m.quitting {
			return m, nil
		}
		m.feed.Push(msg.event)
		m.countEvent(msg.event)
		return m, m.waitSecurityEvent()

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) countEvent(evt events.Event) {
	if evt.Type == events.TypeFinding {
		m.findingCount++
		if block, _ := evt.Data["blocking"].(bool); block {
			m.blockCount++
		} else if strings.EqualFold(evt.Severity, "critical") {
			m.blockCount++
		}
	}
}

func (m *Model) appendRaw(data []byte) {
	m.raw = append(m.raw, data...)
	if len(m.raw) > m.rawMax {
		m.raw = m.raw[len(m.raw)-m.rawMax:]
	}
	m.screen.Feed(data)
}

func (m *Model) resizePTY() {
	if m.height <= 0 || m.width <= 0 {
		return
	}
	contentH := m.height - 1 // status bar
	ptyCols := m.width * 3 / 5
	if ptyCols < 20 {
		ptyCols = m.width
	}
	cols := ptyCols - 4
	rows := contentH - 3
	if cols < 1 {
		cols = 1
	}
	if rows < 1 {
		rows = 1
	}
	m.screen = NewScreen(rows, cols)
	m.screen.Feed(m.raw)
	if m.pty != nil {
		m.pty.SetSize(uint16(rows), uint16(cols))
	}
}

// translateKey converts a bubbletea key press into the raw bytes a shell
// expects. Ctrl+Q is reserved (returns ok=false to quit); everything else is
// forwarded so line editing and shortcuts keep working in the sandbox.
func translateKey(msg tea.KeyMsg) ([]byte, bool) {
	var esc = []byte{0x1b}

	switch msg.Type {
	case tea.KeyCtrlQ:
		return nil, false
	case tea.KeyCtrlC:
		return []byte{0x03}, true
	case tea.KeyCtrlD:
		return []byte{0x04}, true
	case tea.KeyCtrlZ:
		return []byte{0x1a}, true
	case tea.KeyCtrlL:
		return []byte{0x0c}, true
	case tea.KeyEnter:
		return []byte{'\r'}, true
	case tea.KeyTab:
		return []byte{'\t'}, true
	case tea.KeyShiftTab:
		return append(esc, []byte("[Z")...), true
	case tea.KeyEsc:
		return esc, true
	case tea.KeyBackspace:
		return []byte{0x7f}, true
	case tea.KeyDelete:
		return append(esc, []byte("[3~")...), true
	case tea.KeyPgUp:
		return append(esc, []byte("[5~")...), true
	case tea.KeyPgDown:
		return append(esc, []byte("[6~")...), true
	case tea.KeyHome:
		return append(esc, []byte("[H")...), true
	case tea.KeyEnd:
		return append(esc, []byte("[F")...), true
	case tea.KeyUp:
		return append(esc, []byte("[A")...), true
	case tea.KeyDown:
		return append(esc, []byte("[B")...), true
	case tea.KeyRight:
		return append(esc, []byte("[C")...), true
	case tea.KeyLeft:
		return append(esc, []byte("[D")...), true
	case tea.KeyF1:
		return append(esc, []byte("OP")...), true
	case tea.KeyF2:
		return append(esc, []byte("OQ")...), true
	case tea.KeyF3:
		return append(esc, []byte("OR")...), true
	case tea.KeyF4:
		return append(esc, []byte("OS")...), true
	case tea.KeyF5:
		return append(esc, []byte("[15~")...), true
	case tea.KeyF6:
		return append(esc, []byte("[17~")...), true
	case tea.KeyF7:
		return append(esc, []byte("[18~")...), true
	case tea.KeyF8:
		return append(esc, []byte("[19~")...), true
	case tea.KeyF9:
		return append(esc, []byte("[20~")...), true
	case tea.KeyF10:
		return append(esc, []byte("[21~")...), true
	case tea.KeyF11:
		return append(esc, []byte("[23~")...), true
	case tea.KeyF12:
		return append(esc, []byte("[24~")...), true
	case tea.KeySpace:
		return []byte{' '}, true
	}

	if msg.Type == tea.KeyRunes && len(msg.Runes) > 0 {
		b := []byte(string(msg.Runes))
		if msg.Alt {
			return append(esc, b...), true
		}
		return b, true
	}

	// Ctrl with a letter that arrived as runes.
	if len(msg.Runes) == 1 {
		r := msg.Runes[0]
		if r >= 'a' && r <= 'z' {
			return []byte{byte(r - 'a' + 1)}, true
		}
	}
	return nil, true // drop unknown
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Give the quit hint primacy once the command has exited.
	if m.exited {
		if msg.Type == tea.KeyCtrlQ || msg.Type == tea.KeyEnter ||
			msg.Type == tea.KeyCtrlC || msg.Type == tea.KeyRunes {
			m.quitting = true
			if m.pty != nil {
				m.pty.Close()
			}
			return m, tea.Quit
		}
		return m, nil
	}
	raw, forward := translateKey(msg)
	if !forward {
		m.quitting = true
		if m.pty != nil {
			m.pty.Close()
		}
		return m, tea.Quit
	}
	if m.pty != nil {
		m.pty.Write(raw)
	}
	return m, nil
}

func (m Model) View() string {
	// status bar
	var snap session.Metadata
	if m.session != nil {
		snap = m.session.Snapshot()
	}
	var state string
	if m.exited {
		state = "exited"
	} else {
		state = string(snap.State)
		if m.state == "running" {
			state = "running"
		}
	}
	if state == "" {
		state = m.state
	}
	bar := StatusBar{
		SessionID:    snap.SessionID,
		State:        state,
		StartedAt:    m.startedAt,
		FindingCount: m.findingCount,
		BlockCount:   m.blockCount,
		Network:      m.network,
		AgentID:      m.agentName,
		Width:        m.width,
	}.View()

	contentH := m.height - 1
	if contentH < 4 {
		contentH = 4
	}
	ptyCols := m.width * 3 / 5
	if ptyCols < 20 {
		ptyCols = m.width
	}
	feedWidth := m.width - ptyCols

	title := " Agent PTY "
	if m.agentName != "" {
		title = " " + m.agentName + " PTY "
	}
	ptyContent := strings.Join(m.screen.Rows(), "\n")
	if m.exited {
		ptyContent += "\n" + quitHint.Render(fmt.Sprintf("--- command exited (code %d) ---", m.exitCodeErr()))
	}
	ptyView := ptyBox.Width(ptyCols - 2).Height(contentH - 2).
		Render(ptyTitle.Render(title) + "\n" + ptyContent)

	feedView := m.feed.View(feedWidth, contentH-2)

	top := lipgloss.JoinHorizontal(lipgloss.Top, ptyView, feedView)
	hint := helpLine.Render("ctrl+q: quit") +
		sepHint.Render(" · ") +
		helpLine.Render("ctrl+c: shell") +
		sepHint.Render(" · ") +
		helpLine.Render("exit: leave sandbox")
	return lipgloss.JoinVertical(lipgloss.Left, top, bar, hint)
}

// exitCodeErr resolves the reported code for the status/quit banner.
func (m Model) exitCodeErr() int {
	return m.exitCode
}
