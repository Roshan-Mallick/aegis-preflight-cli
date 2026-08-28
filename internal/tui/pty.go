package tui

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
)

// PTYSession runs a command inside the container attached to a real PTY so
// the embedded program sees a terminal (colours, line editing, full-screen
// apps) exactly like the passthrough mode. Output is streamed as raw bytes on
// the channel returned by Start; keystrokes are forwarded through Write and
// the terminal size is kept in sync through SetSize.
type PTYSession struct {
	container string
	ptmx      *os.File
	cmd       *exec.Cmd
	resultCh  chan ptyResult
	out       chan []byte
}

type ptyResult struct {
	code int
	err  error
}

func NewPTYSession(container string) *PTYSession {
	return &PTYSession{container: container}
}

// Start allocates the PTY pair, launches `docker exec -it -w /workspace
// <container> <command...>` and returns a stream of raw output bytes. The
// stream is closed when the command exits.
func (p *PTYSession) Start(command []string) (<-chan []byte, error) {
	bin := "docker"
	if v := os.Getenv("AEGIS_DOCKER_BIN"); v != "" {
		bin = v
	}
	args := []string{"exec", "-it", "-w", "/workspace", p.container}
	args = append(args, command...)
	cmd := exec.Command(bin, args...)

	ptmx, slave, err := pty.Open()
	if err != nil {
		return nil, fmt.Errorf("open pty: %w", err)
	}
	if err := pty.Setsize(ptmx, &pty.Winsize{Rows: 32, Cols: 120}); err != nil {
		slave.Close()
		ptmx.Close()
		return nil, fmt.Errorf("set initial pty size: %w", err)
	}
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}

	if err := cmd.Start(); err != nil {
		slave.Close()
		ptmx.Close()
		return nil, fmt.Errorf("start pty command: %w", err)
	}
	// The child inherited the slave; the parent must release it so EOF
	// propagates when the command exits.
	slave.Close()

	p.ptmx = ptmx
	p.cmd = cmd
	p.resultCh = make(chan ptyResult, 1)

	out := make(chan []byte, 64)
	p.out = out
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				out <- chunk
			}
			if err != nil {
				break
			}
		}
		close(out)
	}()
	go func() {
		err := cmd.Wait()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		p.resultCh <- ptyResult{code: code, err: err}
	}()
	return out, nil
}

// Result returns the exit code (and wait error) after the command exits.
// It blocks until the PTY command terminates.
func (p *PTYSession) Result() (int, error) {
	if p.resultCh == nil {
		return -1, fmt.Errorf("pty not started")
	}
	r := <-p.resultCh
	return r.code, r.err
}

// Write forwards translated keystrokes into the PTY.
func (p *PTYSession) Write(data []byte) error {
	if p.ptmx == nil {
		return fmt.Errorf("pty not started")
	}
	_, err := p.ptmx.Write(data)
	return err
}

// SetSize propagates a window size change to the container.
func (p *PTYSession) SetSize(rows, cols uint16) error {
	if p.ptmx == nil {
		return nil
	}
	return pty.Setsize(p.ptmx, &pty.Winsize{Rows: rows, Cols: cols})
}

// Close kills the command and releases the master.
func (p *PTYSession) Close() error {
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
	}
	if p.ptmx != nil {
		return p.ptmx.Close()
	}
	return nil
}
