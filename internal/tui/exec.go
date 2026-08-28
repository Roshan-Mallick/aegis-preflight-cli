package tui

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

type ExecSession struct {
	ContainerID string
	Bin         string
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	mu          sync.Mutex
	running     bool
	err         error
	exitCode    int
}

type ExecOutput struct {
	Line  string
	IsErr bool
	Time  time.Time
}

func NewExecSession(containerID string) *ExecSession {
	bin := "docker"
	if p := os.Getenv("AEGIS_DOCKER_BIN"); p != "" {
		bin = p
	}
	return &ExecSession{
		ContainerID: containerID,
		Bin:         bin,
	}
}

func (e *ExecSession) RunCommand(command []string, outCh chan<- ExecOutput) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return fmt.Errorf("session already running")
	}
	args := []string{"exec", "-i", e.ContainerID}
	args = append(args, command...)
	e.cmd = exec.Command(e.Bin, args...)
	return e.start(outCh)
}

func (e *ExecSession) StartInteractive(shell string, outCh chan<- ExecOutput) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return fmt.Errorf("session already running")
	}
	if shell == "" {
		shell = "bash"
	}
	args := []string{"exec", "-i", e.ContainerID, shell}
	e.cmd = exec.Command(e.Bin, args...)
	return e.start(outCh)
}

func (e *ExecSession) start(outCh chan<- ExecOutput) error {
	stdout, err := e.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := e.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	stdin, err := e.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	e.stdin = stdin
	if err := e.cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	e.running = true
	go e.stream(stdout, false, outCh)
	go e.stream(stderr, true, outCh)
	go func() {
		err := e.cmd.Wait()
		e.mu.Lock()
		e.running = false
		e.err = err
		if exitErr, ok := err.(*exec.ExitError); ok {
			e.exitCode = exitErr.ExitCode()
		}
		e.mu.Unlock()
	}()
	return nil
}

func (e *ExecSession) stream(r io.Reader, isErr bool, outCh chan<- ExecOutput) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			outCh <- ExecOutput{
				Line:  string(buf[:n]),
				IsErr: isErr,
				Time:  time.Now(),
			}
		}
		if err != nil {
			return
		}
	}
}

func (e *ExecSession) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running || e.stdin == nil {
		return 0, fmt.Errorf("session not running")
	}
	return e.stdin.Write(p)
}

func (e *ExecSession) SendLine(line string) error {
	_, err := e.Write([]byte(line + "\n"))
	return err
}

func (e *ExecSession) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

func (e *ExecSession) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

func (e *ExecSession) ExitCode() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.exitCode
}

func (e *ExecSession) Kill() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running || e.cmd == nil {
		return nil
	}
	return e.cmd.Process.Kill()
}
