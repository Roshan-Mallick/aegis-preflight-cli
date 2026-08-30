package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/images"
	"golang.org/x/term"
)

const (
	// The sandbox container runs from the minimal hardened runtime image
	// (a pruned filesystem with no /home, /var, /root, /srv, /opt and with
	// unreadable /etc/passwd). The tool image aegis-agent:v1 is only the
	// source that the runtime image is derived from.
	defaultImage    = images.RuntimeImage
	containerPrefix = "aegis-agent-"
	memoryLimit     = "2g"
	cpuLimit        = "2"
	pidsLimit       = "512"
)

type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func (r ExecResult) OK() bool { return r.ExitCode == 0 }

type Sandbox struct {
	SessionID   string
	Name        string
	Workspace   string
	Image       string
	NetworkArgs []string
	AgentBin    string
	AgentConfig string
	AgentData   string
	AgentBins   map[string]string
	log         *events.Store
}

func New(sessionID, workspace string, log *events.Store) *Sandbox {
	short := sessionID
	if len(short) > 8 {
		short = short[:8]
	}
	return &Sandbox{
		SessionID: sessionID,
		Name:      containerPrefix + short,
		Workspace: workspace,
		Image:     defaultImage,
		log:       log,
	}
}

func (s *Sandbox) ContainerName() string { return s.Name }

func (s *Sandbox) SetNetworkArgs(args []string) { s.NetworkArgs = args }

func docker(ctx context.Context, args ...string) ([]byte, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return nil, fmt.Errorf("docker binary not found: %w", err)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func DockerAvailable(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := docker(ctx, "info", "--format", "{{.ServerVersion}}")
	if err != nil {
		msg := strings.ToLower(string(out) + err.Error())
		if strings.Contains(msg, "permission denied") || strings.Contains(msg, "docker.sock") {
			return fmt.Errorf("docker daemon permission denied (add user to docker group and re-login)")
		}
		return fmt.Errorf("docker daemon unreachable")
	}
	return nil
}

func EnsureAgentImage(ctx context.Context) error {
	if _, err := docker(ctx, "image", "inspect", images.AgentImage); err == nil {
		return nil
	}
	tmp, err := os.MkdirTemp("", "aegis-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := images.WriteAgentContext(tmp); err != nil {
		return err
	}
	buildCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	out, err := docker(buildCtx, "build", "-t", images.AgentImage, tmp)
	if err != nil {
		tail := string(out)
		if len(tail) > 2000 {
			tail = tail[len(tail)-2000:]
		}
		return fmt.Errorf("agent image build failed: %w\n%s", err, tail)
	}
	return nil
}

func (s *Sandbox) emit(typ, severity string, data map[string]any) {
	if s.log == nil {
		return
	}
	ev := events.New(events.SourceSandbox, typ, severity, "aegis", s.SessionID, data)
	_ = s.log.Append(ev)
}

func (s *Sandbox) Start(ctx context.Context) error {
	// The sandbox images must exist before the container is launched. This
	// is cheap when nothing changed: the runtime image carries a fingerprint
	// of the tool image it was derived from and is only rebuilt when the
	// tool image changes.
	imgCtx, imgCancel := context.WithTimeout(ctx, 12*time.Minute)
	if err := EnsureAgentImage(imgCtx); err != nil {
		imgCancel()
		return err
	}
	if err := EnsureRuntimeImage(imgCtx); err != nil {
		imgCancel()
		return err
	}
	imgCancel()

	_ = s.killStale(ctx)
	wsAbs, err := absPath(s.Workspace)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	networkArgs := []string{"--network", "none"}
	if len(s.NetworkArgs) > 0 {
		networkArgs = s.NetworkArgs
	}
	args := []string{
		"run", "-d",
		"--name", s.Name,
	}
	args = append(args, networkArgs...)
	args = append(args,
		"--user", "1000:1000",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--memory", memoryLimit,
		"--cpus", cpuLimit,
		"--pids-limit", pidsLimit,
		// Filesystem boundary. The container root is the minimal runtime
		// image (images.RuntimeImage), a pruned filesystem that contains no
		// /home, /var, /root, /srv, /opt and an unreadable /etc/passwd, so
		// /workspace/.., absolute paths, relative ".." walks and symlinks
		// can only ever resolve inside the held project or the strictly
		// minimal runtime. --read-only makes the whole runtime immutable.
		// The only writable area is the project itself: /workspace (rw
		// bind). /tmp and /run are empty private tmpfs mountpoints, and
		// /agent/cache is the exec-capable scratch space for agent
		// runtimes (see TMPDIR/HOME below). Docker mounts a tmpfs over
		// /agent/cache as root; uid/gid/mode pin it to the agent user so
		// the non-root agent can actually write there (opencode creates
		// /agent/cache/.local and /agent/cache/.config at startup).
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=100m",
		"--tmpfs", "/run:rw,nosuid,nodev,size=8m",
		"--tmpfs", "/agent/cache:rw,exec,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=0700",
		"-e", "TMPDIR=/agent/cache",
		"-e", "HOME=/agent/cache",
		"-e", "BASH_ENV=/tmp/.aegis-jailrc",
		"-w", "/workspace",
		"-v", wsAbs+":/workspace",
	)

	if s.AgentBin != "" {
		args = append(args,
			"-v", s.AgentBin+":/agent/bin/agent:ro",
		)
		libs := resolveLibs(s.AgentBin)
		for host, ctr := range libs {
			args = append(args, "-v", host+":"+ctr+":ro")
		}
	}
	// Mount additional agent binaries directly into PATH so users can
	// type "opencode", "claude", etc. inside the sandbox shell.
	for name, hostPath := range s.AgentBins {
		args = append(args,
			"-v", hostPath+":/usr/local/bin/"+name+":ro",
		)
		libs := resolveLibs(hostPath)
		for host, ctr := range libs {
			args = append(args, "-v", host+":"+ctr+":ro")
		}
	}
	if s.AgentConfig != "" {
		args = append(args,
			"-v", s.AgentConfig+":/agent/config",
		)
	}
	if s.AgentData != "" {
		args = append(args,
			"-v", s.AgentData+":/agent/data",
			"-e", "XDG_DATA_HOME=/agent/data",
			"-e", "XDG_CONFIG_HOME=/agent/config",
		)
	}

	// The imported runtime image has no CMD; sleep keeps the container
	// alive so docker exec can drive the sandbox.
	args = append(args, "--entrypoint", "/usr/bin/sleep", s.Image, "infinity")
	out, err := docker(runCtx, args...)
	if err != nil {
		s.emit("sandbox.start", events.SevHigh, map[string]any{"error": trim(out)})
		return fmt.Errorf("start container %s: %w\n%s", s.Name, err, trim(out))
	}
	s.emit("sandbox.start", events.SevInfo, map[string]any{
		"container": s.Name,
		"workspace": wsAbs,
		"network":   networkArgs[1],
		"agent_bin": s.AgentBin,
	})
	return nil
}

func (s *Sandbox) killStale(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, _ = docker(cctx, "rm", "-f", s.Name)
	return nil
}

func (s *Sandbox) Exec(ctx context.Context, command string) (ExecResult, error) {
	runCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	args := []string{"exec", "-i", "-w", "/workspace", s.Name, "sh", "-c", command}
	bin, err := exec.LookPath("docker")
	if err != nil {
		return ExecResult{}, err
	}
	cmd := exec.CommandContext(runCtx, bin, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	res := ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: 0}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			return res, fmt.Errorf("exec in %s: %w", s.Name, err)
		}
	}
	s.emit("command.exec", events.SevInfo, map[string]any{
		"container": s.Name,
		"argv":      command,
		"exit_code": res.ExitCode,
	})
	return res, nil
}

func (s *Sandbox) SetupWorkspaceJail() error {
	// The real filesystem boundary is the container mount landscape: the
	// container runs from the minimal runtime image (no /home, /var, /root,
	// /srv, /opt; unreadable /etc/passwd) and the project is the ONLY
	// writable bind mount at /workspace. Nothing outside the project is
	// reachable by absolute path, relative ".." walk or symlink, so the
	// cd() override below is defense-in-depth for shell ergonomics: it uses
	// physical path resolution (cd -P) and an exact /workspace|/workspace/*
	// boundary test, so interior navigation ("cd src; cd ..; cd ../tests")
	// works while any attempt to step above the project — cd .. at
	// /workspace, cd /, cd ~, cd ../src — is refused and the shell is put
	// back where it was.
	const setupScript = `#!/bin/sh
set -e

# ---- workspace jail rcfile ----
mkdir -p /tmp
cat > /tmp/.aegis-jailrc << 'JAILRC'
export HOME=/agent/cache
_aegis_deny() {
  printf '\033[0;31m[aegis]\033[0m access denied: leaving the project (/workspace) is not allowed\n' >&2
}
cd() {
  local prev="$PWD" t
  if [ "${1:-}" = "--" ]; then shift 2>/dev/null; fi
  if [ $# -gt 1 ]; then
    printf '%s\n' 'bash: cd: too many arguments' >&2
    return 1
  fi
  t="${1:-.}"
  if [ "$t" = "-" ]; then
    t="${OLDPWD:-.}"
  fi
  builtin cd -P -- "$t" || return 1
  case "$PWD" in
    /workspace|/workspace/*) return 0 ;;
  esac
  _aegis_deny
  builtin cd -P -- "$prev" >/dev/null 2>&1 || builtin cd -P -- /workspace >/dev/null 2>&1
  return 1
}
JAILRC
chmod 644 /tmp/.aegis-jailrc
echo "jail-ready"
`
	bin := "docker"
	if p := os.Getenv("AEGIS_DOCKER_BIN"); p != "" {
		bin = p
	}
	cmd := exec.Command(bin, "exec", s.Name, "sh", "-c", setupScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("setup workspace jail: %w: %s", err, trim(out))
	}
	s.emit("sandbox.jail", events.SevInfo, map[string]any{"workspace": s.Workspace})
	return nil
}

func (s *Sandbox) ExecInteractive(command []string) int {
	bin := "docker"
	if p := os.Getenv("AEGIS_DOCKER_BIN"); p != "" {
		bin = p
	}

	// No controlling terminal (pipeline, CI, piped stdin): run the command
	// attached but non-interactively. stdout/stderr stream through unchanged
	// and we block until the process exits — the orchestrator must never
	// observe "agent started" as "agent finished".
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		args := []string{"exec", "-i", "-w", "/workspace", s.Name}
		args = append(args, command...)
		cmd := exec.Command(bin, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		code := runExitCode(cmd)
		s.emit("agent.exec", events.SevInfo, map[string]any{
			"container": s.Name,
			"argv":      command,
			"mode":      "piped",
			"exit_code": code,
		})
		return code
	}

	args := []string{"exec", "-it", "-w", "/workspace", s.Name}
	args = append(args, command...)
	cmd := exec.Command(bin, args...)

	// Allocate a host-side PTY. docker exec -it needs a PTY on both sides:
	// the host allocates one via creack/pty, and the container gets one
	// because Docker allocates a PTY inside the container when it sees -t.
	ptmx, err := pty.Start(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start interactive session: %v\n", err)
		return 1
	}
	defer ptmx.Close()

	// Put the user's terminal into raw mode so every keystroke (including
	// Ctrl+C, arrow keys, etc.) is forwarded directly to the container's
	// PTY without host-side line editing. If raw mode cannot be enabled the
	// session still runs (cooked, line-buffered input); we never return
	// before the process exits.
	fd := int(os.Stdin.Fd())
	oldState, rawErr := term.MakeRaw(fd)
	raw := rawErr == nil
	if raw {
		defer term.Restore(fd, oldState)
	} else {
		fmt.Fprintf(os.Stderr, "interactive: continuing without raw terminal: %v\n", rawErr)
	}

	// Set the PTY size to match the user's real terminal.
	if w, h, err := term.GetSize(fd); err == nil {
		pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
	}

	// Forward terminal resize events (SIGWINCH) to the container PTY.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	defer signal.Stop(sigCh)
	go func() {
		for range sigCh {
			if w, h, err := term.GetSize(fd); err == nil {
				pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
			}
		}
	}()
	// Send initial size.
	sigCh <- syscall.SIGWINCH

	// Pipe user input → container PTY, and container output → user terminal.
	// The forward relay must not outlive the session: it stops once the
	// session ends, otherwise a corpse blocked on stdin would swallow the
	// keystrokes of a later remediation round.
	relayStop := make(chan struct{})
	relayDone := make(chan error, 1)
	go func() { relayDone <- relayStdinToPTY(fd, ptmx, relayStop) }()
	io.Copy(os.Stdout, ptmx)
	close(relayStop)
	<-relayDone

	// Restore terminal before returning.
	if raw {
		term.Restore(fd, oldState)
	}

	code := 0
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "interactive session failed: %v\n", err)
			code = 1
		}
	}
	s.emit("agent.exec", events.SevInfo, map[string]any{
		"container": s.Name,
		"argv":      command,
		"mode":      "tty",
		"exit_code": code,
	})
	return code
}

// runExitCode runs the command to completion and returns its exit code.
func runExitCode(cmd *exec.Cmd) int {
	err := cmd.Run()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "interactive exec failed: %v\n", err)
	return 1
}

func (s *Sandbox) Inspect(ctx context.Context) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := docker(cctx, "inspect", s.Name)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", s.Name, err)
	}
	return out, nil
}

func (s *Sandbox) Commit(ctx context.Context, ref string) error {
	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	out, err := docker(cctx, "commit", s.Name, ref)
	if err != nil {
		return fmt.Errorf("commit %s: %w\n%s", s.Name, err, trim(out))
	}
	s.emit("sandbox.commit", events.SevInfo, map[string]any{
		"container": s.Name,
		"image":     ref,
	})
	return nil
}

func (s *Sandbox) Kill(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := docker(cctx, "rm", "-f", s.Name)
	if err != nil && !strings.Contains(string(out), "No such container") {
		s.emit("sandbox.kill", events.SevHigh, map[string]any{"error": trim(out)})
		return fmt.Errorf("kill container %s: %w", s.Name, err)
	}
	s.emit("sandbox.kill", events.SevInfo, map[string]any{"container": s.Name})
	return nil
}

func (s *Sandbox) InjectAgentBinary(name string) error {
	// With --read-only root, symlinks in /usr/local/bin fail.  Write to
	// the workspace (bind-mounted, writable) instead.
	ln := fmt.Sprintf("mkdir -p /workspace/.aegis/bin && ln -sf /agent/bin/agent /workspace/.aegis/bin/%s", name)
	bin := "docker"
	if p := os.Getenv("AEGIS_DOCKER_BIN"); p != "" {
		bin = p
	}
	cmd := exec.Command(bin, "exec", s.Name,
		"sh", "-c", ln)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("inject agent binary %s: %w: %s", name, err, trim(out))
	}
	s.emit("sandbox.inject_agent", events.SevInfo, map[string]any{
		"agent": name,
		"path":  "/workspace/.aegis/bin/" + name,
	})
	return nil
}

func absPath(p string) (string, error) {
	return filepath.Abs(p)
}

func trim(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 800 {
		s = s[:800] + "...(truncated)"
	}
	return s
}

func resolveLibs(binaryPath string) map[string]string {
	out, err := exec.Command("ldd", binaryPath).Output()
	if err != nil {
		return nil
	}
	libs := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, "=>", 2)
		if len(parts) != 2 {
			continue
		}
		libPath := strings.TrimSpace(parts[1])
		if libPath == "not found" || !strings.HasPrefix(libPath, "/") {
			continue
		}
		if strings.Contains(libPath, "linux-vdso") {
			continue
		}
		libs[libPath] = libPath
	}
	return libs
}
