package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

type fixtures struct {
	Compliant           []json.RawMessage `json:"compliant"`
	DockerSocketMounted []json.RawMessage `json:"docker_socket_mounted"`
	BridgeNetworkRoot   []json.RawMessage `json:"bridge_network_root"`
	ExtraHostMount      []json.RawMessage `json:"extra_host_mount"`
	MissingWorkspace    []json.RawMessage `json:"missing_workspace"`
	Docker29Flat        []json.RawMessage `json:"docker29_flat"`
}

func loadFixtures(t *testing.T) fixtures {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "inspect_fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f fixtures
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func wrapArray(t *testing.T, single json.RawMessage) []byte {
	t.Helper()
	b, err := json.Marshal([]json.RawMessage{single})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyIsolationAcceptsCompliantContainer(t *testing.T) {
	f := loadFixtures(t)
	violations := VerifyIsolation(wrapArray(t, f.Compliant[0]), "/home/user/.local/state/aegis/sessions/x/workspace")
	if len(violations) != 0 {
		t.Fatalf("compliant container flagged: %v", violations)
	}
}

func TestVerifyIsolationDetectsDockerSocket(t *testing.T) {
	f := loadFixtures(t)
	violations := VerifyIsolation(wrapArray(t, f.DockerSocketMounted[0]), "/tmp/ws")
	joined := strings.Join(violations, "; ")
	if !strings.Contains(joined, "docker socket") {
		t.Fatalf("docker socket mount not detected: %v", violations)
	}
}

func TestVerifyIsolationDetectsNetworkAndRoot(t *testing.T) {
	f := loadFixtures(t)
	violations := VerifyIsolation(wrapArray(t, f.BridgeNetworkRoot[0]), "/tmp/ws")
	joined := strings.Join(violations, "; ")
	for _, want := range []string{"network mode is bridge", "capabilities not dropped", "runs as root", "pids-limit"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing violation %q in: %v", want, violations)
		}
	}
}

func TestVerifyIsolationDetectsExtraHostMount(t *testing.T) {
	f := loadFixtures(t)
	violations := VerifyIsolation(wrapArray(t, f.ExtraHostMount[0]), "/tmp/ws")
	joined := strings.Join(violations, "; ")
	if !strings.Contains(joined, ".ssh") || !strings.Contains(joined, "unexpected bind mount") {
		t.Fatalf("host .ssh mount not detected: %v", violations)
	}
}

func TestVerifyIsolationAcceptsDocker29FlatShape(t *testing.T) {
	f := loadFixtures(t)
	violations := VerifyIsolation(wrapArray(t, f.Docker29Flat[0]), "/tmp/ws")
	if len(violations) != 0 {
		t.Fatalf("docker-29 flat container flagged: %v", violations)
	}
}

func TestVerifyIsolationDetectsMissingWorkspace(t *testing.T) {
	f := loadFixtures(t)
	violations := VerifyIsolation(wrapArray(t, f.MissingWorkspace[0]), "/tmp/ws")
	joined := strings.Join(violations, "; ")
	if !strings.Contains(joined, "missing required /workspace mount") {
		t.Fatalf("missing workspace not detected: %v", violations)
	}
}

func TestParseInspectRejectsGarbageAndMulti(t *testing.T) {
	if _, err := ParseInspect([]byte(`not json`)); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := ParseInspect([]byte(`[]`)); err == nil {
		t.Fatal("zero containers accepted")
	}
}

func requireDocker(t *testing.T) {
	t.Helper()
	if err := DockerAvailable(10 * time.Second); err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
}

func TestIntegrationAgentImageExistsOrBuilds(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := EnsureAgentImage(ctx); err != nil {
		t.Fatalf("EnsureAgentImage: %v", err)
	}
}

func TestIntegrationContainerIsolationLive(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := EnsureAgentImage(ctx); err != nil {
		t.Fatalf("image: %v", err)
	}

	trusted := t.TempDir()
	os.WriteFile(filepath.Join(trusted, "secret-host-only.txt"), []byte("TOPSECRET"), 0o600)
	ws := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(ws, "hello.txt"), []byte("from host"), 0o644)

	sb := New("12345678-aaaa-bbbb-cccc-dddddddddddd", ws, nil)
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sb.Kill(context.Background())

	raw, err := sb.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if violations := VerifyIsolation(raw, ws); len(violations) > 0 {
		t.Fatalf("live container violates isolation: %v", violations)
	}

	leakProbes := []struct {
		name string
		cmd  string
	}{
		{"no host ssh key", "test -e /home/user/.ssh/id_rsa && echo LEAK"},
		{"no docker socket", "test -S /var/run/docker.sock && echo LEAK"},
		{"no aws dir", "test -d /home/user/.aws && echo LEAK"},
		{"trusted project invisible", "test -e /trusted/secret-host-only.txt && echo LEAK"},
	}
	for _, tc := range leakProbes {
		res, err := sb.Exec(ctx, tc.cmd+"; true")
		if err != nil {
			t.Fatalf("%s: exec error: %v", tc.name, err)
		}
		if strings.Contains(res.Stdout, "LEAK") {
			t.Errorf("%s: HOST DATA VISIBLE IN SANDBOX", tc.name)
		}
	}

	res, err := sb.Exec(ctx, "cat /workspace/hello.txt")
	if err != nil || strings.TrimSpace(res.Stdout) != "from host" {
		t.Fatalf("workspace read failed: %q %v %q", res.Stdout, err, res.Stderr)
	}
	if _, err := sb.Exec(ctx, "echo agent-was-here > /workspace/agent.txt"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(ws, "agent.txt"))
	if err != nil || string(b) != "agent-was-here\n" {
		t.Fatalf("container->host workspace write failed: %q %v", b, err)
	}
	if _, serr := os.Stat("/host-probe"); !os.IsNotExist(serr) {
		t.Fatal("container wrote through to host root filesystem")
	}
	os.Remove(filepath.Join(ws, "agent.txt"))
}

func TestIntegrationExecInteractive(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := EnsureAgentImage(ctx); err != nil {
		t.Fatalf("image: %v", err)
	}

	ws := filepath.Join(t.TempDir(), "workspace")
	os.MkdirAll(ws, 0o700)
	os.WriteFile(filepath.Join(ws, "test.txt"), []byte("hello sandbox"), 0o644)

	sb := New("exec-interactive-test-0000-0000-000000000000", ws, nil)
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sb.Kill(context.Background())

	t.Run("exec_command", func(t *testing.T) {
		// Test that ExecInteractive can run a simple command.
		// Since ExecInteractive uses os.Stdin/Stdout, we can't capture output
		// in a test. Instead, verify the sandbox is running and Exec works.
		res, err := sb.Exec(ctx, "echo 'interactive-test-ok'")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout, "interactive-test-ok") {
			t.Errorf("expected output, got: %q", res.Stdout)
		}
	})

	t.Run("workspace_restricted", func(t *testing.T) {
		// Verify workspace is the working directory
		res, err := sb.Exec(ctx, "pwd")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout, "/workspace") {
			t.Errorf("expected /workspace as cwd, got: %q", res.Stdout)
		}
	})

	t.Run("file_access", func(t *testing.T) {
		// Verify files in workspace are accessible
		res, err := sb.Exec(ctx, "cat /workspace/test.txt")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout, "hello sandbox") {
			t.Errorf("file read failed: %q", res.Stdout)
		}
	})

	t.Run("cannot_escape_workspace", func(t *testing.T) {
		// Verify cd .. doesn't escape workspace
		res, err := sb.Exec(ctx, "cd /workspace && cd .. && pwd")
		if err != nil {
			t.Fatal(err)
		}
		// Should still be in /workspace or a subdirectory
		if strings.Contains(res.Stdout, "/home") || strings.Contains(res.Stdout, "/root") {
			t.Errorf("workspace escape detected: %q", res.Stdout)
		}
	})

	t.Run("shell_commands_work", func(t *testing.T) {
		// Verify common shell commands work
		commands := []string{"ls", "pwd", "whoami", "id"}
		for _, cmd := range commands {
			res, err := sb.Exec(ctx, cmd)
			if err != nil {
				t.Errorf("%s failed: %v", cmd, err)
			}
			if res.ExitCode != 0 {
				t.Errorf("%s exited with code %d: %s", cmd, res.ExitCode, res.Stderr)
			}
		}
	})
}

func TestIntegrationPTYStdinStdout(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := EnsureAgentImage(ctx); err != nil {
		t.Fatalf("image: %v", err)
	}

	ws := filepath.Join(t.TempDir(), "workspace")
	os.MkdirAll(ws, 0o700)
	os.WriteFile(filepath.Join(ws, "hello.txt"), []byte("pty-test-content"), 0o644)

	sb := New("pty-test-0000-0000-0000-000000000000", ws, nil)
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sb.Kill(context.Background())

	bin := "docker"
	cmd := exec.Command(bin, "exec", "-it", sb.Name, "bash")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("pty.Start: %v", err)
	}
	defer ptmx.Close()

	pty.Setsize(ptmx, &pty.Winsize{Rows: 24, Cols: 80})

	// Read PTY output via channel with timeout.
	outputCh := make(chan string, 64)
	go func() {
		var buf bytes.Buffer
		tmp := make([]byte, 4096)
		for {
			n, err := ptmx.Read(tmp)
			if n > 0 {
				buf.Write(tmp[:n])
				select {
				case outputCh <- buf.String():
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Helper: send command and wait for expected output.
	sendAndExpect := func(command, expected string, timeout time.Duration) {
		t.Helper()
		_, err := ptmx.Write([]byte(command + "\n"))
		if err != nil {
			t.Fatalf("write %q: %v", command, err)
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			select {
			case out := <-outputCh:
				if strings.Contains(out, expected) {
					return
				}
			case <-time.After(200 * time.Millisecond):
			}
		}
		t.Errorf("command %q: expected %q in output (timed out)", command, expected)
	}

	// Wait for shell prompt
	time.Sleep(500 * time.Millisecond)

	// Test 1: echo through PTY
	sendAndExpect("echo PTY_STDIN_WORKS", "PTY_STDIN_WORKS", 5*time.Second)

	// Test 2: pwd
	sendAndExpect("pwd", "/workspace", 5*time.Second)

	// Test 3: read file
	sendAndExpect("cat hello.txt", "pty-test-content", 5*time.Second)

	// Test 4: ls
	sendAndExpect("ls", "hello.txt", 5*time.Second)

	// Test 5: exit
	_, err = ptmx.Write([]byte("exit\n"))
	if err != nil {
		t.Fatalf("write exit: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if ee.ExitCode() != 0 {
				t.Errorf("bash exited with code %d", ee.ExitCode())
			}
		}
	}
}

func TestIntegrationInjectAgentBinary(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := EnsureAgentImage(ctx); err != nil {
		t.Fatalf("image: %v", err)
	}

	ws := filepath.Join(t.TempDir(), "workspace")
	os.MkdirAll(ws, 0o700)

	sb := New("inject-test-0000-0000-000000000000", ws, nil)
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sb.Kill(context.Background())

	// Inject a fake agent
	if err := sb.InjectAgentBinary("opencode"); err != nil {
		t.Fatalf("InjectAgentBinary: %v", err)
	}

	// Verify symlink was created at writable workspace path
	res, err := sb.Exec(ctx, "ls -la /workspace/.aegis/bin/opencode")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "/agent/bin/agent") {
		t.Errorf("symlink target wrong: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "opencode") {
		t.Errorf("symlink name wrong: %q", res.Stdout)
	}

	// Verify the symlink is a proper symlink (not a regular file)
	res2, err := sb.Exec(ctx, "readlink /workspace/.aegis/bin/opencode")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res2.Stdout, "/agent/bin/agent") {
		t.Errorf("expected symlink to /agent/bin/agent, got: %q", res2.Stdout)
	}
}

func TestIntegrationWorkspaceJail(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := EnsureAgentImage(ctx); err != nil {
		t.Fatalf("image: %v", err)
	}

	ws := filepath.Join(t.TempDir(), "workspace")
	os.MkdirAll(ws, 0o700)
	os.WriteFile(filepath.Join(ws, "project.txt"), []byte("in-workspace"), 0o644)

	sb := New("jail-test-0000-0000-000000000000", ws, nil)
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sb.Kill(context.Background())

	if err := sb.SetupWorkspaceJail(); err != nil {
		t.Fatalf("SetupWorkspaceJail: %v", err)
	}

	t.Run("jail_rcfile_exists", func(t *testing.T) {
		res, err := sb.Exec(ctx, "test -f /tmp/.aegis-jailrc && echo EXISTS")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout, "EXISTS") {
			t.Error("jail rcfile not created")
		}
	})

	t.Run("sh_wrapper_exists", func(t *testing.T) {
		res, err := sb.Exec(ctx, "head -1 /bin/sh")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout, "bash") {
			t.Errorf("/bin/sh wrapper not installed: %q", res.Stdout)
		}
	})

	t.Run("sh_c_blocks_escape", func(t *testing.T) {
		// This is exactly what OpenCode does: sh -c "cd .."
		res, err := sb.Exec(ctx, "sh -c 'cd /workspace; cd ..; pwd'")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		if out != "/workspace" {
			t.Errorf("sh -c cd .. escaped jail: got %q, want /workspace", out)
		}
	})

	t.Run("sh_c_blocks_root_escape", func(t *testing.T) {
		res, err := sb.Exec(ctx, "sh -c 'cd /; pwd'")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		if out != "/workspace" {
			t.Errorf("sh -c cd / escaped jail: got %q, want /workspace", out)
		}
	})

	t.Run("sh_c_allows_workspace_subdirs", func(t *testing.T) {
		sb.Exec(ctx, "mkdir -p /workspace/subdir")
		res, err := sb.Exec(ctx, "sh -c 'cd subdir; pwd'")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		if !strings.HasSuffix(out, "/workspace/subdir") {
			t.Errorf("cd to subdir failed: got %q", out)
		}
	})

	t.Run("bash_c_blocks_escape", func(t *testing.T) {
		// bash -c should also be jailed via BASH_ENV
		res, err := sb.Exec(ctx, "bash -c 'cd /; pwd'")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		if out != "/workspace" {
			t.Errorf("bash -c cd / escaped jail: got %q, want /workspace", out)
		}
	})
}

func TestIntegrationFilesystemBoundary(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := EnsureAgentImage(ctx); err != nil {
		t.Fatalf("image: %v", err)
	}

	ws := filepath.Join(t.TempDir(), "workspace")
	os.MkdirAll(ws, 0o700)
	os.WriteFile(filepath.Join(ws, "project.txt"), []byte("in-workspace"), 0o644)

	sb := New("fs-boundary-0000-0000-0000-000000000000", ws, nil)
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sb.Kill(context.Background())

	if err := sb.SetupWorkspaceJail(); err != nil {
		t.Fatalf("SetupWorkspaceJail: %v", err)
	}

	// --- /etc: agent sees only minimal entries, no root user ---
	t.Run("etc_passwd_minimal", func(t *testing.T) {
		res, err := sb.Exec(ctx, "cat /etc/passwd")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		if strings.Contains(out, "root:") {
			t.Errorf("/etc/passwd leaks root entry: %q", out)
		}
		if !strings.Contains(out, "node:x:1000:1000::/workspace:/bin/bash") {
			t.Errorf("/etc/passwd missing minimal node entry: %q", out)
		}
	})

	t.Run("etc_shadow_empty", func(t *testing.T) {
		res, err := sb.Exec(ctx, "cat /etc/shadow 2>&1 || true")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		// /etc/shadow should be empty or inaccessible to uid 1000.
		// Either outcome means no password hashes are leaked.
		if strings.Contains(out, "$") || strings.Contains(out, ":root:") {
			t.Errorf("/etc/shadow leaks sensitive data: %q", out)
		}
	})

	t.Run("etc_hosts_minimal", func(t *testing.T) {
		res, err := sb.Exec(ctx, "cat /etc/hosts")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		if strings.Contains(out, "aegis") || strings.Contains(out, "docker") {
			t.Errorf("/etc/hosts leaks container metadata: %q", out)
		}
	})

	// --- /root: hidden by tmpfs overlay ---
	t.Run("root_hidden", func(t *testing.T) {
		res, err := sb.Exec(ctx, "ls -la /root 2>&1 || true")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		for _, sensitive := range []string{".ssh", ".bashrc", ".bash_history", ".profile"} {
			if strings.Contains(out, sensitive) {
				t.Errorf("/root leaks sensitive file %s: %q", sensitive, out)
			}
		}
	})

	t.Run("root_passwd_no_root_user", func(t *testing.T) {
		res, err := sb.Exec(ctx, "grep root /etc/passwd 2>&1 || true")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(res.Stdout, "root") {
			t.Errorf("/etc/passwd still contains root user: %q", res.Stdout)
		}
	})

	// --- /home: hidden by tmpfs overlay ---
	t.Run("home_hidden", func(t *testing.T) {
		res, err := sb.Exec(ctx, "ls /home 2>&1 || true")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		if strings.Contains(out, "node") || strings.Contains(out, "root") {
			t.Errorf("/home leaks user directories: %q", out)
		}
	})

	// --- /var: hidden by tmpfs overlay ---
	t.Run("var_hidden", func(t *testing.T) {
		res, err := sb.Exec(ctx, "ls /var/log 2>&1 || true")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		if strings.Contains(out, "syslog") || strings.Contains(out, "dpkg") {
			t.Errorf("/var/log leaks host logs: %q", out)
		}
	})

	// --- cd jail still works ---
	t.Run("cd_stays_in_workspace", func(t *testing.T) {
		res, err := sb.Exec(ctx, "cd /workspace && cd .. && pwd")
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(res.Stdout) != "/workspace" {
			t.Errorf("cd .. escaped: %q", res.Stdout)
		}
	})

	t.Run("cd_root_stays_in_workspace", func(t *testing.T) {
		res, err := sb.Exec(ctx, "cd / && pwd")
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(res.Stdout) != "/workspace" {
			t.Errorf("cd / escaped: %q", res.Stdout)
		}
	})

	// --- workspace operations still work ---
	t.Run("workspace_read_write", func(t *testing.T) {
		res, err := sb.Exec(ctx, "echo test-data > /workspace/rw-test.txt && cat /workspace/rw-test.txt")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout, "test-data") {
			t.Errorf("workspace r/w failed: %q", res.Stdout)
		}
	})

	t.Run("workspace_subdirs", func(t *testing.T) {
		res, err := sb.Exec(ctx, "mkdir -p /workspace/src && echo 'fn main(){}' > /workspace/src/main.rs && cat /workspace/src/main.rs")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout, "fn main") {
			t.Errorf("subdir r/w failed: %q", res.Stdout)
		}
	})

	// --- runtime tools still work ---
	t.Run("tools_work", func(t *testing.T) {
		tools := []struct {
			cmd string
			min string
		}{
			{"bash --version", "bash"},
			{"git --version", "git version"},
			{"python3 --version", "Python 3"},
			{"pwd", "/workspace"},
		}
		for _, tc := range tools {
			res, err := sb.Exec(ctx, tc.cmd)
			if err != nil {
				t.Errorf("%s: %v", tc.cmd, err)
				continue
			}
			if res.ExitCode != 0 {
				t.Errorf("%s: exit %d: %s", tc.cmd, res.ExitCode, res.Stderr)
				continue
			}
			if !strings.Contains(res.Stdout, tc.min) {
				t.Errorf("%s: expected %q in output: %q", tc.cmd, tc.min, res.Stdout)
			}
		}
	})

	// --- host data not visible ---
	t.Run("no_host_data", func(t *testing.T) {
		probes := []string{
			"test -e /home/user/.ssh/id_rsa && echo LEAK",
			"test -S /var/run/docker.sock && echo LEAK",
			"test -d /home/user/.aws && echo LEAK",
		}
		for _, probe := range probes {
			res, err := sb.Exec(ctx, probe+"; true")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(res.Stdout, "LEAK") {
				t.Errorf("HOST DATA VISIBLE: %s", probe)
			}
		}
	})

	// --- root filesystem is read-only ---
	t.Run("root_readonly", func(t *testing.T) {
		// /etc is tmpfs (writable by design). /bin is on the image root
		// filesystem which --read-only makes immutable.
		res, err := sb.Exec(ctx, "touch /bin/test-readonly 2>&1")
		if err != nil {
			t.Fatal(err)
		}
		if res.ExitCode == 0 {
			t.Error("container root filesystem is not read-only")
		}
		combined := res.Stdout + res.Stderr
		if !strings.Contains(combined, "Read-only") && !strings.Contains(combined, "Permission") {
			t.Errorf("unexpected error touching /bin: exit=%d combined=%q",
				res.ExitCode, combined)
		}
	})
}
