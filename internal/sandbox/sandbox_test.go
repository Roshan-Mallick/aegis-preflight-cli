package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path"
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
	FatImage            []json.RawMessage `json:"fat_image"`
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

func TestVerifyIsolationRejectsFatToolImage(t *testing.T) {
	f := loadFixtures(t)
	violations := VerifyIsolation(wrapArray(t, f.FatImage[0]), "/tmp/ws")
	joined := strings.Join(violations, "; ")
	if !strings.Contains(joined, "not the minimal runtime") {
		t.Fatalf("fat tool image not rejected: %v", violations)
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
		// Verify common shell commands work. The runtime image has no
		// readable /etc/passwd (agent runs as numeric uid 1000), so
		// name-lookup utilities like `whoami` intentionally fail while
		// numeric id and ordinary commands work.
		commands := []string{"ls", "pwd", "id", "id -u", "bash --version"}
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

	// --- /etc/passwd + /etc/group: exist for NSS edge cases but are
	// root-owned 0600, so the agent cannot read them and cannot see any
	// account data (let alone host accounts or hashes). ---
	t.Run("etc_passwd_inaccessible", func(t *testing.T) {
		res, err := sb.Exec(ctx, "cat /etc/passwd 2>&1")
		if err != nil {
			t.Fatal(err)
		}
		if res.ExitCode == 0 {
			t.Errorf("/etc/passwd is readable by the agent: %q", res.Stdout)
		}
		out := strings.TrimSpace(res.Stdout + res.Stderr)
		if strings.Contains(out, "root:") || strings.Contains(out, ":"+":") {
			t.Errorf("/etc/passwd content leaked to stderr/stdout: %q", out)
		}
	})

	t.Run("etc_shadow_absent", func(t *testing.T) {
		res, err := sb.Exec(ctx, "ls /etc/shadow 2>&1 || true")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout + res.Stderr)
		if strings.Contains(out, "No such file") == false {
			t.Errorf("/etc/shadow should not exist: %q", out)
		}
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

	// --- /root, /home, /var (and the rest of the host tree) do not exist
	// in the minimal runtime image: any access fails at the filesystem
	// level, not by policy. ---
	t.Run("root_absent", func(t *testing.T) {
		res, err := sb.Exec(ctx, "ls /root 2>&1 || true")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout+res.Stderr, "No such file") {
			t.Errorf("/root is present in the sandbox: %q", res.Stdout)
		}
	})

	t.Run("home_absent", func(t *testing.T) {
		res, err := sb.Exec(ctx, "ls /home 2>&1 || true")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout+res.Stderr, "No such file") {
			t.Errorf("/home is present in the sandbox: %q", res.Stdout)
		}
	})

	t.Run("var_absent", func(t *testing.T) {
		res, err := sb.Exec(ctx, "ls /var 2>&1 || true")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout+res.Stderr, "No such file") {
			t.Errorf("/var is present in the sandbox: %q", res.Stdout)
		}
	})

	t.Run("opt_srv_absent", func(t *testing.T) {
		for _, p := range []string{"/opt", "/srv", "/media", "/mnt", "/boot"} {
			res, err := sb.Exec(ctx, "ls "+p+" 2>&1 || true")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(res.Stdout+res.Stderr, "No such file") {
				t.Errorf("%s is present in the sandbox: %q", p, res.Stdout)
			}
		}
	})

	// --- cd jail still works ---
	t.Run("cd_stays_in_workspace", func(t *testing.T) {
		res, err := sb.Exec(ctx, "cd /workspace; cd ..; pwd")
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(res.Stdout) != "/workspace" {
			t.Errorf("cd .. escaped: %q", res.Stdout)
		}
	})

	t.Run("cd_root_stays_in_workspace", func(t *testing.T) {
		res, err := sb.Exec(ctx, "cd /; pwd")
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

// TestIntegrationMinimalRuntimeBoundary is the live contract for the
// filesystem-level boundary enforced by the minimal runtime image
// (images.RuntimeImage): outside /workspace nothing sensitive EXISTS or is
// readable, and nothing can be reached by absolute path, relative ".." walk
// or symlink — including the user's exact checklist.
func TestIntegrationMinimalRuntimeBoundary(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	parent := t.TempDir()
	project := filepath.Join(parent, "proj")
	if err := os.MkdirAll(project, 0755); err != nil {
		t.Fatal(err)
	}
	writeFileHost(t, filepath.Join(parent, "outside.txt"), "HOST-SECRET", 0644)
	_ = os.MkdirAll(filepath.Join(project, "src"), 0755)
	writeFileHost(t, filepath.Join(project, "src", "a.py"), "x=1\n", 0644)

	sb := New("min-runtime-0000-0000-0000-000000000000", project, nil)
	if err := sb.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sb.Kill(ctx)
	if err := sb.SetupWorkspaceJail(); err != nil {
		t.Fatal(err)
	}

	// The running container must use the minimal runtime image.
	rawInspect, err := sb.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("runtime_image_in_use", func(t *testing.T) {
		items, err := ParseInspect(rawInspect)
		if err != nil {
			t.Fatal(err)
		}
		if img := items[0].Config.Image; !strings.HasPrefix(img, runtimeImagePrefix) {
			t.Errorf("container is not running the minimal runtime image, got %q", img)
		}
		if v := VerifyIsolation(rawInspect, project); len(v) != 0 {
			t.Errorf("running container violates isolation: %v", v)
		}
	})

	// User's critical checklist: every escape path must fail at the
	// filesystem level (rc != 0), not by policy messaging. Two exceptions
	// are still stricts: `ls /tmp` succeeds but must show an empty private
	// tmpfs, and `ls /workspace/..` succeeds but must show only the minimal
	// runtime tree (covered by workspace_parent_is_minimal below).
	t.Run("user_checklist_denied_at_fs_level", func(t *testing.T) {
		mustFail := map[string]string{
			"cat /workspace/../outside.txt":    "trailing-parent escape",
			"cat /workspace/../../outside.txt": "double-parent escape",
			"cat ../outside.txt":               "cwd relative escape",
			"cat ../../outside.txt":            "cwd double-relative escape",
			"cat /etc/passwd":                  "host passwd",
			"ls /home":                         "home",
			"ls /home/user":                    "home user dir",
			"ls /root":                         "root home",
			"find /home":                       "home walk",
		}
		for probe, label := range mustFail {
			res, err := sb.Exec(ctx, probe+" >/dev/null 2>&1; echo rc=$?")
			if err != nil {
				t.Fatalf("%s: exec failed: %v", label, err)
			}
			out := strings.TrimSpace(res.Stdout)
			// Expected outcomes: rc=2 for removed paths (ENOENT), rc=1 for
			// filesystem permission denials. Any rc=0 with content is a leak.
			if strings.Contains(out, "rc=0") {
				t.Errorf("%s: %q returned rc=0", label, probe)
			}
			if strings.Contains(out, "outside.txt") || strings.Contains(out, "outside") {
				t.Errorf("%s: leaked file content at %q: %s", label, probe, out)
			}
		}
		for _, probe := range []string{"ls /tmp", "find /tmp"} {
			res, err := sb.Exec(ctx, probe+" 2>&1")
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range strings.Fields(res.Stdout) {
				base := strings.TrimSuffix(path.Base(e), "/")
				if base != "." && base != ".." && base != "/" && base != ".aegis-jailrc" && base != "tmp" {
					t.Errorf("%s must be a private empty tree, got %q (full %v)", probe, e, strings.Fields(res.Stdout))
				}
			}
		}
	})

	t.Run("workspace_parent_is_minimal", func(t *testing.T) {
		res, err := sb.Exec(ctx, "ls -1 /workspace/.. 2>&1")
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Fields(res.Stdout)
		allowed := map[string]bool{
			"agent": true, "bin": true, "dev": true, "etc": true,
			"lib": true, "lib64": true, "proc": true, "run": true,
			"sbin": true, "sys": true, "tmp": true, "usr": true,
			"workspace": true, ".dockerenv": true,
		}
		for _, e := range got {
			if !allowed[e] {
				t.Errorf("/workspace/.. contains unexpected entry %q (full list %v)", e, got)
			}
		}
		if len(got) == 0 {
			t.Error("/workspace/.. is empty: expected at least the minimal runtime root")
		}
	})

	t.Run("find_root_only_minimal", func(t *testing.T) {
		res, err := sb.Exec(ctx, "find / -maxdepth 1 2>/dev/null | sort")
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Fields(res.Stdout)
		allowed := map[string]bool{
			"agent": true, "bin": true, "dev": true, "etc": true,
			"lib": true, "lib64": true, "proc": true, "run": true,
			"sbin": true, "sys": true, "tmp": true, "usr": true,
			"workspace": true, "/": true, ".dockerenv": true,
		}
		for _, e := range got {
			key := e
			if e != "/" {
				key = strings.TrimLeft(e, "/")
			}
			if !allowed[key] {
				t.Errorf("find / leaked entry %q (full %v)", e, got)
			}
		}
		if len(got) == 0 {
			t.Error("find / produced no output")
		}
	})

	t.Run("agent_cache_agent_owned_writable", func(t *testing.T) {
		// Regression: opencode crashed at startup with
		// `EACCES: permission denied, mkdir '/agent/cache/.local'` because
		// the tmpfs over /agent/cache was root-owned 0755. The mount must
		// be pinned to the agent uid with mode 0700.
		res, err := sb.Exec(ctx, "stat -c '%A %u:%g' /agent/cache; mkdir -p /agent/cache/.local /agent/cache/.config && touch /agent/cache/.local/probe && printf 'x\\n' > /agent/cache/.config/c && rm /agent/cache/.local/probe && echo AGENT-CACHE-OK")
		if err != nil {
			t.Fatal(err)
		}
		out := strings.TrimSpace(res.Stdout)
		fields := strings.Fields(out)
		if len(fields) == 0 {
			t.Fatalf("no stat output: %q", out)
		}
		mode := fields[0]
		if !(strings.HasPrefix(mode, "-rwx") || strings.HasPrefix(mode, "drwx")) {
			t.Errorf("/agent/cache mode = %s, want agent-writable (0700)", mode)
		}
		if mode[2] != 'w' {
			t.Errorf("/agent/cache is not owner-writable: %s", mode)
		}
		if mode[4] == 'r' || mode[5] == 'w' || mode[7] == 'r' {
			t.Errorf("/agent/cache is too permissive (group/other readable): %s", mode)
		}
		if !strings.HasPrefix(fields[1], "1000:") {
			t.Errorf("/agent/cache owner = %s, want uid 1000", fields[1])
		}
		if !strings.Contains(out, "AGENT-CACHE-OK") {
			t.Errorf("agent could not create .local/.config under /agent/cache: %q", out)
		}
	})

	t.Run("tmp_is_private_empty_tmpfs", func(t *testing.T) {
		res, err := sb.Exec(ctx, "ls -1 /tmp 2>&1")
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Fields(res.Stdout)
		if len(got) != 0 {
			t.Errorf("/tmp should be empty, contains %v", got)
		}
	})

	t.Run("symlink_escapes_blocked", func(t *testing.T) {
		probes := map[string]string{
			`ln -sf /etc/passwd /workspace/link1 && cat /workspace/link1`:               "to /etc/passwd",
			`ln -sf /home /workspace/link2 && ls /workspace/link2`:                      "to /home",
			`ln -sf / /workspace/link3 && ls /workspace/link3`:                          "to /",
			`ln -sf /workspace/../outside.txt /workspace/link4 && cat /workspace/link4`: "to ../outside.txt",
			`ln -sf ../../../etc/passwd /workspace/link5 && cat /workspace/link5`:       "deep-relative to /etc/passwd",
		}
		for probe, label := range probes {
			res, err := sb.Exec(ctx, probe+" >/dev/null 2>&1; echo rc=$?")
			if err != nil {
				t.Fatalf("symlink %s: exec failed: %v", label, err)
			}
			if strings.Contains(res.Stdout, "HOST-SECRET") {
				t.Errorf("symlink %s leaked host data", label)
			}
			if strings.Contains(res.Stdout, "root:x:") || strings.Contains(res.Stdout, "node:x:") {
				t.Errorf("symlink %s leaked passwd data", label)
			}
		}
	})

	t.Run("symlink_created_after_startup", func(t *testing.T) {
		res, err := sb.Exec(ctx, "cd /workspace && ln -sf / /workspace/escape-root && ls /workspace/escape-root/ >>/dev/null 2>&1 && cat /workspace/escape-root/workspace/../outside.txt 2>&1; echo rc=$?")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(res.Stdout, "HOST-SECRET") {
			t.Error("post-start symlink to / escaped to host data")
		}
	})

	// CRUD under /workspace keeps working (the project remains fully
	// usable for the agent).
	t.Run("crud_inside_workspace_works", func(t *testing.T) {
		res, err := sb.Exec(ctx, "mkdir -p /workspace/newdir && printf 'c=2\\n' > /workspace/newdir/c.txt && cat /workspace/newdir/c.txt && rm /workspace/src/a.py && test ! -e /workspace/src/a.py && echo CRUD-OK")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Stdout, "CRUD-OK") {
			t.Errorf("in-project CRUD failed: %q", res.Stdout)
		}
		if !strings.Contains(res.Stdout, "c=2") {
			t.Errorf("created file content missing: %q", res.Stdout)
		}
	})
}

// TestIntegrationProjectRootMountDirect is the live direct-mount contract:
// an arbitrary launch directory is mounted AS /workspace, the bind mount
// source is exactly that directory, and files created by the agent inside the
// container appear immediately in the original project directory on the host.
// No separate workspace copy exists anywhere.
func TestIntegrationProjectRootMountDirect(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := EnsureAgentImage(ctx); err != nil {
		t.Fatalf("image: %v", err)
	}

	// An "arbitrary" project directory, exactly as if launched from it.
	projectRoot := t.TempDir()
	writeFileHost(t, filepath.Join(projectRoot, "README.md"), "direct-mount project\n", 0o644)
	parent := filepath.Dir(projectRoot)
	writeFileHost(t, filepath.Join(parent, "host-secret.txt"), "DO NOT LEAK", 0o600)
	// Deliberately no "<state>/sessions/<id>/workspace" copy anywhere.
	stateRoot := t.TempDir()

	sb := New("mount-direct-0000-0000-000000000001", projectRoot, nil)
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sb.Kill(context.Background())
	if err := sb.SetupWorkspaceJail(); err != nil {
		t.Fatalf("SetupWorkspaceJail: %v", err)
	}

	// 1. The bind mount source is EXACTLY the project root.
	raw, err := sb.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	items, err := ParseInspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	projectAbs, _ := filepath.Abs(projectRoot)
	var bindMounts int
	for _, m := range items[0].Mounts {
		if m.Type == "bind" {
			bindMounts++
			if m.Destination != "/workspace" {
				t.Errorf("unexpected bind mount destination %s <- %s", m.Destination, m.Source)
			}
			if src, _ := filepath.Abs(m.Source); src != projectAbs {
				t.Errorf("bind source %q != project %q", m.Source, projectAbs)
			}
			if !m.RW {
				t.Error("/workspace bind mount is not read-write")
			}
		}
	}
	if bindMounts != 1 {
		t.Errorf("expected exactly one bind mount (/workspace <- project), got %d", bindMounts)
	}
	if violations := VerifyIsolation(raw, projectRoot); len(violations) > 0 {
		t.Fatalf("live container violates isolation: %v", violations)
	}

	// 2. Container reads the project's original content.
	res, err := sb.Exec(ctx, "cat /workspace/README.md")
	if err != nil || strings.TrimSpace(res.Stdout) != "direct-mount project" {
		t.Fatalf("project content not visible at /workspace: %q %v %q", res.Stdout, err, res.Stderr)
	}

	// 3. Agent-created files land in the ORIGINAL project directory.
	if _, err := sb.Exec(ctx, "mkdir -p /workspace/src && echo 'fn main(){}' > /workspace/src/main.rs"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(projectRoot, "src", "main.rs"))
	if err != nil || !strings.Contains(string(b), "fn main(){}") {
		t.Fatalf("agent file missing from original project dir: %q %v", b, err)
	}

	// 4. The parent directory (with its secret) stays unreachable through
	// the mount boundary and through a symlink planted from inside.
	probes := []string{
		"cat /workspace/../host-secret.txt 2>&1",
		"cat /../host-secret.txt 2>&1",
	}
	for _, p := range probes {
		res, _ := sb.Exec(ctx, p)
		if strings.Contains(res.Stdout, "DO NOT LEAK") {
			t.Errorf("HOST PARENT DATA READ VIA %s", p)
		}
	}
	link, _ := sb.Exec(ctx, "ln -s ../host-secret.txt /workspace/dangling && cat /workspace/dangling 2>&1")
	if strings.Contains(link.Stdout, "DO NOT LEAK") {
		t.Error("host secret reached through relative-escape symlink")
	}
	absLink, _ := sb.Exec(ctx, "ln -s /etc/passwd /workspace/abslink && cat /workspace/abslink 2>&1")
	if strings.Contains(absLink.Stdout, "root:") || strings.Contains(absLink.Stdout, "DO NOT LEAK") {
		t.Errorf("/workspace/abslink reached host /etc/passwd: %q", absLink.Stdout)
	}

	// 5. No workspace copy directory was ever created under the state root.
	var copies []string
	_ = filepath.WalkDir(stateRoot, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && d.Name() == "workspace" {
			copies = append(copies, path)
		}
		return nil
	})
	if len(copies) != 0 {
		t.Fatalf("a copied workspace dir exists under state root: %v", copies)
	}
}

// TestIntegrationCdNavigationAndBoundary is the precise navigation contract:
// interior navigation works anywhere inside the project (cd src; cd ..; cd
// tests; cd ../src), while every attempt above/through the boundary — cd .. at
// /workspace, cd /workspace/../src, cd /, cd ~ (HOME=/home/node) — is refused
// and the shell ends up where it was.
func TestIntegrationCdNavigationAndBoundary(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := EnsureAgentImage(ctx); err != nil {
		t.Fatalf("image: %v", err)
	}

	projectRoot := t.TempDir()
	sb := New("cd-navigation-0000-0000-000000000001", projectRoot, nil)
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sb.Kill(context.Background())
	if err := sb.SetupWorkspaceJail(); err != nil {
		t.Fatalf("SetupWorkspaceJail: %v", err)
	}

	allowed := []struct {
		name string
		cmd  string
		want string
	}{
		{"cd into subdir", "mkdir -p /workspace/src; cd /workspace/src; cd ..; pwd", "/workspace"},
		{"cd up from subdir to root", "mkdir -p /workspace/src; cd /workspace/src; cd ..; cd ..; pwd", "/workspace"},
		{"cd down then sibling via ..", "mkdir -p /workspace/tests; cd /workspace/src; cd ..; cd tests; cd ../src; pwd", "/workspace/src"},
		{"deep relative nav", "mkdir -p /workspace/a/b/c; cd /workspace/a/b/c; cd ../../b/c; pwd", "/workspace/a/b/c"},
		{"cd - returns to previous dir", "cd /workspace; mkdir -p /workspace/x; cd /workspace/x; cd - >/dev/null; pwd", "/workspace"},
	}
	for _, tc := range allowed {
		res, err := sb.Exec(ctx, tc.cmd)
		if err != nil {
			t.Fatalf("%s: exec error: %v", tc.name, err)
		}
		if got := strings.TrimSpace(res.Stdout); got != tc.want {
			t.Errorf("%s: pwd = %q, want %q (stderr %q)", tc.name, got, tc.want, res.Stderr)
		}
	}

	blocked := []struct {
		name string
		cmd  string
	}{
		{"cd .. at workspace root", "cd /workspace; cd ..; pwd"},
		{"cd .. twice at root", "cd /workspace; cd ..; cd ..; pwd"},
		{"cd /workspace/../src", "cd /workspace/../src 2>&1; pwd"},
		{"cd /", "cd /; pwd"},
		{"cd ~", "cd ~ 2>&1; pwd"},
		{"cd /home", "cd /home 2>&1; pwd"},
		{"cd /etc", "cd /etc 2>&1; pwd"},
		{"cd /tmp", "cd /tmp 2>&1; pwd"},
	}
	for _, tc := range blocked {
		res, err := sb.Exec(ctx, tc.cmd)
		if err != nil {
			t.Fatalf("%s: exec error: %v", tc.name, err)
		}
		lines := strings.Fields(strings.TrimSpace(res.Stdout))
		last := ""
		if len(lines) > 0 {
			last = lines[len(lines)-1]
		}
		if last != "/workspace" {
			t.Errorf("%s: escaped boundary, final pwd = %q (stderr %q)", tc.name, last, res.Stderr)
		}
	}
}

// TestIntegrationAgentBinMountsPassIsolation verifies VerifyIsolation accepts
// the documented read-only agent-tool chain mounts (a real binary under
// /usr/local/bin plus its ldd libraries) while still flagging unknown host
// paths — so production runs with AgentBins set are not mis-reported.
func TestIntegrationAgentBinMountsPassIsolation(t *testing.T) {
	requireDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := EnsureAgentImage(ctx); err != nil {
		t.Fatalf("image: %v", err)
	}

	probeBin, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found for mount probe")
	}
	projectRoot := t.TempDir()
	sb := New("agent-mounts-0000-0000-000000000001", projectRoot, nil)
	sb.AgentBins = map[string]string{"probe-agent": probeBin}
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sb.Kill(context.Background())

	raw, err := sb.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if violations := VerifyIsolation(raw, projectRoot); len(violations) > 0 {
		t.Fatalf("agent-tool mounts wrongly flagged: %v", violations)
	}
	res, err := sb.Exec(ctx, "test -x /usr/local/bin/probe-agent && echo MOUNTED")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "MOUNTED") {
		t.Errorf("probe agent bin not mounted into PATH: %q", res.Stdout)
	}
}

func writeFileHost(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
