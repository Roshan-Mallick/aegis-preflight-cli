package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eth0x1/aegis/internal/paths"
)

const (
	stOK   = "OK"
	stWarn = "WARN"
	stFail = "FAIL"
	stSkip = "SKIP"
)

type checkResult struct {
	Status string
	Name   string
	Detail string
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Verify host environment readiness (no external network calls)",
		RunE: func(cmd *cobra.Command, args []string) error {
			results := runDoctorChecks()
			failed := false
			warned := false
			for _, r := range results {
				fmt.Printf("[%-4s] %-24s %s\n", r.Status, r.Name, r.Detail)
				if r.Status == stFail {
					failed = true
				}
				if r.Status == stWarn {
					warned = true
				}
			}
			fmt.Println()
			if failed {
				fmt.Println("result: FAIL — mandatory requirements not met")
				fmt.Println("fix the FAIL items above, then re-run: aegis doctor")
				return fmt.Errorf("environment not ready")
			}
			if warned {
				fmt.Println("result: PASS (with warnings)")
				fmt.Println("optional tools missing — some features disabled")
			} else {
				fmt.Println("result: PASS")
			}
			return nil
		},
	}
}

func runDoctorChecks() []checkResult {
	var results []checkResult

	if runtime.GOOS == "linux" {
		results = append(results, checkResult{stOK, "platform", runtime.GOOS + "/" + runtime.GOARCH})
	} else {
		results = append(results, checkResult{stWarn, "platform", runtime.GOOS + " unsupported in v1 (Linux-first)"})
	}

	dockerBin, dockerErr := exec.LookPath("docker")
	if dockerErr != nil {
		results = append(results, checkResult{stFail, "docker binary", "not found in PATH"})
		results = append(results, skipDockerDependent()...)
	} else {
		results = append(results, checkResult{stOK, "docker binary", dockerBin})
		daemonOK, daemonVer := checkDockerDaemon()
		if !daemonOK {
			results = append(results, checkResult{stFail, "docker daemon", daemonVer})
			results = append(results, skipDockerDependent()...)
		} else {
			results = append(results, checkResult{stOK, "docker daemon", "reachable (" + daemonVer + ")"})
			results = append(results, checkImages()...)
		}
	}

	for _, c := range toolChecks() {
		results = append(results, c)
	}

	results = append(results, stateDirCheck())
	return results
}

func skipDockerDependent() []checkResult {
	return []checkResult{
		{stSkip, "required images", "docker unavailable"},
	}
}

func checkDockerDaemon() (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	out, err := cmd.CombinedOutput()
	msg := strings.TrimSpace(string(out))
	if err != nil {
		low := strings.ToLower(msg + " " + err.Error())
		if strings.Contains(low, "permission denied") || strings.Contains(low, "docker.sock") {
			// Check if user is in docker group but session lacks it
			idCmd := exec.Command("id", "-nG")
			idOut, idErr := idCmd.CombinedOutput()
			if idErr == nil && strings.Fields(string(idOut)) != nil {
				groups := strings.Fields(string(idOut))
				for _, g := range groups {
					if g == "docker" {
						return false, "permission denied — you are in the docker group but this shell session needs re-login (or use: sg docker -c 'aegis run')"
					}
				}
			}
			return false, "permission denied — add your user to the docker group, then re-login: sudo usermod -aG docker $USER && newgrp docker"
		}
		return false, "daemon unreachable: " + msg
	}
	return true, msg
}

func checkImages() []checkResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", "aegis-agent:v1", "aegis-proxy:v1")
	if err := cmd.Run(); err != nil {
		return []checkResult{{stWarn, "required images", "missing aegis-agent:v1 / aegis-proxy:v1 — run 'aegis init'"}}
	}
	return []checkResult{{stOK, "required images", "aegis-agent:v1, aegis-proxy:v1 present"}}
}

func toolChecks() []checkResult {
	type tc struct {
		name  string
		bin   string
		okMsg string
		warn  string
		fail  bool
	}
	checks := []tc{
		{"git", "git", "", "git not found in PATH (used for diff generation)", false},
		{"gitleaks", "gitleaks", "", "gitleaks not found in PATH (required for PreFlight; see scripts/install.sh)", false},
		{"claude cli", "claude", "", "claude not found in PATH (Claude Code adapter requires it)", false},
		{"node/npm", "npm", "", "npm not found (npm audit disabled)", false},
		{"pip-audit", "pip-audit", "", "pip-audit not found (pip audit disabled)", false},
	}
	var results []checkResult
	for _, c := range checks {
		if p, err := exec.LookPath(c.bin); err == nil {
			results = append(results, checkResult{stOK, c.name, p})
		} else if c.fail {
			results = append(results, checkResult{stFail, c.name, c.warn})
		} else {
			results = append(results, checkResult{stWarn, c.name, c.warn})
		}
	}
	return results
}

func stateDirCheck() checkResult {
	dir, err := paths.EnsureSessionsDir()
	if err != nil {
		return checkResult{stFail, "state directory", fmt.Sprintf("cannot create %s: %v", paths.StateDir(), err)}
	}
	probe := filepath.Join(dir, ".probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return checkResult{stFail, "state directory", fmt.Sprintf("not writable: %s", dir)}
	}
	os.Remove(probe)
	return checkResult{stOK, "state directory", dir}
}
