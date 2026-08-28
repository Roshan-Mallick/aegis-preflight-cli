package network

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/sandbox"
)

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker binary missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := docker(ctx, "info", "--format", "ok"); err != nil {
		t.Skipf("docker daemon unavailable")
	}
}

func requireInternet(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "api.anthropic.com:443", 6*time.Second)
	if err != nil {
		t.Skipf("outbound internet unavailable: %v", err)
	}
	conn.Close()
}

func pollForEvent(t *testing.T, dir string, timeout time.Duration, pred func(events.Event) bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		evts, err := events.ReadAll(dir)
		if err == nil {
			for _, e := range evts {
				if pred(e) {
					return true
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

func TestGatewayUnitInit(t *testing.T) {
	stateRoot := t.TempDir()
	sessionID := uuid.NewString()
	store, err := events.Open(filepath.Join(stateRoot, "sessions", sessionID))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	t.Run("strict_profile", func(t *testing.T) {
		gw, err := New(sessionID, ProfileStrict, store)
		if err != nil {
			t.Fatal(err)
		}
		if gw.SessionID != sessionID {
			t.Errorf("SessionID = %q, want %q", gw.SessionID, sessionID)
		}
		if gw.NetName != "aegis-net-"+sessionID[:8] {
			t.Errorf("NetName = %q", gw.NetName)
		}
		args := gw.AgentNetworkArgs()
		if len(args) != 10 {
			t.Fatalf("AgentNetworkArgs() returned %d args, want 10", len(args))
		}
		if args[0] != "--network" || args[1] != gw.NetName {
			t.Errorf("args[0:2] = %v, want [--network %s]", args[0:2], gw.NetName)
		}
		if args[2] != "--dns" {
			t.Errorf("args[2] = %q, want --dns", args[2])
		}
	})

	t.Run("dev_profile", func(t *testing.T) {
		gw, err := New(sessionID, ProfileDev, store)
		if err != nil {
			t.Fatal(err)
		}
		args := gw.AgentNetworkArgs()
		if len(args) != 10 {
			t.Fatalf("AgentNetworkArgs() returned %d args, want 10", len(args))
		}
		if args[0] != "--network" {
			t.Errorf("args[0] = %q, want --network", args[0])
		}
	})

	t.Run("invalid_profile", func(t *testing.T) {
		_, err := New(sessionID, Profile("invalid"), store)
		if err == nil {
			t.Error("expected error for invalid profile")
		}
	})
}

func TestIntegrationEgressGatewayLive(t *testing.T) {
	requireDocker(t)
	requireInternet(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	stateRoot := t.TempDir()
	sessionID := uuid.NewString()
	store, err := events.Open(filepath.Join(stateRoot, "sessions", sessionID))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	eventDir := filepath.Join(stateRoot, "sessions", sessionID)

	gw, err := New(sessionID, ProfileStrict, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := gw.Up(ctx); err != nil {
		t.Fatalf("gateway up: %v", err)
	}
	defer gw.Down(context.Background())

	ws := filepath.Join(t.TempDir(), "workspace")
	os.MkdirAll(ws, 0o700)
	sb := sandbox.New(sessionID, ws, nil)
	sb.NetworkArgs = gw.AgentNetworkArgs()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("agent start: %v", err)
	}
	defer sb.Kill(context.Background())

	t.Run("TEST3_allowed_provider_origin", func(t *testing.T) {
		res, err := sb.Exec(ctx,
			"curl -sS -o /dev/null -w '%{http_code}' --max-time 30 https://api.anthropic.com")
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
		code := strings.TrimSpace(res.Stdout)
		if res.ExitCode != 0 || code == "" || code == "000" {
			t.Fatalf("allowed destination failed: exit=%d code=%q stderr=%q",
				res.ExitCode, code, res.Stderr)
		}
		ok := pollForEvent(t, eventDir, 12*time.Second, func(e events.Event) bool {
			return e.Source == events.SourceProxy && e.Type == events.TypeNetworkConnect &&
				e.Data["domain"] == "api.anthropic.com" && e.Data["decision"] == "allow"
		})
		if !ok {
			t.Error("no allow event recorded for api.anthropic.com")
		}
	})

	t.Run("TEST4_blocked_domain", func(t *testing.T) {
		res, err := sb.Exec(ctx,
			"curl -sS --max-time 20 https://evil.com ; echo RC=$?")
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
		if !strings.Contains(res.Stdout, "RC=56") || !strings.Contains(res.Stderr, "403") {
			t.Fatalf("expected CONNECT 403 refusal, got rc-out=%q stderr=%q",
				res.Stdout, res.Stderr)
		}
		res2, _ := sb.Exec(ctx, "curl -sS --max-time 20 http://evil.com/ ; echo EXIT=$?")
		combined := res2.Stdout + res2.Stderr
		blockedAtProxy := strings.Contains(combined, "AEGIS-BLOCKED")
		blockedAtDNS := strings.Contains(combined, "Could not resolve host") &&
			strings.Contains(res2.Stdout, "EXIT=6")
		if !blockedAtProxy && !blockedAtDNS {
			t.Fatalf("plain-http request neither proxy-blocked nor dns-blocked: %q %q",
				res2.Stdout, res2.Stderr)
		}
		ok := pollForEvent(t, eventDir, 12*time.Second, func(e events.Event) bool {
			return e.Source == events.SourceProxy && e.Type == events.TypeNetworkConnect &&
				e.Data["domain"] == "evil.com" && e.Data["decision"] == "block"
		})
		if !ok {
			t.Error("no block event recorded for evil.com")
		}
	})

	t.Run("TEST5_raw_ip_and_direct_bypass", func(t *testing.T) {
		res, err := sb.Exec(ctx,
			"curl -sS --max-time 20 https://1.1.1.1 ; echo RC=$?")
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
		if !strings.Contains(res.Stdout, "RC=56") || !strings.Contains(res.Stderr, "403") {
			t.Fatalf("raw IP via proxy expected 403 refusal, got rc-out=%q stderr=%q",
				res.Stdout, res.Stderr)
		}
		res2, err := sb.Exec(ctx,
			"curl -sS --noproxy '*' -o /dev/null --connect-timeout 5 --max-time 12 https://1.1.1.1 ; echo RC=$?")
		if err != nil {
			t.Fatalf("exec bypass: %v", err)
		}
		if strings.Contains(res2.Stdout, "RC=0") {
			t.Fatal("DIRECT RAW-IP CONNECTION SUCCEEDED — topology bypass!")
		}
		ok := pollForEvent(t, eventDir, 12*time.Second, func(e events.Event) bool {
			return e.Source == events.SourceProxy && e.Data["decision"] == "block" &&
				strings.Contains(e.Severity, "high")
		})
		if !ok {
			t.Error("raw-IP block event (high severity) not recorded")
		}
	})

	t.Run("dns_gate", func(t *testing.T) {
		resBad, _ := sb.Exec(ctx, "getent hosts evil.com >/dev/null 2>&1; echo RC=$?")
		if strings.Contains(resBad.Stdout, "RC=0") {
			t.Error("non-allowlisted domain resolved inside sandbox — DNS gate failed")
		}
		resGood, _ := sb.Exec(ctx, "getent hosts api.anthropic.com >/dev/null 2>&1; echo RC=$?")
		if !strings.Contains(resGood.Stdout, "RC=0") {
			t.Errorf("allowlisted domain failed to resolve: %q %q", resGood.Stdout, resGood.Stderr)
		}
	})
}
