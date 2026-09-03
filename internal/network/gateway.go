package network

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/images"
)

type Gateway struct {
	SessionID string
	Profile   Profile
	NetName   string
	ProxyName string
	ProxyIP   string
	store     *events.Store

	onMu    sync.Mutex
	onEvent func(events.Event)

	logsCmd *exec.Cmd
	logsCxl context.CancelFunc
}

func New(sessionID string, profile Profile, store *events.Store) (*Gateway, error) {
	if _, err := AllowlistFor(profile); err != nil {
		return nil, err
	}
	short := sessionID
	if len(short) > 8 {
		short = short[:8]
	}
	return &Gateway{
		SessionID: sessionID,
		Profile:   profile,
		NetName:   "aegis-net-" + short,
		ProxyName: "aegis-proxy-" + short,
		store:     store,
	}, nil
}

func docker(ctx context.Context, args ...string) ([]byte, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func out3(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := docker(ctx, args...)
	return strings.TrimSpace(string(out)), err
}

func EnsureProxyImage(ctx context.Context) error {
	if _, err := docker(ctx, "image", "inspect", images.ProxyImage); err == nil {
		out, _ := docker(ctx, "image", "inspect", "--format", "{{index .Config.Labels \"com.aegis.build\"}}|{{json .Config.Entrypoint}}", images.ProxyImage)
		parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
		if os.Getenv("AEGIS_REBUILD_PROXY") == "" && len(parts) == 2 && parts[0] == images.BuildVersion && strings.Contains(parts[1], "/aegis-proxy") {
			return nil
		}
	}
	repoRoot := os.Getenv("AEGIS_REPO_ROOT")
	if repoRoot == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		repoRoot = findRepoRoot(wd)
	}
	tmp, err := os.MkdirTemp("", "aegis-proxy-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	binDir := filepath.Join(tmp, "bin")
	ctxDir := filepath.Join(tmp, "ctx")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "aegis-proxy")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-s -w",
		"-o", binPath, "./cmd/aegis-proxy")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("compile aegis-proxy: %w", err)
	}
	if fi, err := os.Stat(binPath); err != nil || fi.Size() < 1024*1024 {
		return fmt.Errorf("compiled proxy binary missing or suspiciously small (%v)", fi)
	}

	buildCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := images.WriteProxyContext(ctxDir, binPath); err != nil {
		return err
	}
	out, err := docker(buildCtx, "build", "-t", images.ProxyImage,
		"--label", "com.aegis.managed=true", "--label", "com.aegis.resource=proxy-image",
		"--label", "com.aegis.build="+images.BuildVersion, ctxDir)
	if err != nil {
		return fmt.Errorf("proxy image build failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func installedProxyBinary() string {
	if configured := os.Getenv("AEGIS_PROXY_BIN"); configured != "" {
		if info, err := os.Stat(configured); err == nil && info.Mode()&0111 != 0 {
			return configured
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	candidate := filepath.Join(filepath.Dir(exe), "..", "lib", "aegis", "aegis-proxy")
	if info, err := os.Stat(candidate); err == nil && info.Mode()&0111 != 0 {
		return candidate
	}
	return ""
}

func findRepoRoot(start string) string {
	dir := start
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "cmd", "aegis-proxy")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return start
}

func (g *Gateway) SetOnEvent(fn func(events.Event)) {
	g.onMu.Lock()
	g.onEvent = fn
	g.onMu.Unlock()
}

func (g *Gateway) eventHandler() func(events.Event) {
	g.onMu.Lock()
	defer g.onMu.Unlock()
	return g.onEvent
}

func (g *Gateway) emit(typ, severity string, data map[string]any) {
	if g.store == nil {
		return
	}
	ev := events.New(events.SourceSandbox, typ, severity, "aegis", g.SessionID, data)
	_ = g.store.Append(ev)
}

func (g *Gateway) Up(ctx context.Context) error {
	if err := EnsureProxyImage(ctx); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	_, _ = docker(cctx, "rm", "-f", g.ProxyName)
	_, _ = docker(cctx, "network", "rm", g.NetName)
	if out, err := docker(cctx, "network", "create", "--internal", "--driver", "bridge",
		"--label", "com.aegis.managed=true", "--label", "com.aegis.resource=session-network", g.NetName); err != nil {
		return fmt.Errorf("create internal network: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	g.emit("gateway.up", events.SevInfo, map[string]any{"network": g.NetName})

	allowlist, _ := AllowlistFor(g.Profile)
	runArgs := []string{
		"run", "-d",
		"--name", g.ProxyName,
		"--label", "com.aegis.managed=true",
		"--label", "com.aegis.resource=proxy",
		"--label", "com.aegis.session=" + g.SessionID,
		"--network", g.NetName,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--restart", "no",
		"--env", "AEGIS_ALLOWLIST=" + strings.Join(allowlist, ","),
		images.ProxyImage,
	}
	if out, err := docker(cctx, runArgs...); err != nil {
		return fmt.Errorf("start proxy sidecar: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	if _, err := docker(cctx, "network", "connect", "bridge", g.ProxyName); err != nil {
		return fmt.Errorf("attach proxy egress uplink: %w", err)
	}

	ip, err := g.pollProxyIP(ctx)
	if err != nil {
		logsOut, _ := docker(ctx, "logs", "--tail", "5", g.ProxyName)
		return fmt.Errorf("resolve proxy IP: %w (status=%v logs=%s)", err,
			containerStatus(g.ProxyName), strings.TrimSpace(string(logsOut)))
	}
	g.ProxyIP = ip

	g.startLogStream()
	g.waitForProxyReady(ctx)
	g.emit("gateway.ready", events.SevInfo, map[string]any{
		"proxy":     g.ProxyName,
		"ip":        g.ProxyIP,
		"allowlist": allowlist,
	})
	return nil
}

type inspectNetEntry struct {
	IPAddress string `json:"IPAddress"`
}

type inspectNetworks struct {
	NetworkSettings struct {
		Networks map[string]inspectNetEntry `json:"Networks"`
	} `json:"NetworkSettings"`
	State struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
	} `json:"State"`
}

func containerStatus(name string) string {
	out, err := out3("inspect", "--format", "{{.State.Status}} exit={{.State.ExitCode}}", name)
	if err != nil {
		return "unknown"
	}
	return out
}

func (g *Gateway) pollProxyIP(ctx context.Context) (string, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return "", err
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.CommandContext(ctx, bin, "inspect", g.ProxyName)
		out, err := cmd.Output()
		if err == nil {
			var items []inspectNetworks
			if jerr := json.Unmarshal(out, &items); jerr == nil && len(items) == 1 {
				entry := items[0].NetworkSettings.Networks[g.NetName]
				ip := strings.TrimSpace(entry.IPAddress)
				if ip != "" && items[0].State.Running {
					return ip, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("proxy never received an IP on %s", g.NetName)
}

func (g *Gateway) waitForProxyReady(ctx context.Context) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(g.ProxyIP, "3128"), time.Second)
		if err == nil {
			conn.Close()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
}

type proxyLogLine struct {
	Time     string `json:"time"`
	Kind     string `json:"kind"`
	Domain   string `json:"domain"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func severityFor(l proxyLogLine) string {
	switch l.Decision {
	case "allow":
		return events.SevInfo
	default:
		if l.Kind == "dns" {
			return events.SevLow
		}
		reason := strings.ToLower(l.Reason)
		if strings.Contains(reason, "raw ip") || strings.Contains(reason, "private") ||
			strings.Contains(reason, "loopback") {
			return events.SevHigh
		}
		return events.SevMedium
	}
}

func (l proxyLogLine) toCanonical(sessionID string) events.Event {
	data := map[string]any{
		"domain":   l.Domain,
		"port":     l.Port,
		"decision": l.Decision,
		"reason":   l.Reason,
		"layer":    l.Kind,
	}
	if l.IP != "" {
		data["ip"] = l.IP
	}
	return events.New(events.SourceProxy, events.TypeNetworkConnect, severityFor(l), "egress-gateway", sessionID, data)
}

func (g *Gateway) startLogStream() {
	ctx, cancel := context.WithCancel(context.Background())
	g.logsCxl = cancel
	bin, err := exec.LookPath("docker")
	if err != nil {
		cancel()
		return
	}
	cmd := exec.CommandContext(ctx, bin, "logs", "-f", "--tail", "0", g.ProxyName)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return
	}
	g.logsCmd = cmd
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var l proxyLogLine
			if json.Unmarshal([]byte(line), &l) != nil || l.Domain == "" {
				continue
			}
			if g.store != nil {
				ev := l.toCanonical(g.SessionID)
				_ = g.store.Append(ev)
				if fn := g.eventHandler(); fn != nil {
					fn(ev)
				}
			}
		}
	}()
}

func (g *Gateway) AgentNetworkArgs() []string {
	return []string{
		"--network", g.NetName,
		"--dns", g.ProxyIP,
		"--env", "HTTPS_PROXY=http://" + g.ProxyIP + ":3128",
		"--env", "HTTP_PROXY=http://" + g.ProxyIP + ":3128",
		"--env", "NO_PROXY=",
	}
}

func (g *Gateway) Down(ctx context.Context) error {
	if g.logsCxl != nil {
		g.logsCxl()
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var errs []error
	if _, err := docker(cctx, "rm", "-f", g.ProxyName); err != nil {
		errs = append(errs, fmt.Errorf("remove proxy: %w", err))
	}
	if _, err := docker(cctx, "network", "rm", g.NetName); err != nil {
		errs = append(errs, fmt.Errorf("remove network: %w", err))
	} else {
		g.emit("gateway.down", events.SevInfo, map[string]any{"network": g.NetName})
	}
	switch len(errs) {
	case 0:
		return nil
	default:
		return errs[0]
	}
}
