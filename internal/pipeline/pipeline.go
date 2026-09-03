// Package pipeline orchestrates the complete AEGIS runtime lifecycle for a
// single controlled-agent session:
//
//	ENTRY GATE → SNAPSHOT → SANDBOX → AGENT → ACTIVE
//	  └ concurrent monitoring: hook tailer + proxy log stream + correlator
//	→ AGENT_FINISHED → SECURITY_SCAN → PREFLIGHT → BLOCK | PASS
//	→ cleanup / finalize
//
// The workspace model is direct-mount: the launch directory (PROJECT_ROOT) is
// itself the sandbox's /workspace. "SNAPSHOTTING_PROJECT" therefore baselines
// the live project with an audit manifest (never a copy); the agent edits the
// real project inside the container, and the verified diff is the session's
// change set against that baseline.
//
// The orchestrator drives real components (sandbox, network gateway, event
// store, preflight scanners) but declares them through narrow interfaces so
// the flow can be unit-tested with fakes. It never fakes events: every step
// operates on the active session_id and writes to the real session store.
package pipeline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/eth0x1/aegis/internal/agents"
	"github.com/eth0x1/aegis/internal/correlate"
	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/exitgate"
	"github.com/eth0x1/aegis/internal/findings"
	"github.com/eth0x1/aegis/internal/images"
	"github.com/eth0x1/aegis/internal/network"
	"github.com/eth0x1/aegis/internal/observer"
	"github.com/eth0x1/aegis/internal/paths"
	"github.com/eth0x1/aegis/internal/preflight"
	"github.com/eth0x1/aegis/internal/response"
	"github.com/eth0x1/aegis/internal/sandbox"
	"github.com/eth0x1/aegis/internal/session"
	"github.com/eth0x1/aegis/internal/workspace"
)

// Gateway abstracts the network sidecar for the orchestrator.
type Gateway interface {
	Up(ctx context.Context) error
	Down(ctx context.Context) error
	AgentNetworkArgs() []string
	SetOnEvent(func(events.Event))
}

// Sandbox abstracts the Docker container lifecycle.
type Sandbox interface {
	Start(ctx context.Context) error
	Kill(ctx context.Context) error
	SetupWorkspaceJail() error
	ExecInteractive(command []string) int
	Inspect(ctx context.Context) ([]byte, error)
	Commit(ctx context.Context, ref string) error
	ContainerName() string
	SetNetworkArgs(args []string)
}

// InteractiveOptions carries everything the interactive UI/provider needs to
// run the agent inside the sandbox for the duration of the ACTIVE state.
type InteractiveOptions struct {
	Sandbox Sandbox
	Manager *session.Manager
	Feed    *observer.Feed
	Args    []string
	Profile string
}

// InteractiveFunc runs the agent interactively and returns its exit code.
type InteractiveFunc func(ctx context.Context, opts InteractiveOptions) int

type RunOptions struct {
	ProjectRoot   string
	Agent         string
	Profile       string
	Args          []string
	Interactive   InteractiveFunc
	NewGateway    func(sessionID string, profile network.Profile, store *events.Store) (Gateway, error)
	NewSandbox    func(sessionID, workspace string, store *events.Store) Sandbox
	Print         func(format string, a ...any)
	PreflightExec preflight.ExecFunc
	// StateRoot overrides the session state directory (defaults to
	// paths.StateDir()); primarily for tests.
	StateRoot string
	// OnBlock runs while the session store is still open when the exit gate
	// blocks; OnPass runs for a clean PASS. Both are advisory callbacks.
	OnBlock func(ctx context.Context, mgr *session.Manager, ws string, final *preflight.FinalResult)
	OnPass  func(ctx context.Context, mgr *session.Manager, ws string, final *preflight.FinalResult)

	// ExitGate optionally enables the Local AI exit security review. It is
	// constructed with the session id and store (so model events carry the
	// session id) and runs ONLY after the deterministic preflight checks have
	// passed. A nil field keeps deterministic-only behavior. The returned
	// gate may be nil to disable the review for that session.
	ExitGate func(sessionID string, store *events.Store) *exitgate.Gate
}

type RunResult struct {
	SessionID string
	State     session.State
	Outcome   string
	ExitCode  int
	Final     *preflight.FinalResult
}

func (r *RunResult) ShortID() string {
	if len(r.SessionID) > 8 {
		return r.SessionID[:8]
	}
	return r.SessionID
}

func (r RunOptions) print(format string, a ...any) {
	if r.Print != nil {
		r.Print(format, a...)
	} else {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}

// Run executes the complete lifecycle for one session. It creates a fresh
// session id, propagates it to every component, keeps monitoring active
// while the agent runs, enforces the preflight exit gate, and finalizes.
func Run(ctx context.Context, opts RunOptions) (*RunResult, error) {
	if opts.Profile == "" {
		opts.Profile = "strict"
	}
	if opts.Interactive == nil {
		opts.Interactive = defaultInteractive
	}
	if opts.StateRoot == "" {
		opts.StateRoot = paths.StateDir()
	}

	res := &RunResult{}

	// ---------------------------------------------------------------- ENTRY GATE
	mgr, err := session.Create(opts.StateRoot, opts.ProjectRoot, opts.Agent, opts.Profile)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	defer mgr.Close()
	snap := mgr.Snapshot()
	res.SessionID = snap.SessionID
	res.State = snap.State

	// ---------------------------------------------------------- SNAPSHOTTING_PROJECT
	// Direct-mount model: the launch directory IS the sandbox workspace. The
	// snapshot phase baselines the live project with an audit manifest for
	// the verified diff — it never copies project content anywhere. The agent
	// edits the real project through the container's /workspace mount.
	if err := mgr.Transition(session.StateSnapshotting, nil); err != nil {
		return res, err
	}
	opts.print("  PREPARE_WORKSPACE  Preparing workspace...\n")
	ws := opts.ProjectRoot
	manifest, err := workspace.BuildManifest(ws)
	if err != nil {
		return res, fmt.Errorf("baseline project: %w", err)
	}
	if err := mgr.SetWorkspace(ws); err != nil {
		return res, err
	}
	if err := workspace.SaveManifest(mgr.Dir(), manifest); err != nil {
		return res, err
	}
	opts.print("workspace:   %s (in place, %d entries baselined)\n", ws, len(manifest))

	// Observation hooks are always injected before the agent starts:
	// they write .aegis/bin/hook.sh, .claude/settings.json and
	// .opencode/config.json into the project, and the live monitor
	// consumes the JSONL they emit.
	if err := observer.InjectHooks(ws); err != nil {
		return res, fmt.Errorf("inject observation hooks: %w", err)
	}
	opts.print("hooks:       observation hooks injected\n")

	opts.print("  CHECK_DOCKER       Checking Docker...\n")
	if err := checkDockerAccess(); err != nil {
		return res, fmt.Errorf("docker: %w", err)
	}
	opts.print("  [OK] Docker\n")

	// ------------------------------------------------------------- network gateway
	gw, err := opts.gatewayFor(mgr)
	if err != nil {
		return res, err
	}
	opts.print("  PREPARE_NETWORK    Preparing network policy and security proxy...\n")
	opts.print("  START_PROXY        Starting security proxy and egress network...\n")
	if err := gw.Up(ctx); err != nil {
		return res, fmt.Errorf("start network gateway: %w", err)
	}
	opts.print("  [OK] Network policy and security proxy\n")
	defer gw.Down(ctx)

	// ------------------------------------------------------------------ sandbox
	sb := opts.sandboxFor(mgr, ws)
	if opts.Agent != "" {
		if a, err := agents.Detect(opts.Agent); err == nil {
			if concrete, ok := sb.(*sandbox.Sandbox); ok {
				concrete.AgentBin = a.BinaryPath
				concrete.AgentBins[opts.Agent] = a.BinaryPath
			}
		}
	}
	sb.SetNetworkArgs(gw.AgentNetworkArgs())
	if opts.Agent != "" {
		if a, err := agents.Detect(opts.Agent); err == nil {
			opts.print("agent:       %s (%s)\n", opts.Agent, a.BinaryPath)
		}
	}
	if err := mgr.Transition(session.StateSandboxStarted, nil); err != nil {
		return res, err
	}
	opts.print("  PREPARE_SANDBOX    Preparing hardened sandbox...\n")
	if err := sb.Start(ctx); err != nil {
		return res, fmt.Errorf("start sandbox: %w", err)
	}
	defer sb.Kill(ctx)
	res.State = session.StateSandboxStarted
	opts.print("  [OK] Sandbox (%s)\n", sb.ContainerName())

	if err := sb.SetupWorkspaceJail(); err != nil {
		opts.print("warning: workspace jail setup failed: %v\n", err)
	}
	opts.print("  [OK] Security initialization\n")

	// ------------------------------------------------------------------- agent
	if err := mgr.Transition(session.StateAgentStarted, map[string]any{
		"container": sb.ContainerName(),
		"shell":     len(opts.Args) == 0,
	}); err != nil {
		return res, err
	}

	// --------------------------------------------- simultaneous live monitoring
	feed := observer.NewFeed(500)
	corrEngine := correlate.NewEngine(snap.SessionID, correlate.DefaultWindow)
	monitor := newMonitor(ctx, mgr, sb, ws, manifest, feed, corrEngine)

	gw.SetOnEvent(monitor.onGatewayEvent)
	hookPath := observer.RawLogPath(ws)
	tailer := monitor.startHookTailer(hookPath)

	// monCtl runs the live monitor across every interactive agent phase
	// (the initial run plus any remediation rounds) and flushes it between
	// phases, so a scan never runs while the agent process is alive.
	monCtl := &monitorController{mon: monitor, tailer: tailer}
	monCtl.startMonitor()
	defer monCtl.close()

	// ---------------------------------------------------------------- ACTIVE
	if err := mgr.Transition(session.StateActive, nil); err != nil {
		return res, err
	}
	res.State = session.StateActive

	shellArgs := opts.Args
	if len(shellArgs) == 0 {
		shellArgs = []string{"bash", "--rcfile", "/tmp/.aegis-jailrc"}
		opts.print("\n[aegis sandbox %s] (type 'exit' to quit)\n\n", res.ShortID())
	}
	interactiveOpts := InteractiveOptions{
		Sandbox: sb,
		Manager: mgr,
		Feed:    feed,
		Args:    shellArgs,
		Profile: opts.Profile,
	}
	if len(opts.Args) > 0 {
		opts.print("Launching %s...\n", opts.Args[0])
	}
	// Wait here for the agent to actually finish. The preflight gate below
	// never sees the workspace while the agent process is still running.
	exitCode := opts.Interactive(ctx, interactiveOpts)
	res.ExitCode = exitCode
	monCtl.stopMonitor()

	// ----------------------------------------------------------- AGENT_FINISHED
	if err := mgr.Transition(session.StateAgentFinished, map[string]any{"exit_code": exitCode}); err != nil {
		return res, err
	}
	opts.print("\n")
	res.State = session.StateAgentFinished

	// ------------------------------------------------------------- SECURITY_SCAN
	if err := mgr.Transition(session.StateSecurityScan, nil); err != nil {
		return res, err
	}
	allEvents, _ := events.ReadAll(mgr.Dir())
	incidents := correlate.EvaluateAll(snap.SessionID, allEvents, correlate.DefaultWindow)
	if len(incidents) > 0 {
		opts.print("security:    %d incident(s) detected\n", len(incidents))
		for _, inc := range incidents {
			monitor.handleIncident(ctx, inc)
		}
		snap2 := mgr.Snapshot()
		if snap2.State == session.StateTerminated || snap2.State == session.StateFailed {
			res.State = snap2.State
			res.Outcome = snap2.Outcome
			return res, fmt.Errorf("session terminated due to security incident")
		}
	}

	// ---------------------------------------------------------------- PREFLIGHT
	if err := mgr.Transition(session.StatePreflight, nil); err != nil {
		return res, err
	}
	opts.print("preflight:   running security scan...\n")
	final, err := runPreflightGate(ctx, opts, mgr, ws, sb, feed, monCtl, interactiveOpts, res)
	if err != nil {
		opts.print("preflight:   error: %v\n", err)
		_ = mgr.Transition(session.StateFailed, map[string]any{"error": err.Error()})
		res.State = session.StateFailed
		res.Outcome = "failed"
		return res, fmt.Errorf("preflight scan failed: %w", err)
	}
	res.Final = final

	// --------------------------------------------------------------- BLOCK | PASS
	if !final.Passed {
		blockReason := "BLOCKED"
		if final.AIBlocked && final.Last != nil && final.Last.Blocking == 0 {
			blockReason = "exit security review blocked"
		}
		if err := mgr.Transition(session.StateBlock, map[string]any{
			"cycles":        final.Cycles,
			"blocking_last": final.Last.Blocking,
			"total_last":    final.Last.Total,
			"ai_blocked":    final.AIBlocked,
			"reason":        blockReason,
		}); err != nil {
			return res, err
		}
		_ = mgr.SetOutcome("blocked")
		_ = preflight.WriteFindingsArtifact(mgr.Dir(), final.AllResults)
		if opts.OnBlock != nil {
			opts.OnBlock(ctx, mgr, ws, final)
		}

		res.State = session.StateBlock
		res.Outcome = "blocked"
		if final.AIBlocked && final.Last != nil && final.Last.Blocking == 0 && final.Last.Total == 0 {
			return res, fmt.Errorf("EXIT SECURITY REVIEW BLOCKED (%d AI finding(s))", len(final.AIFindings))
		}
		return res, fmt.Errorf("PREFLIGHT BLOCKED — %d blocking finding(s)", final.Last.Blocking)
	}

	if err := mgr.Transition(session.StatePass, map[string]any{"cycles": final.Cycles}); err != nil {
		return res, err
	}
	_ = mgr.SetOutcome("verified")
	res.State = session.StatePass
	res.Outcome = "verified"

	if before, verr := workspace.LoadManifest(mgr.Dir()); verr == nil {
		if vd, derr := preflight.GenerateVerifiedDiff(snap.SessionID, before, ws, final.Cycles); derr == nil {
			_ = preflight.WriteVerifiedArtifacts(mgr.Dir(), vd)
		}
	}
	if opts.OnPass != nil {
		opts.OnPass(ctx, mgr, ws, final)
	}
	return res, nil
}

func (opts RunOptions) gatewayFor(mgr *session.Manager) (Gateway, error) {
	snap := mgr.Snapshot()
	profile := network.ProfileStrict
	if opts.Profile == "dev" {
		profile = network.ProfileDev
	}
	if opts.NewGateway != nil {
		return opts.NewGateway(snap.SessionID, profile, mgr.Store())
	}
	return network.New(snap.SessionID, profile, mgr.Store())
}

func (opts RunOptions) sandboxFor(mgr *session.Manager, ws string) Sandbox {
	snap := mgr.Snapshot()
	if opts.NewSandbox != nil {
		sb := opts.NewSandbox(snap.SessionID, ws, mgr.Store())
		return sb
	}
	sb := sandbox.New(snap.SessionID, ws, mgr.Store())
	// The sandbox runs from the minimal hardened runtime image — a pruned
	// filesystem with no /home, /var, /root, /srv, /opt and with an
	// unreadable /etc/passwd — enforced by the filesystem itself. The tool
	// image (images.AgentImage) is only the source the runtime image is
	// derived from and must never be mounted as the container root.
	sb.Image = images.RuntimeImage
	sb.AgentBins = make(map[string]string)
	for _, name := range agents.ListAvailable() {
		if a, err := agents.Detect(name); err == nil {
			sb.AgentBins[name] = a.BinaryPath
		}
	}
	return sb
}

// defaultInteractive falls back to the full-screen PTY passthrough when the
// caller does not supply a custom interactive function (e.g. the TUI).
func defaultInteractive(_ context.Context, opts InteractiveOptions) int {
	args := opts.Args
	return opts.Sandbox.ExecInteractive(args)
}

// monitorController keeps the live monitor (hook tailer + proxy stream +
// correlator) running across every interactive agent phase — the initial run
// plus each remediation round — and flushes it between phases so the preflight
// gate always scans a workspace whose agent process has already exited.
type monitorController struct {
	mon    *monitor
	tailer *observer.Tailer
	stop   func()
}

func (c *monitorController) startMonitor() {
	if c.stop != nil {
		c.stop()
	}
	c.stop = c.mon.goRun(2 * time.Second)
}

func (c *monitorController) stopMonitor() {
	if c.stop != nil {
		c.stop()
		c.stop = nil
	}
}

func (c *monitorController) close() {
	c.stopMonitor()
	if c.tailer != nil {
		c.tailer.Stop()
	}
}

// runPreflightGate implements the exit gate. It is strictly sequential: the
// agent has already exited before cycle 1 scans. On a BLOCK it writes the
// structured fix request into the workspace and — because remediation must
// happen in the SAME session_id and SAME workspace — relaunches the agent
// interactively before the next scan. A bare shell session (no agent command)
// is never auto-relaunched: it is reported immediately and left for the user
// to fix and re-run.
//
// Remediation rounds follow the legal state path
//
//	PREFLIGHT → BLOCK → ACTIVE → AGENT_FINISHED → PREFLIGHT
//
// so the session timeline records each fix iteration on the same session id.
func runPreflightGate(ctx context.Context, opts RunOptions, mgr *session.Manager, ws string,
	sb Sandbox, feed *observer.Feed, monCtl *monitorController, iopts InteractiveOptions, res *RunResult,
) (*preflight.FinalResult, error) {
	final := &preflight.FinalResult{}
	po := preflight.RunOptions{SessionID: mgr.Snapshot().SessionID, Store: mgr.Store()}

	// The Local AI exit security review is an additive layer on top of the
	// deterministic exit gate. It is constructed with the session id and
	// store so its model events carry the same session lineage, and it only
	// ever runs AFTER a cycle's deterministic checks have passed.
	var gate *exitgate.Gate
	if opts.ExitGate != nil {
		gate = opts.ExitGate(mgr.Snapshot().SessionID, mgr.Store())
		if gate == nil {
			opts.print("exit-review: disabled for this session\n")
		}
	}

	for cycle := 1; cycle <= preflight.MaxCycles; cycle++ {
		opts.print("preflight:   cycle %d/%d\n", cycle, preflight.MaxCycles)
		po.Cycle = cycle
		r, err := preflight.RunScan(ctx, ws, po, opts.PreflightExec)
		if err != nil {
			return final, err
		}
		r.Cycle = cycle
		final.AllResults = append(final.AllResults, r)
		final.Last = r
		final.Cycles = cycle

		// Deterministic block: the local AI review is skipped entirely (it
		// could never override this) and the deterministic findings drive
		// the remediation round.
		detBlock := r.Blocking > 0
		aiBlock := false
		var aiReview *exitgate.Review
		if !detBlock && gate != nil {
			ev, err := exitgate.BuildEvidence(ctx, exitgate.Input{
				SessionID:  mgr.Snapshot().SessionID,
				SessionDir: mgr.Dir(),
				Workspace:  ws,
				Cycle:      cycle,
				Task:       strings.Join(opts.Args, " "),
				Profile:    opts.Profile,
				Findings:   allFindings(final),
			})
			if err != nil {
				opts.print("exit-review: evidence build failed (%v) — treating review as unavailable\n", err)
			}
			aiReview = gate.Review(ctx, ev)
			final.AIBlocked = aiReview.Decision != exitgate.Pass
			final.AIFindings = aiReview.Findings
			final.AIRisk = aiReview.Risk
			final.AISummary = aiReview.Summary
			final.AIUnavailable = aiReview.Unavailable
			aiBlock = final.AIBlocked
			switch {
			case aiReview.Unavailable:
				opts.print("exit-review: WARNING — local AI security review unavailable (%s); decision=%s\n",
					aiReview.Summary, aiReview.Decision)
			case aiBlock:
				opts.print("exit-review: BLOCK (risk %s)\n", orNA(aiReview.Risk))
			default:
				opts.print("exit-review: PASS%s\n", cacheNote(aiReview))
			}
		}
		if !detBlock && !aiBlock {
			final.Passed = true
			return final, nil
		}

		// BLOCK: hand concise remediation input back to the workspace so the
		// relaunched agent can act on it in the same session.
		if detBlock {
			opts.print("preflight:   BLOCK (%d blocking finding(s)) — fix request written\n", r.Blocking)
			if err := preflight.WriteFixRequest(mgr.Dir(), ws, cycle, r); err != nil {
				opts.print("preflight:   warning: fix request not written: %v\n", err)
			}
		} else {
			opts.print("preflight:   EXIT REVIEW BLOCKED — concise remediation findings written\n")
			if err := exitgate.WriteFixRequest(mgr.Dir(), ws, cycle, aiReview); err != nil {
				opts.print("preflight:   warning: exit-review fix request not written: %v\n", err)
			}
		}

		if cycle == preflight.MaxCycles {
			break
		}
		if len(opts.Args) == 0 {
			// No agent attached: this is an interactive shell. Do not
			// re-scan an unchanged workspace; report and stop.
			opts.print("preflight:   no agent attached — fix the workspace and re-run\n")
			break
		}

		// Remediation round: BLOCK → ACTIVE, restore monitoring, and wait
		// for the agent to edit /workspace before the next scan.
		if err := mgr.Transition(session.StateBlock, map[string]any{
			"cycle": cycle, "blocking": r.Blocking, "total": r.Total,
		}); err != nil {
			opts.print("preflight:   warning: %v\n", err)
		}
		if err := mgr.Transition(session.StateActive, map[string]any{"remediation": cycle}); err != nil {
			return final, err
		}
		opts.print("preflight:   BLOCK — relaunching agent for remediation round %d\n", cycle)
		monCtl.startMonitor()
		code := opts.Interactive(ctx, iopts)
		monCtl.stopMonitor()
		res.ExitCode = code
		if err := mgr.Transition(session.StateAgentFinished, map[string]any{
			"exit_code": code, "remediation": cycle,
		}); err != nil {
			return final, err
		}
		if err := mgr.Transition(session.StatePreflight, map[string]any{"remediation": cycle}); err != nil {
			return final, err
		}
	}
	return final, nil
}

// allFindings aggregates every unique finding across the remediation cycles
// so the exit review sees the complete audit trail (earlier blocks plus the
// current state), deduplicated by rule/file/line/message.
func allFindings(final *preflight.FinalResult) []findings.Finding {
	if final == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []findings.Finding
	for _, r := range final.AllResults {
		for _, f := range r.Findings {
			key := f.Rule + "|" + f.File + "|" + itoa(f.Line) + "|" + f.Message
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

func cacheNote(r *exitgate.Review) string {
	if r.Cached {
		return " (cached — unchanged evidence)"
	}
	return ""
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// monitor ties the hook tailer, proxy log stream and correlation engine
// together with the session store and incident responder.
type monitor struct {
	ctx       context.Context
	mgr       *session.Manager
	sb        Sandbox
	ws        string
	manifest  workspace.Manifest
	feed      *observer.Feed
	corr      *correlate.Engine
	tailer    *observer.Tailer
	incidents []*correlate.Incident
}

func newMonitor(ctx context.Context, mgr *session.Manager, sb Sandbox, ws string,
	manifest workspace.Manifest, feed *observer.Feed, corr *correlate.Engine) *monitor {
	return &monitor{ctx: ctx, mgr: mgr, sb: sb, ws: ws, manifest: manifest, feed: feed, corr: corr}
}

func (m *monitor) startHookTailer(path string) *observer.Tailer {
	t := observer.StartTailer(path, m.mgr.Store(), m.feed)
	t.SetOnEvent(m.onHookEvent)
	m.tailer = t
	return t
}

func (m *monitor) goRun(interval time.Duration) func() {
	monitorCtx, cancel := context.WithCancel(m.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if m.tailer != nil {
			m.tailer.Run(monitorCtx, interval)
		}
	}()
	return func() { cancel(); <-done }
}

func (m *monitor) onGatewayEvent(ev events.Event) {
	if m.feed != nil {
		m.feed.Publish(ev)
	}
	if inc := m.corr.Observe(ev); inc != nil {
		m.handleIncident(m.ctx, inc)
	}
}

func (m *monitor) onHookEvent(ev events.Event) {
	if inc := m.corr.Observe(ev); inc != nil {
		m.handleIncident(m.ctx, inc)
	}
}

func (m *monitor) handleIncident(ctx context.Context, inc *correlate.Incident) {
	m.incidents = append(m.incidents, inc)
	store := m.mgr.Store()
	if store == nil {
		return
	}
	responder := &response.Responder{
		Ctrl:       m.sb,
		Mgr:        m.mgr,
		Store:      store,
		SessionDir: m.mgr.Dir(),
		Workspace:  m.ws,
		Manifest:   m.manifest,
	}
	finding := response.Finding{Severity: "critical", Incident: *inc, Reason: inc.Summary}
	if err := responder.HandleFinding(ctx, finding); err != nil {
		fmt.Printf("warning: incident response failed: %v\n", err)
	}
}

// checkDockerAccess ensures the Docker daemon is reachable and permissioned.
func checkDockerAccess() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.ID}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		low := strings.ToLower(msg + " " + err.Error())
		if strings.Contains(low, "permission denied") {
			return fmt.Errorf("permission denied connecting to Docker daemon\n\n" +
				"  Your user is in the docker group but this terminal session\n" +
				"  hasn't loaded the new group membership yet.\n\n" +
				"  Fix: log out and log back in, then re-run this command.\n" +
				"  Or run this first: newgrp docker\n\n" +
				"  Quick test: docker ps")
		}
		return fmt.Errorf("cannot connect to Docker daemon: %s", msg)
	}
	return nil
}
