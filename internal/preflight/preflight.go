package preflight

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/findings"
	"github.com/eth0x1/aegis/internal/workspace"
)

const MaxCycles = 3

type ExecFunc func(ctx context.Context, cmd string) (stdout, stderr string, exitCode int, err error)

type Scanner interface {
	Name() string
	Scan(ctx context.Context, workspace string, exec ExecFunc) ([]findings.Finding, error)
}

type GitleaksScanner struct {
	BinPath string
}

func (g *GitleaksScanner) Name() string { return "gitleaks" }

func (g *GitleaksScanner) Scan(ctx context.Context, workspaceDir string, _ ExecFunc) ([]findings.Finding, error) {
	bin := g.BinPath
	if bin == "" {
		if p, err := exec.LookPath("gitleaks"); err != nil {
			return []findings.Finding{findings.UnavailableFinding("gitleaks",
				"gitleaks not found in PATH; install it to enable secret detection")}, nil
		} else {
			bin = p
		}
	}
	reportPath := filepath.Join(os.TempDir(), fmt.Sprintf("aegis-gitleaks-%d.json", time.Now().UnixNano()))
	defer os.Remove(reportPath)
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "detect",
		"--source", workspaceDir,
		"--no-git",
		"--report-format", "json",
		"--report-path", reportPath,
		"--redact")
	out, err := cmd.CombinedOutput()
	exitErr, isExit := err.(*exec.ExitError)
	switch {
	case err == nil:
	case isExit && exitErr.ExitCode() == 1:
	default:
		return []findings.Finding{findings.UnavailableFinding("gitleaks",
			strings.TrimSpace(string(out)))}, nil
	}
	raw, rerr := os.ReadFile(reportPath)
	if rerr != nil {
		return []findings.Finding{}, nil
	}
	return findings.ParseGitleaks(raw), nil
}

type NpmAuditScanner struct{}

func (n *NpmAuditScanner) Name() string { return "npm-audit" }

func (n *NpmAuditScanner) applicable(workspaceDir string) bool {
	if _, err := os.Stat(filepath.Join(workspaceDir, "package.json")); err != nil {
		return false
	}
	for _, lock := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		if _, err := os.Stat(filepath.Join(workspaceDir, lock)); err == nil {
			return true
		}
	}
	return false
}

func (n *NpmAuditScanner) Scan(ctx context.Context, workspaceDir string, execFn ExecFunc) ([]findings.Finding, error) {
	if !n.applicable(workspaceDir) {
		return []findings.Finding{}, nil
	}
	if execFn == nil {
		return []findings.Finding{findings.SkipFinding("npm-audit",
			"package-lock present but no sandbox executor attached; dependency audit skipped offline")}, nil
	}
	stdout, stderr, code, err := execFn(ctx, "cd /workspace && npm audit --json 2>/dev/null; echo NPMRC=$?")
	if err != nil {
		return []findings.Finding{findings.SkipFinding("npm-audit", "executor error: "+err.Error())}, nil
	}
	if strings.Contains(stdout, "NPMRC=1") || code > 1 && !strings.Contains(stdout, "\"vulnerabilities\"") {
		return []findings.Finding{findings.SkipFinding("npm-audit",
			strings.TrimSpace(lastLine(stderr))+" (registry unreachable in strict profile)")}, nil
	}
	payload := extractJSON(stdout)
	return findings.ParseNpmAudit([]byte(payload)), nil
}

type PipAuditScanner struct{}

func (p *PipAuditScanner) Name() string { return "pip-audit" }

func (p *PipAuditScanner) applicable(workspaceDir string) bool {
	patterns := []string{"requirements*.txt", "pyproject.toml"}
	for _, pat := range patterns {
		if matches, _ := filepath.Glob(filepath.Join(workspaceDir, pat)); len(matches) > 0 {
			return true
		}
	}
	return false
}

func (p *PipAuditScanner) Scan(ctx context.Context, workspaceDir string, execFn ExecFunc) ([]findings.Finding, error) {
	if !p.applicable(workspaceDir) {
		return []findings.Finding{}, nil
	}
	if pip, err := exec.LookPath("pip-audit"); err == nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		reqs, _ := filepath.Glob(filepath.Join(workspaceDir, "requirements*.txt"))
		args := []string{"--format", "json"}
		if len(reqs) > 0 {
			for _, r := range reqs {
				args = append(args, "-r", r)
			}
		} else {
			args = append(args, "--path", workspaceDir)
		}
		out, err := exec.CommandContext(cctx, pip, args...).Output()
		if err != nil && !isExitError(err) {
			return []findings.Finding{findings.SkipFinding("pip-audit", "pip-audit failed: "+err.Error())}, nil
		}
		return findings.ParsePipAudit(out), nil
	}
	if execFn == nil {
		return []findings.Finding{findings.SkipFinding("pip-audit",
			"python project detected but pip-audit unavailable and no sandbox executor attached")}, nil
	}
	stdout, _, _, err := execFn(ctx, "pip-audit --format json 2>/dev/null || python3 -m pip_audit --format json 2>/dev/null; echo true")
	if err != nil {
		return []findings.Finding{findings.SkipFinding("pip-audit", "sandbox executor error")}, nil
	}
	payload := extractJSON(stdout)
	if payload == "" {
		return []findings.Finding{findings.SkipFinding("pip-audit", "no output from sandboxed pip-audit")}, nil
	}
	return findings.ParsePipAudit([]byte(payload)), nil
}

func isExitError(err error) bool {
	_, ok := err.(*exec.ExitError)
	return ok
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func extractJSON(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}
	return s[start:]
}

type Result struct {
	Cycle       int                `json:"cycle"`
	Findings    []findings.Finding `json:"findings"`
	Blocking    int                `json:"blocking"`
	Total       int                `json:"total"`
	Verdict     string             `json:"verdict"`
	ScannersRun []string           `json:"scanners_run"`
	DurationMS  int64              `json:"duration_ms"`
}

type RunOptions struct {
	SessionID string
	Store     *events.Store
	Scanners  []Scanner
	OnFinding func(findings.Finding)
	Cycle     int
}

func RunScan(ctx context.Context, workspaceDir string, opts RunOptions, execFn ExecFunc) (*Result, error) {
	start := time.Now()
	res := &Result{}
	if opts.Scanners == nil {
		opts.Scanners = DefaultScanners()
	}
	for _, sc := range opts.Scanners {
		res.ScannersRun = append(res.ScannersRun, sc.Name())
		fs, err := sc.Scan(ctx, workspaceDir, execFn)
		if err != nil {
			return res, fmt.Errorf("scanner %s: %w", sc.Name(), err)
		}
		res.Findings = append(res.Findings, fs...)
	}
	res.Total = len(res.Findings)
	res.Blocking = findings.CountBlocking(res.Findings)
	if res.Blocking > 0 {
		res.Verdict = "BLOCK"
	} else {
		res.Verdict = "PASS"
	}
	if opts.Cycle > 0 {
		res.Cycle = opts.Cycle
	}
	res.DurationMS = time.Since(start).Milliseconds()

	if opts.Store != nil {
		for _, f := range res.Findings {
			ev := events.New(events.SourceScanner, events.TypeFinding, sevOf(f), "scanner:"+f.Scanner,
				opts.SessionID, map[string]any{
					"finding_id": f.FindingID,
					"blocking":   f.Blocking,
					"file":       f.File,
					"line":       f.Line,
					"rule":       f.Rule,
					"message":    f.Message,
				})
			_ = opts.Store.Append(ev)
			if opts.OnFinding != nil {
				opts.OnFinding(f)
			}
		}
		appendSummary(opts.Store, opts.SessionID, res)
	}
	return res, nil
}

func appendSummary(store *events.Store, sessionID string, res *Result) {
	data := map[string]any{
		"cycle":        res.Cycle,
		"verdict":      res.Verdict,
		"blocking":     res.Blocking,
		"total":        res.Total,
		"scanners_run": res.ScannersRun,
	}
	ev := events.New(events.SourcePolicy, "policy.preflight", verdictSeverity(res), "aegis", sessionID, data)
	_ = store.Append(ev)
}

func verdictSeverity(res *Result) string {
	if res.Verdict == "BLOCK" {
		return events.SevHigh
	}
	return events.SevInfo
}

func sevOf(f findings.Finding) string {
	return f.Severity
}

func DefaultScanners() []Scanner {
	return []Scanner{&GitleaksScanner{}, &NpmAuditScanner{}, &PipAuditScanner{}}
}

type LoopCallbacks struct {
	BeforeCycle       func(ctx context.Context, cycle int) error
	PublishFixRequest func(ctx context.Context, cycle int, res *Result) error
	BeforeRescan      func(ctx context.Context, cycle int) error
}

type FinalResult struct {
	Passed     bool
	Cycles     int
	Last       *Result
	AllResults []*Result

	// Exit-gate Local AI review outcome. Populated only when the exit gate
	// is enabled and the deterministic checks passed; the AI review can
	// never override a deterministic block.
	AIBlocked     bool     `json:"-"`
	AIFindings    []string `json:"-"`
	AIRisk        string   `json:"-"`
	AISummary     string   `json:"-"`
	AIUnavailable bool     `json:"-"`
}

func RunLoop(ctx context.Context, workspaceDir string, opts RunOptions, cb LoopCallbacks, execFn ExecFunc) (*FinalResult, error) {
	final := &FinalResult{}
	for cycle := 1; cycle <= MaxCycles; cycle++ {
		if cb.BeforeCycle != nil {
			if err := cb.BeforeCycle(ctx, cycle); err != nil {
				return final, fmt.Errorf("pre-cycle hook: %w", err)
			}
		}
		opts.Cycle = cycle
		res, err := RunScan(ctx, workspaceDir, opts, execFn)
		if err != nil {
			return final, err
		}
		res.Cycle = cycle
		final.AllResults = append(final.AllResults, res)
		final.Last = res
		final.Cycles = cycle
		if res.Verdict == "PASS" {
			final.Passed = true
			return final, nil
		}
		if cycle == MaxCycles {
			break
		}
		if cb.PublishFixRequest != nil {
			if err := cb.PublishFixRequest(ctx, cycle, res); err != nil {
				return final, fmt.Errorf("publish fix request: %w", err)
			}
		}
		if cb.BeforeRescan != nil {
			if err := cb.BeforeRescan(ctx, cycle); err != nil {
				return final, fmt.Errorf("pre-rescan hook: %w", err)
			}
		}
	}
	return final, nil
}

func WriteFixRequest(sessionDir, workspace string, cycle int, res *Result) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# AEGIS PreFlight: changes BLOCKED (fix cycle %d/%d)\n\n", cycle, MaxCycles)
	fmt.Fprintf(&b, "%d blocking finding(s). Fix the items below, then AEGIS will rescan.\n\n", res.Blocking)
	for _, f := range res.Findings {
		if !f.Blocking {
			continue
		}
		loc := f.File
		if loc == "" {
			loc = "(project)"
		}
		fmt.Fprintf(&b, "- [%s] %s:%d rule=%s — %s\n", strings.ToUpper(f.Severity), loc, f.Line, f.Rule, f.Message)
	}
	path := filepath.Join(workspace, ".aegis", "FIX_REQUEST.md")
	os.MkdirAll(filepath.Dir(path), 0o700)
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

type ChangeRecord struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

type VerifiedDiff struct {
	SessionID string         `json:"session_id"`
	CreatedAt string         `json:"created_at"`
	Cycles    int            `json:"preflight_cycles"`
	Changes   []ChangeRecord `json:"changes"`
	Summary   map[string]int `json:"summary"`
}

func GenerateVerifiedDiff(sessionID string, before workspace.Manifest, workspaceDir string, cycles int) (*VerifiedDiff, error) {
	changes, _, err := workspace.ComputeDiff(before, workspaceDir)
	if err != nil {
		return nil, fmt.Errorf("verified diff: %w", err)
	}
	vd := &VerifiedDiff{
		SessionID: sessionID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Cycles:    cycles,
		Summary:   map[string]int{},
	}
	var txt strings.Builder
	txt.WriteString(fmt.Sprintf("# AEGIS verified diff (%d preflight cycle(s))\n\n", cycles))
	for _, ch := range changes {
		vd.Changes = append(vd.Changes, ChangeRecord{Path: ch.Path, Kind: string(ch.Kind)})
		vd.Summary[string(ch.Kind)]++
		fmt.Fprintf(&txt, "%s\t%s\n", ch.Kind, ch.Path)
	}
	return vd, nil
}

func WriteVerifiedArtifacts(sessionDir string, vd *VerifiedDiff) error {
	jb, err := json.MarshalIndent(vd, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "verified-diff.json"), append(jb, '\n'), 0o600); err != nil {
		return err
	}
	os.Chmod(filepath.Join(sessionDir, "verified-diff.json"), 0o600)

	var txt strings.Builder
	txt.WriteString(fmt.Sprintf("# AEGIS verified diff (%d preflight cycle(s))\n\n", vd.Cycles))
	for _, c := range vd.Changes {
		fmt.Fprintf(&txt, "%s\t%s\n", c.Kind, c.Path)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "verified-diff.txt"), []byte(txt.String()), 0o600); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(sessionDir, "verified-diff.txt"), 0o600)
}

type findingsExport struct {
	SessionID string                `json:"session_id"`
	Cycles    int                   `json:"cycles"`
	Passed    bool                  `json:"passed"`
	Results   []findingsExportCycle `json:"results"`
}

type findingsExportCycle struct {
	Cycle    int                `json:"cycle"`
	Verdict  string             `json:"verdict"`
	Blocking int                `json:"blocking"`
	Total    int                `json:"total"`
	Findings []findings.Finding `json:"findings"`
}

// WriteFindingsArtifact writes preflight-findings.json to the session directory.
// This is the structured findings artifact required by the evidence bundle spec.
func WriteFindingsArtifact(sessionDir string, results []*Result) error {
	export := findingsExport{}
	for _, r := range results {
		export.Cycles++
		export.Passed = r.Verdict == "PASS"
		export.Results = append(export.Results, findingsExportCycle{
			Cycle:    r.Cycle,
			Verdict:  r.Verdict,
			Blocking: r.Blocking,
			Total:    r.Total,
			Findings: r.Findings,
		})
	}

	jb, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "preflight-findings.json"), append(jb, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(sessionDir, "preflight-findings.json"), 0o600)
}
