package preflight

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/findings"
	"github.com/eth0x1/aegis/internal/workspace"
)

const gitleaksSample = `[
 {"Description":"AWS Access Key","StartLine":3,"File":"src/config.py","RuleID":"aws-access-token","Severity":"HIGH","Secret":"AKIA…","Fingerprint":"x"},
 {"Description":"Generic API Key","StartLine":18,"File":"src/config.py","RuleID":"generic-api-key","Severity":"CRITICAL","Secret":"…","Fingerprint":"y"}
]`

const npmAuditSample = `{
 "vulnerabilities": {
   "lodash": {"name":"lodash","severity":"critical","via":["CVE-2021-23337"]},
   "minimist": {"name":"minimist","severity":"low","via":["prototype pollution"]}
 },
 "metadata": {"vulnerabilities":{"critical":1,"low":1}}
}`

const pipAuditSample = `{
 "dependencies": [
   {"name":"flask","version":"2.0.0","vulns":[{"id":"PYSEC-2023-001","description":"trusted host issue","fix_versions":["2.2.5"]}]}
 ]
}`

func TestParseGitleaks(t *testing.T) {
	fs := findings.ParseGitleaks([]byte(gitleaksSample))
	if len(fs) != 2 {
		t.Fatalf("got %d findings", len(fs))
	}
	if fs[0].Scanner != "gitleaks" || !fs[0].Blocking {
		t.Errorf("finding 0 wrong: %+v", fs[0])
	}
	if fs[0].Severity != "high" || fs[1].Severity != "critical" {
		t.Errorf("severities: %s %s", fs[0].Severity, fs[1].Severity)
	}
	if fs[1].Line != 18 || fs[1].File != "src/config.py" || fs[1].Rule != "generic-api-key" {
		t.Errorf("fields: %+v", fs[1])
	}
	if _, err := os.Stat("nonexistent"); err == nil {
		t.Fail()
	}
}

func TestParseNpmAudit(t *testing.T) {
	fs := findings.ParseNpmAudit([]byte(npmAuditSample))
	if len(fs) != 2 {
		t.Fatalf("got %d", len(fs))
	}
	var crit *findings.Finding
	for i := range fs {
		if strings.HasPrefix(fs[i].Message, "lodash") {
			crit = &fs[i]
		}
	}
	if crit == nil {
		t.Fatal("lodash finding missing")
	}
	if crit.Severity != "critical" || !crit.Blocking {
		t.Errorf("lodash must be critical+blocking: %+v", crit)
	}
	for i := range fs {
		if strings.HasPrefix(fs[i].Message, "minimist") && fs[i].Blocking {
			t.Error("low severity npm finding must not block")
		}
	}
}

func TestParsePipAudit(t *testing.T) {
	fs := findings.ParsePipAudit([]byte(pipAuditSample))
	if len(fs) != 1 {
		t.Fatalf("got %d", len(fs))
	}
	if fs[0].Rule != "PYSEC-2023-001" || fs[0].Severity != "critical" || !fs[0].Blocking {
		t.Errorf("%+v", fs[0])
	}
	if !strings.Contains(fs[0].Message, "2.2.5") {
		t.Errorf("fix version lost: %s", fs[0].Message)
	}
}

type fakeScanner struct {
	name string
	seq  [][]findings.Finding
	idx  int
}

func (f *fakeScanner) Name() string { return f.name }
func (f *fakeScanner) Scan(ctx context.Context, ws string, e ExecFunc) ([]findings.Finding, error) {
	i := f.idx
	if i >= len(f.seq) {
		i = len(f.seq) - 1
	}
	f.idx++
	return f.seq[i], nil
}

func secretFinding() findings.Finding {
	return findings.New("fake-scanner", "critical", "src/config.py", 18, "generic-api-key",
		"possible hardcoded secret", true)
}

func TestRunLoopPassesImmediately(t *testing.T) {
	dir := t.TempDir()
	sc := &fakeScanner{name: "clean-scan", seq: [][]findings.Finding{{}}}
	final, err := RunLoop(context.Background(), dir,
		RunOptions{Scanners: []Scanner{sc}}, LoopCallbacks{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !final.Passed || final.Cycles != 1 {
		t.Errorf("passed=%v cycles=%d", final.Passed, final.Cycles)
	}
}

func TestRunLoopFixRescanWithinMaxCycles(t *testing.T) {
	dir := t.TempDir()
	sc := &fakeScanner{name: "flaky", seq: [][]findings.Finding{
		{secretFinding()},
		{secretFinding()},
		{},
	}}
	published := 0
	final, err := RunLoop(context.Background(), dir,
		RunOptions{Scanners: []Scanner{sc}},
		LoopCallbacks{PublishFixRequest: func(ctx context.Context, cycle int, res *Result) error {
			published++
			if res.Blocking != 1 {
				t.Errorf("cycle %d blocking=%d", cycle, res.Blocking)
			}
			return nil
		}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !final.Passed || final.Cycles != 3 {
		t.Fatalf("passed=%v cycles=%d want true/3", final.Passed, final.Cycles)
	}
	if published != 2 {
		t.Errorf("fix requests = %d, want 2", published)
	}
}

func TestRunLoopFailsAfterMaxCycles(t *testing.T) {
	dir := t.TempDir()
	sc := &fakeScanner{name: "always-bad", seq: [][]findings.Finding{
		{secretFinding()}, {secretFinding()}, {secretFinding()},
	}}
	final, err := RunLoop(context.Background(), dir,
		RunOptions{Scanners: []Scanner{sc}},
		LoopCallbacks{
			PublishFixRequest: func(ctx context.Context, c int, r *Result) error { return nil },
			BeforeRescan:      func(ctx context.Context, c int) error { return nil },
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if final.Passed {
		t.Fatal("must fail after max cycles of persistent findings")
	}
	if final.Cycles != MaxCycles {
		t.Errorf("cycles=%d want %d (hard cap)", final.Cycles, MaxCycles)
	}
}

func TestGitleaksFailClosedWhenMissing(t *testing.T) {
	g := &GitleaksScanner{BinPath: "/definitely/not/a/real/path/gitleaks"}
	fs, err := g.Scan(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("unavailable scanner should degrade to finding, not error: %v", err)
	}
	if len(fs) != 1 || !fs[0].Blocking || fs[0].Rule != "scanner-unavailable" {
		t.Fatalf("fail-closed finding missing: %+v", fs)
	}
}

func TestScanEmitsCanonicalEvents(t *testing.T) {
	storeDir := t.TempDir()
	store, err := events.Open(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	sc := &fakeScanner{name: "evt-scan", seq: [][]findings.Finding{{secretFinding()}}}
	res, err := RunScan(context.Background(), t.TempDir(),
		RunOptions{SessionID: "aaaa1111-2222-3333-4444-555555555555", Store: store,
			Scanners: []Scanner{sc}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "BLOCK" {
		t.Fatalf("verdict=%s", res.Verdict)
	}
	evts, _ := events.ReadAll(storeDir)
	kinds := map[string]int{}
	for _, e := range evts {
		kinds[e.Type]++
		if e.Type == events.TypeFinding && e.Source != events.SourceScanner {
			t.Error("finding event source wrong")
		}
	}
	if kinds[events.TypeFinding] != 1 || kinds["policy.preflight"] != 1 {
		t.Fatalf("event kinds: %v", kinds)
	}
}

func TestWriteFixRequestAndVerifiedArtifacts(t *testing.T) {
	sessionDir := t.TempDir()
	ws := t.TempDir()
	res := &Result{Cycle: 2, Blocking: 1, Findings: []findings.Finding{secretFinding()}}
	if err := WriteFixRequest(sessionDir, ws, 2, res); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(ws, ".aegis", "FIX_REQUEST.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fix cycle 2/", "generic-api-key", "src/config.py"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("FIX_REQUEST missing %q", want)
		}
	}
	fi, _ := os.Stat(filepath.Join(ws, ".aegis", "FIX_REQUEST.md"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("perms=%v", fi.Mode().Perm())
	}

	vd, err := GenerateVerifiedDiff("sid-test", map[string]workspace.Entry{}, ws, 1)
	if err != nil {
		t.Fatal(err)
	}
	vd.Changes = append(vd.Changes, ChangeRecord{Path: "new.go", Kind: "added"})
	if err := WriteVerifiedArtifacts(sessionDir, vd); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"verified-diff.json", "verified-diff.txt"} {
		if _, err := os.Stat(filepath.Join(sessionDir, name)); err != nil {
			t.Errorf("%s missing", name)
		}
	}
}
