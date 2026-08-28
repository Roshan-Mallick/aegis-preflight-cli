package findings

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type Finding struct {
	FindingID string `json:"finding_id"`
	Scanner   string `json:"scanner"`
	Severity  string `json:"severity"`
	Blocking  bool   `json:"blocking"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	Rule      string `json:"rule,omitempty"`
	Message   string `json:"message"`
}

const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

var validSev = map[string]bool{
	SevInfo: true, SevLow: true, SevMedium: true, SevHigh: true, SevCritical: true,
}

func New(scanner, severity, file string, line int, rule, msg string, blocking bool) Finding {
	if !validSev[severity] {
		severity = SevMedium
	}
	return Finding{
		FindingID: uuid.NewString(),
		Scanner:   scanner,
		Severity:  severity,
		Blocking:  blocking,
		File:      file,
		Line:      line,
		Rule:      rule,
		Message:   msg,
	}
}

func SkipFinding(scanner, reason string) Finding {
	return New(scanner, SevInfo, "", 0, "skipped", reason, false)
}

func UnavailableFinding(scanner, detail string) Finding {
	return New(scanner, SevCritical, "", 0, "scanner-unavailable",
		"required scanner could not run: "+detail, true)
}

type gitleaksReportItem struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	Severity    string `json:"Severity"`
	Secret      string `json:"Secret"`
}

func ParseGitleaks(output []byte) []Finding {
	var items []gitleaksReportItem
	if err := json.Unmarshal(output, &items); err != nil {
		return []Finding{New("gitleaks", SevMedium, "", 0, "parse-error",
			"gitleaks output not parseable: "+err.Error(), false)}
	}
	out := make([]Finding, 0, len(items))
	for _, it := range items {
		sev := strings.ToLower(strings.TrimSpace(it.Severity))
		if sev == "" {
			sev = SevHigh
		}
		msg := it.Description
		if msg == "" {
			msg = "potential secret detected"
		}
		out = append(out, New("gitleaks", sev, it.File, it.StartLine, it.RuleID, msg, true))
	}
	return out
}

type npmAuditReport struct {
	Vulnerabilities map[string]struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
		Via      []any  `json:"via"`
	} `json:"vulnerabilities"`
	Error any `json:"error"`
}

func ParseNpmAudit(output []byte) []Finding {
	var rep npmAuditReport
	if err := json.Unmarshal(output, &rep); err != nil {
		return []Finding{New("npm-audit", SevMedium, "", 0, "parse-error",
			"npm audit output not parseable: "+err.Error(), false)}
	}
	out := []Finding{}
	for name, v := range rep.Vulnerabilities {
		sev := strings.ToLower(v.Severity)
		blocking := sev == SevCritical
		viaDesc := describeVia(v.Via)
		out = append(out, New("npm-audit", sev, "", 0, "npm:"+name,
			fmt.Sprintf("%s: %s", name, viaDesc), blocking))
	}
	return out
}

func describeVia(via []any) string {
	parts := []string{}
	for _, v := range via {
		switch tv := v.(type) {
		case string:
			parts = append(parts, tv)
		case map[string]any:
			title, _ := tv["title"].(string)
			if title != "" {
				parts = append(parts, title)
			}
		}
	}
	if len(parts) == 0 {
		return "vulnerability reported"
	}
	return strings.Join(parts, "; ")
}

type pipAuditReport struct {
	Dependencies []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Vulns   []struct {
			ID          string   `json:"id"`
			Description string   `json:"description"`
			FixVersions []string `json:"fix_versions"`
		} `json:"vulns"`
	} `json:"dependencies"`
}

func ParsePipAudit(output []byte) []Finding {
	var rep pipAuditReport
	if err := json.Unmarshal(output, &rep); err != nil {
		return []Finding{New("pip-audit", SevMedium, "", 0, "parse-error",
			"pip-audit output not parseable: "+err.Error(), false)}
	}
	out := []Finding{}
	for _, dep := range rep.Dependencies {
		for _, v := range dep.Vulns {
			fix := strings.Join(v.FixVersions, ",")
			msg := fmt.Sprintf("%s %s: %s (fix: %s)", dep.Name, dep.Version, v.ID, fix)
			out = append(out, New("pip-audit", SevCritical, "", 0, v.ID, msg, true))
		}
	}
	return out
}

func CountBlocking(fs []Finding) int {
	n := 0
	for _, f := range fs {
		if f.Blocking {
			n++
		}
	}
	return n
}
