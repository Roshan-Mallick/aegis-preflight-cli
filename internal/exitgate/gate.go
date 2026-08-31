package exitgate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/eth0x1/aegis/internal/model"
	"github.com/eth0x1/aegis/internal/preflight"
)

const (
	Pass  = "PASS"
	Block = "BLOCK"

	// PolicyBlock is the default safe exit policy: an unavailable local AI
	// review blocks exit with an explicit message rather than silently
	// approving it.
	PolicyBlock = "block"
	// PolicyWarn allows exit with an explicit warning when the advisory
	// review could not run (opt-in; deterministic checks still fully hold).
	PolicyWarn = "warn"
)

// Review is the outcome of one exit-gate review.
type Review struct {
	Decision    string   // PASS | BLOCK
	Risk        string   // NONE | LOW | MEDIUM | HIGH | CRITICAL
	Summary     string   // concise advisor summary (redacted, bounded)
	Findings    []string // concise, actionable remediation findings
	Unavailable bool     // the advisor could not be reached or did not respond
	Cached      bool     // served from in-session cache; no model call was made
	ReviewID    string   // evidence digest this verdict applies to
}

// Compose folds the deterministic preflight verdict and the local AI review
// into the final exit decision:
//   - a deterministic block can never be overridden by the AI review;
//   - a local AI block always blocks;
//   - exit requires deterministic PASS and AI PASS;
//   - a missing review is never treated as approval.
func Compose(deterministicPass bool, review *Review) string {
	if !deterministicPass {
		return Block
	}
	if review == nil {
		return Block
	}
	if review.Decision != Pass {
		return Block
	}
	return Pass
}

// Gate runs the local AI exit review for one session. It is constructed with
// a model client bound to the session id and store, and it carries the
// in-session evidence cache that prevents unchanged evidence from being
// re-sent between remediation retries.
type Gate struct {
	client *model.Client
	policy string // PolicyBlock (default) | PolicyWarn
	cache  map[string]Review
}

// New returns a Gate. A nil client degrades exactly like an unavailable
// advisor (policy-resolved, never a silent approval). policyOnUnavailable is
// "block" (default/safe) or "warn".
func New(client *model.Client, policyOnUnavailable string) *Gate {
	if client == nil {
		client = model.New("")
	}
	p := strings.ToLower(strings.TrimSpace(policyOnUnavailable))
	if p != PolicyBlock && p != PolicyWarn {
		p = PolicyBlock
	}
	return &Gate{client: client, policy: p, cache: map[string]Review{}}
}

// Review evaluates one compact evidence summary. It never returns nil: on
// health/parse failures it returns a policy-resolved Review marked
// Unavailable (block by default), so a missing advisor can never be mistaken
// for security approval.
func (g *Gate) Review(ctx context.Context, ev *Evidence) *Review {
	if ev == nil {
		return g.unavailable("exit security evidence could not be built")
	}
	if prev, ok := g.cache[ev.ReviewID]; ok {
		out := prev
		out.Cached = true
		return &out
	}
	if err := g.client.Health(ctx); err != nil {
		return g.unavailable("local AI advisor unavailable: " + err.Error())
	}
	system, user := PromptForReview(ev)
	v, err := g.client.SecurityReview(ctx, system, user)
	if err != nil {
		return g.unavailable("local AI advisor request failed: " + err.Error())
	}
	r := &Review{
		Decision: v.Decision,
		Risk:     v.Risk,
		Summary:  Redact(truncate(strings.TrimSpace(v.Summary), 240)),
		ReviewID: ev.ReviewID,
	}
	for _, f := range v.Findings {
		if len(r.Findings) >= 10 {
			break
		}
		r.Findings = append(r.Findings, Redact(truncate(strings.TrimSpace(f), 240)))
	}
	g.cache[ev.ReviewID] = *r
	return r
}

func (g *Gate) unavailable(reason string) *Review {
	detail := Redact(reason)
	if g.policy == PolicyWarn {
		return &Review{
			Decision:    Pass,
			Risk:        "LOW",
			Unavailable: true,
			Summary:     "local AI security review unavailable — exit allowed under explicit WARN policy; deterministic checks only",
			Findings:    []string{detail + " — (warn policy: advisory review skipped)"},
		}
	}
	return &Review{
		Decision:    Block,
		Risk:        "MEDIUM",
		Unavailable: true,
		Summary:     "local AI security review unavailable — safe BLOCK policy",
		Findings:    []string{detail + " — start/fix the local advisor, then retry the final security review"},
	}
}

const reviewSystem = `You are the AEGIS final security review gate. A cloud AI agent finished working in a sandboxed project and requests permission to exit.

Analyze the SECURITY SUMMARY (JSON). Determine:
1. What changed?
2. Did it access external APIs/network resources?
3. Did it access secrets or sensitive data?
4. Did it introduce security vulnerabilities?
5. Did it weaken security controls?
6. Is there anything requiring remediation?

Use ONLY the supplied evidence. Never invent activity that is not observed. "External access: none" and "Screen/UI access: none observed" are literal statements of absent evidence — do not upgrade them to "unknown" or guess.

SECURITY-BOUNDARY RULES:
- The "profile" field is the active network policy. Destinations WITHOUT "blocked":true were PERMITTED by that profile (model API, package registries, git hosts) — their presence alone is expected infrastructure and is NOT grounds for a BLOCK.
- A destination with "blocked":true (or a raw-IP / private-range attempt) is a policy violation and therefore a real security indication.
- Elevated concern applies when a boundary violation — blocked egress, secrets access, or a scanner finding — is combined with other risky signals.
- You are the last line of defense, not a nitpicker. A BLOCK must be justified by a concrete, traceable security indication in the evidence. Do not split one observation into multiple findings. When the agent only edited files and used permitted infrastructure, PASS.

Respond with ONLY a JSON object, no prose:
{"decision":"PASS|BLOCK","risk":"NONE|LOW|MEDIUM|HIGH|CRITICAL","summary":"<concise>","findings":["<concise, actionable>"]}`

// PromptForReview builds the system/user prompt from a compact evidence
// summary. The user message is the evidence JSON only — nothing else from the
// session is ever forwarded.
func PromptForReview(ev *Evidence) (string, string) {
	b, _ := json.Marshal(ev)
	user := "evidence_id=" + short(ev.ReviewID) + "\n" + string(b)
	return reviewSystem, user
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// WriteFixRequest hands the cloud agent ONLY the concise remediation findings
// that came out of an AI-blocked exit gate, mirroring the deterministic
// preflight fix-request contract in .aegis/FIX_REQUEST.md.
func WriteFixRequest(sessionDir, workspace string, cycle int, review *Review) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# AEGIS Exit Security Review: BLOCKED (review cycle %d/%d)\n\n",
		cycle, preflight.MaxCycles)
	if review == nil {
		b.WriteString("The exit security review returned no verdict. Retry the final security review.\n")
	} else if review.Unavailable {
		b.WriteString("The local AI security review was UNAVAILABLE and exit was blocked under the safe policy.\n")
		b.WriteString("Start/fix the local advisor, then retry the final security review.\n")
		if len(review.Findings) > 0 {
			b.WriteString("\nDetail:\n")
			for _, f := range review.Findings {
				b.WriteString("- ")
				b.WriteString(f)
				b.WriteString("\n")
			}
		}
	} else {
		fmt.Fprintf(&b, "Risk: %s\n\n", orNA(review.Risk))
		if len(review.Summary) > 0 {
			b.WriteString(review.Summary)
			b.WriteString("\n")
		}
		b.WriteString("\nFindings:\n")
		for _, f := range review.Findings {
			b.WriteString("- ")
			b.WriteString(f)
			b.WriteString("\n")
		}
		b.WriteString("\nFix these issues and retry the final security review.\n")
	}

	path := filepath.Join(workspace, ".aegis", "FIX_REQUEST.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return err
	}

	if review != nil {
		detail := "# AEGIS exit security review\n\n" +
			fmt.Sprintf("review_id: %s\n", review.ReviewID) +
			fmt.Sprintf("decision:  %s\n", review.Decision) +
			fmt.Sprintf("risk:      %s\n", orNA(review.Risk)) +
			fmt.Sprintf("cached:    %t\n\n", review.Cached)
		if len(review.Summary) > 0 {
			detail += review.Summary + "\n"
		}
		_ = os.WriteFile(filepath.Join(sessionDir, "exit-review.md"),
			[]byte(detail), 0o600)
	}
	return nil
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}