package exitgate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/eth0x1/aegis/internal/model"
)

// fakeAdvisor is an OpenAI-compatible local model server that returns a
// configurable review verdict and counts chat requests.
type fakeAdvisor struct {
	mu      sync.Mutex
	chatCalls int
	content string // the chat message content returned by the model
	status  int    // HTTP status applied to every endpoint (0 = 200)
}

func (f *fakeAdvisor) server(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/health"):
			if f.status != 0 {
				w.WriteHeader(f.status)
			}
		case strings.HasSuffix(r.URL.Path, "/v1/chat/completions"):
			f.mu.Lock()
			f.chatCalls++
			f.mu.Unlock()
			if f.status != 0 {
				w.WriteHeader(f.status)
				return
			}
			body := fmt.Sprintf(`{"choices":[{"message":{"content":%s}}],"usage":{"prompt_tokens":4,"completion_tokens":3}}`,
				strconv.Quote(f.content))
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (f *fakeAdvisor) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.chatCalls
}

func newReviewGate(t *testing.T, advisor *fakeAdvisor, policy string) *Gate {
	t.Helper()
	client := model.New(uuid.NewString(),
		model.WithBaseURL(advisor.server(t).URL))
	return New(client, policy)
}

func sampleEvidence(reviewID string) *Evidence {
	return &Evidence{
		Version:      EvidenceVersion,
		ReviewID:     reviewID,
		Cycle:        1,
		Task:         "add feature",
		Profile:      "strict",
		ChangeCounts: map[string]int{"added": 1},
		Network:      Network{ExternalAccess: "none"},
		ScreenOrUI:   "none observed",
	}
}

func reviewJSON(decision, risk string) string {
	return fmt.Sprintf(`{"decision":%q,"risk":%q,"summary":"ok","findings":["nothing to fix"]}`, decision, risk)
}

func TestGatePASS(t *testing.T) {
	a := &fakeAdvisor{content: reviewJSON("PASS", "NONE")}
	g := newReviewGate(t, a, PolicyBlock)
	r := g.Review(context.Background(), sampleEvidence("e1"))
	if r.Decision != Pass {
		t.Fatalf("expected PASS, got %+v", r)
	}
	if r.Cached || r.Unavailable {
		t.Fatalf("unexpected cached/unavailable: %+v", r)
	}
}

func TestGateBLOCK(t *testing.T) {
	a := &fakeAdvisor{content: reviewJSON("BLOCK", "HIGH")}
	g := newReviewGate(t, a, PolicyBlock)
	r := g.Review(context.Background(), sampleEvidence("e2"))
	if r.Decision != Block {
		t.Fatalf("expected BLOCK, got %+v", r)
	}
	if len(r.Findings) == 0 {
		t.Error("expected remediation findings")
	}
}

func TestGateCachesUnchangedEvidence(t *testing.T) {
	a := &fakeAdvisor{content: reviewJSON("PASS", "LOW")}
	g := newReviewGate(t, a, PolicyBlock)
	ev := sampleEvidence("same-digest")

	r1 := g.Review(context.Background(), ev)
	if r1.Cached {
		t.Fatal("first review must not be cached")
	}
	r2 := g.Review(context.Background(), ev)
	if !r2.Cached {
		t.Fatal("unchanged evidence must be served from cache (no re-send)")
	}
	if a.calls() != 1 {
		t.Fatalf("model chat calls = %d, want 1 (unchanged evidence re-sent)", a.calls())
	}
}

func TestGateReanalyzesChangedEvidence(t *testing.T) {
	a := &fakeAdvisor{content: reviewJSON("BLOCK", "HIGH")}
	g := newReviewGate(t, a, PolicyBlock)

	if r := g.Review(context.Background(), sampleEvidence("digest-before")); r.Decision != Block {
		t.Fatalf("first review = %+v", r)
	}
	if r := g.Review(context.Background(), sampleEvidence("digest-after")); r.Decision != Block {
		t.Fatalf("second review = %+v", r)
	}
	if a.calls() != 2 {
		t.Fatalf("model chat calls = %d, want 2 (changed evidence must be re-analyzed)", a.calls())
	}
}

func TestGateAdvisorUnavailableBlocksByDefault(t *testing.T) {
	a := &fakeAdvisor{content: reviewJSON("PASS", "NONE"), status: http.StatusInternalServerError}
	g := newReviewGate(t, a, PolicyBlock) // default safe policy
	r := g.Review(context.Background(), sampleEvidence("e3"))
	if r.Decision != Block || !r.Unavailable {
		t.Fatalf("unavailable advisor must fail closed under block policy, got %+v", r)
	}
}

func TestGateAdvisorUnavailableWarnIsExplicit(t *testing.T) {
	a := &fakeAdvisor{content: reviewJSON("PASS", "NONE"), status: http.StatusInternalServerError}
	g := newReviewGate(t, a, PolicyWarn) // opt-in warn policy
	r := g.Review(context.Background(), sampleEvidence("e4"))
	if r.Decision != Pass {
		t.Fatalf("warn policy allows exit, got %+v", r)
	}
	if !r.Unavailable || !strings.Contains(strings.ToLower(r.Summary), "warn") {
		t.Fatalf("unavailable must be explicitly reported, got %+v", r)
	}
}

func TestGateNilEvidenceFailsSafe(t *testing.T) {
	a := &fakeAdvisor{content: reviewJSON("PASS", "NONE")}
	g := newReviewGate(t, a, PolicyBlock)
	if r := g.Review(context.Background(), nil); r.Decision != Block || !r.Unavailable {
		t.Fatalf("nil evidence must fail closed, got %+v", r)
	}
}

func TestGateUnparseableResponseFailsSafe(t *testing.T) {
	a := &fakeAdvisor{content: "sure, everything looks fine"} // not JSON
	g := newReviewGate(t, a, PolicyBlock)
	if r := g.Review(context.Background(), sampleEvidence("e5")); r.Decision != Block || !r.Unavailable {
		t.Fatalf("unparseable advisor response must fail closed, got %+v", r)
	}
}

func TestComposeMatrix(t *testing.T) {
	aiPass := &Review{Decision: Pass}
	aiBlock := &Review{Decision: Block, Findings: []string{"x"}}

	if got := Compose(false, aiPass); got != Block {
		t.Errorf("deterministic BLOCK + AI PASS = %s, want BLOCK", got)
	}
	if got := Compose(true, aiBlock); got != Block {
		t.Errorf("deterministic PASS + AI BLOCK = %s, want BLOCK", got)
	}
	if got := Compose(true, aiPass); got != Pass {
		t.Errorf("deterministic PASS + AI PASS = %s, want PASS", got)
	}
	if got := Compose(true, nil); got != Block {
		t.Errorf("missing review must never approve: %s", got)
	}
}

func TestPromptSendsCompactEvidenceOnly(t *testing.T) {
	ev := sampleEvidence("digest-1234567890abcdef")
	system, user := PromptForReview(ev)
	if !strings.Contains(user, "evidence_id=digest-12345") {
		t.Errorf("user prompt missing review id: %q", user)
	}
	if strings.Contains(user, "conversation") || strings.Contains(system, "conversation") {
		t.Error("prompt must not reference the conversation")
	}
	if len(user) > 4096 {
		t.Errorf("user prompt too large: %d bytes", len(user))
	}
}