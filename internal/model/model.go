// Package model integrates the local Qwen inference server (llama.cpp,
// OpenAI-compatible API) into the AEGIS runtime pipeline.
//
// The model is advisory only — it NEVER enforces a security decision.
// Every inference request/response/error/latency is emitted to the same
// central session event store with the active session_id.
package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/eth0x1/aegis/internal/events"
)

const (
	DefaultBaseURL = "http://127.0.0.1:8080"
	DefaultModel   = "qwen2.5-coder-1.5b-instruct"
	DefaultTimeout = 90 * time.Second
)

type Client struct {
	BaseURL   string
	SessionID string
	Model     string
	Timeout   time.Duration
	HTTP      *http.Client
	store     *events.Store
}

type Option func(*Client)

func WithStore(store *events.Store) Option {
	return func(c *Client) { c.store = store }
}

func WithModel(name string) Option {
	return func(c *Client) {
		if name != "" {
			c.Model = name
		}
	}
}

// WithBaseURL overrides the local model server endpoint (default
// model.DefaultBaseURL).
func WithBaseURL(url string) Option {
	return func(c *Client) {
		if url != "" {
			c.BaseURL = url
		}
	}
}

func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.Timeout = d
		}
	}
}

func New(sessionID string, opts ...Option) *Client {
	c := &Client{
		BaseURL:   DefaultBaseURL,
		SessionID: sessionID,
		Model:     DefaultModel,
		Timeout:   DefaultTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: c.Timeout}
	}
	return c
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []message `json:"messages"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

type Response struct {
	Text             string
	LatencyMS        int64
	PromptTokens     int
	CompletionTokens int
}

// Health pings the local server. No events are emitted for health checks.
func (c *Client) Health(ctx context.Context) error {
	url := strings.TrimSuffix(c.BaseURL, "/") + "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("model server unhealthy (status %d)", resp.StatusCode)
	}
	return nil
}

// Chat runs a single completion. It emits model.request, model.response
// (or model.error on failure) and model.latency events tagged with the
// client's session_id.
func (c *Client) Chat(ctx context.Context, system, user string) (*Response, error) {
	start := time.Now()
	data := map[string]any{
		"model":         c.Model,
		"prompt_chars":  len(user),
		"system_prompt": truncate(system, 200),
	}
	c.emit(events.TypeModelRequest, events.SevInfo, data)
	if c.SessionID == "" {
		return nil, fmt.Errorf("model client created without a session id")
	}

	body, _ := json.Marshal(chatRequest{
		Model: c.Model,
		Messages: []message{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		MaxTokens:   1024,
		Temperature: 0.2,
	})
	url := strings.TrimSuffix(c.BaseURL, "/") + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		c.emitError(start, err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		c.emitError(start, err)
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		c.emitError(start, err)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		err := fmt.Errorf("model server error (status %d): %s", resp.StatusCode, msg)
		c.emitError(start, err)
		return nil, err
	}

	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		c.emitError(start, err)
		return nil, err
	}
	if len(cr.Choices) == 0 {
		err := fmt.Errorf("model returned no choices")
		c.emitError(start, err)
		return nil, err
	}

	latency := time.Since(start).Milliseconds()
	out := &Response{
		Text:             cr.Choices[0].Message.Content,
		LatencyMS:        latency,
		PromptTokens:     cr.Usage.PromptTokens,
		CompletionTokens: cr.Usage.CompletionTokens,
	}
	c.emit(events.TypeModelResponse, events.SevInfo, map[string]any{
		"model":         c.Model,
		"tokens":        out.CompletionTokens,
		"prompt_tokens": out.PromptTokens,
		"latency_ms":    latency,
	})
	c.emit(events.TypeModelLatency, events.SevInfo, map[string]any{
		"model":      c.Model,
		"latency_ms": latency,
	})
	return out, nil
}

func (c *Client) emitError(start time.Time, err error) {
	c.emit(events.TypeModelError, events.SevMedium, map[string]any{
		"model":      c.Model,
		"error":      truncate(err.Error(), 400),
		"latency_ms": time.Since(start).Milliseconds(),
	})
}

func (c *Client) emit(typ, severity string, data map[string]any) {
	if c.store == nil {
		return
	}
	ev := events.New(events.SourceModel, typ, severity, "aegis", c.SessionID, data)
	_ = c.store.Append(ev)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// PromptForFindings builds a system/user prompt asking the model to
// explain blocking security findings in developer-actionable terms.
// The model's output is advisory; enforcement stays deterministic.
func PromptForFindings(sessionID string, cycle, blocking, total int, fs []FindingRef) (string, string) {
	var b strings.Builder
	fmt.Fprintf(&b, "PreFlight cycle %d found %d of %d findings BLOCKING release of session %s.\n\n",
		cycle, blocking, total, shortID(sessionID))
	if len(fs) == 0 {
		b.WriteString("(no finding detail supplied)")
	}
	for i, f := range fs {
		loc := f.File
		if loc == "" {
			loc = "(project)"
		}
		fmt.Fprintf(&b, "%d. [%s] %s:%d rule=%s — %s\n", i+1, f.Severity, loc, f.Line, f.Rule, f.Message)
	}
	system := "You are AEGIS's local security advisor (1.5B). You explain security " +
		"findings to a developer so they can fix them. Be concrete and concise. " +
		"You are advisory only and never make enforcement decisions."
	return system, b.String()
}

// PromptForTimeline builds a prompt to reason over a session's full
// event timeline (files, tools, network, scans).
func PromptForTimeline(sessionID string, lines []string) (string, string) {
	var b strings.Builder
	fmt.Fprintf(&b, "Session %s completed. Timeline (%d events):\n\n", shortID(sessionID), len(lines))
	for i, l := range lines {
		if i >= 120 {
			fmt.Fprintf(&b, "… (%d more events)\n", len(lines)-120)
			break
		}
		b.WriteString(l)
		b.WriteString("\n")
	}
	system := "You are AEGIS's local session analyst (1.5B). Summarize the security-relevant " +
		"behavior of this agent session: notable files accessed, tools run, network activity, " +
		"any suspicious patterns, and the final verdict. Be concise. Advisory only."
	return system, b.String()
}

// PromptForIncident builds a prompt explaining a correlated incident.
func PromptForIncident(sessionID string, ruleID, summary string, evidence []string) (string, string) {
	var b strings.Builder
	fmt.Fprintf(&b, "AEGIS detected an INCIDENT (rule %s) in session %s:\n%s\n\n", ruleID, shortID(sessionID), summary)
	b.WriteString("Triggering evidence:\n")
	for _, e := range evidence {
		b.WriteString("- ")
		b.WriteString(e)
		b.WriteString("\n")
	}
	system := "You are AEGIS's local incident analyst (1.5B). Explain what happened, how the " +
		"containment worked, and what the developer should do next. Advisory only."
	return system, b.String()
}

// FindingRef is a minimal structured finding used to build model prompts.
type FindingRef struct {
	Severity string
	File     string
	Line     int
	Rule     string
	Message  string
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
