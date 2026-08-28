package model

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/paths"
	"github.com/eth0x1/aegis/internal/session"
)

func newTestManager(t *testing.T) *session.Manager {
	t.Helper()
	mgr, err := session.Create(paths.StateDir(), t.TempDir(), "test-agent", "strict")
	if err != nil {
		t.Fatalf("session.Create: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	return mgr
}

func TestHealthOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	c := New("11111111-1111-1111-1111-111111111111", WithStore(newTestManager(t).Store()))
	c.BaseURL = srv.URL
	c.HTTP = srv.Client()
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}
}

func TestHealthUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New("22222222-2222-2222-2222-222222222222", WithStore(newTestManager(t).Store()))
	c.BaseURL = srv.URL
	c.HTTP = srv.Client()
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("expected health error on 503")
	}
}

func TestChatAndEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Model != "" && !strings.Contains(req.Model, "qwen") {
			t.Errorf("model name mismatch: %s", req.Model)
		}
		if len(req.Messages) != 2 || req.Messages[0].Role != "system" || req.Messages[1].Role != "user" {
			t.Errorf("messages layout wrong")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(chatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: "inline fix advised"}}},
			Usage: struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			}{PromptTokens: 11, CompletionTokens: 7},
		})
	}))
	defer srv.Close()

	mgr := newTestManager(t)
	store := mgr.Store()
	c := New("33333333-3333-3333-3333-333333333333", WithStore(store))
	c.BaseURL = srv.URL
	c.HTTP = srv.Client()

	resp, err := c.Chat(context.Background(), "sys", "user findings")
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	if resp.Text != "inline fix advised" {
		t.Errorf("unexpected text %q", resp.Text)
	}
	if resp.LatencyMS < 0 || resp.PromptTokens != 11 || resp.CompletionTokens != 7 {
		t.Errorf("unexpected response %+v", resp)
	}

	all, err := events.ReadAll(mgr.Dir())
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	seen := map[string]bool{}
	for _, ev := range all {
		if ev.Type == events.TypeModelRequest || ev.Type == events.TypeModelResponse || ev.Type == events.TypeModelLatency {
			if ev.SessionID != "33333333-3333-3333-3333-333333333333" {
				t.Errorf("model event missing session id: %+v", ev)
			}
			seen[ev.Type] = true
		}
	}
	if !seen[events.TypeModelRequest] || !seen[events.TypeModelResponse] || !seen[events.TypeModelLatency] {
		t.Errorf("missing model.* events: %v", seen)
	}
}

func TestChatErrorEmitsEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("oops"))
	}))
	defer srv.Close()

	mgr := newTestManager(t)
	store := mgr.Store()
	c := New("44444444-4444-4444-4444-444444444444", WithStore(store))
	c.BaseURL = srv.URL
	c.HTTP = srv.Client()

	if _, err := c.Chat(context.Background(), "sys", "user"); err == nil {
		t.Fatal("expected chat error")
	}
	all, err := events.ReadAll(mgr.Dir())
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	foundErr := false
	for _, ev := range all {
		if ev.Type == events.TypeModelError {
			foundErr = true
		}
	}
	if !foundErr {
		t.Error("expected model.error event")
	}
}

func TestWithOptions(t *testing.T) {
	c := New("sid", WithModel("custom-model"), WithTimeout(2))
	if c.Model != "custom-model" {
		t.Errorf("model = %s", c.Model)
	}
	if c.Timeout != 2 {
		t.Errorf("timeout = %v", c.Timeout)
	}
	c2 := New("sid", WithModel(""))
	if c2.Model != DefaultModel {
		t.Errorf("empty model default = %s", c2.Model)
	}
}
