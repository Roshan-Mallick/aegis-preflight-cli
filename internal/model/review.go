package model

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ReviewVerdict is the strict JSON verdict the exit-gate prompt requires from
// the local model. Decision must be PASS or BLOCK; anything else is a parse
// error and is handled as a safe failure by the caller.
type ReviewVerdict struct {
	Decision string   `json:"decision"`
	Risk     string   `json:"risk"`
	Summary  string   `json:"summary"`
	Findings []string `json:"findings"`
}

// SecurityReview runs a single structured security review completion and
// enforces the strict JSON contract on the response.
func (c *Client) SecurityReview(ctx context.Context, system, user string) (*ReviewVerdict, error) {
	resp, err := c.Chat(ctx, system, user)
	if err != nil {
		return nil, err
	}
	v, err := ParseReviewJSON(resp.Text)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// ParseReviewJSON extracts and validates the strict review JSON object from a
// model response. The model is told to return JSON only, but a small amount of
// surrounding prose is tolerated so the first/last braces still parse.
func ParseReviewJSON(text string) (*ReviewVerdict, error) {
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("review response is not JSON")
	}
	var v ReviewVerdict
	if err := json.Unmarshal([]byte(text[start:end+1]), &v); err != nil {
		return nil, fmt.Errorf("parse review json: %w", err)
	}
	v.Decision = strings.ToUpper(strings.TrimSpace(v.Decision))
	switch v.Decision {
	case "PASS", "BLOCK":
	default:
		return nil, fmt.Errorf("review decision %q is invalid", v.Decision)
	}
	v.Risk = strings.ToUpper(strings.TrimSpace(v.Risk))
	switch v.Risk {
	case "", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL":
	default:
		return nil, fmt.Errorf("review risk %q is invalid", v.Risk)
	}
	v.Summary = strings.TrimSpace(v.Summary)
	if v.Findings == nil {
		v.Findings = []string{}
	}
	return &v, nil
}