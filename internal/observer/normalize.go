package observer

import (
	"encoding/json"
	"strings"

	"github.com/eth0x1/aegis/internal/events"
	"github.com/eth0x1/aegis/internal/policy"
)

const (
	TypeToolUse = "tool.use"
)

type HookEvent struct {
	SessionID     string          `json:"session_id"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	CWD           string          `json:"cwd"`
}

func NormalizeHook(raw []byte) (events.Event, bool) {
	var he HookEvent
	if err := json.Unmarshal(raw, &he); err != nil {
		return events.Event{}, false
	}
	if he.HookEventName == "" {
		return events.Event{}, false
	}
	data := map[string]any{
		"hook_event": he.HookEventName,
		"tool":       he.ToolName,
	}
	typ, severity := classify(he.ToolName)
	switch typ {
	case events.TypeCommandExec:
		data["command"] = jsonString(he.ToolInput, "command")
	case events.TypeFileRead:
		p := jsonString(he.ToolInput, "file_path")
		data["path"] = p
		data["sensitive"] = policy.IsSensitivePath(p)
	case events.TypeFileWrite:
		p := jsonString(he.ToolInput, "file_path")
		data["path"] = p
		data["sensitive"] = policy.IsSensitivePath(p)
	case TypeToolUse:
		var input map[string]any
		_ = json.Unmarshal(he.ToolInput, &input)
		if input != nil {
			for k, v := range input {
				if _, exists := data[k]; !exists {
					data[k] = v
				}
			}
		}
	case events.TypeNetworkConnect:
		u := jsonString(he.ToolInput, "url")
		data["url"] = u
		data["decision"] = "intent"
	default:
		var input map[string]any
		_ = json.Unmarshal(he.ToolInput, &input)
		if input != nil {
			for k, v := range input {
				data["in_"+k] = v
			}
		}
	}
	ev := events.New(events.SourceHook, typ, severity, "claude", he.SessionID, data)
	return ev, true
}

func classify(tool string) (string, string) {
	switch strings.ToLower(tool) {
	case "bash":
		return events.TypeCommandExec, events.SevInfo
	case "read":
		return events.TypeFileRead, events.SevLow
	case "write", "edit", "multiedit", "notebookedit":
		return events.TypeFileWrite, events.SevInfo
	case "webfetch", "websearch":
		return events.TypeNetworkConnect, events.SevLow
	default:
		return TypeToolUse, events.SevLow
	}
}

func jsonString(raw json.RawMessage, key string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}
