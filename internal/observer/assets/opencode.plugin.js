import { mkdirSync, appendFileSync } from "node:fs"
import { dirname } from "node:path"

const LOG_PATH = "/workspace/.aegis/raw/hooks.jsonl"

// Normalize the opencode tool arguments into the shape the AEGIS hook tailer
// expects. opencode passes camelCase keys (e.g. filePath), while the normalizer
// reads snake_case (file_path). This mapping is local to the plugin and only
// affects event observation.
function normalizeArgs(args) {
  const a = args && typeof args === "object" ? { ...args } : {}
  if (a.filePath !== undefined) {
    a.file_path = a.filePath
  }
  return a
}

export const AegisObserver = async ({ directory }) => {
  const cwd = directory || "/workspace"
  mkdirSync(dirname(LOG_PATH), { recursive: true })

  function emit(sessionID, eventName, toolName, toolInput) {
    try {
      const line = JSON.stringify({
        session_id: sessionID || "",
        hook_event_name: eventName,
        tool_name: toolName,
        tool_input: toolInput || {},
        cwd,
      })
      appendFileSync(LOG_PATH, line + "\n")
    } catch (e) {
      // observation only; never influence or block the agent
    }
  }

  return {
    "tool.execute.before": async (input, output) => {
      if (!input || !input.tool) return
      emit(input.sessionID, "PreToolUse", input.tool, normalizeArgs(output && output.args))
    },
    "tool.execute.after": async (input) => {
      if (!input || !input.tool) return
      emit(input.sessionID, "PostToolUse", input.tool, {})
    },
  }
}
