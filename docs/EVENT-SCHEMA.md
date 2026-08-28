# AEGIS Canonical Event Schema (v1)

Every security-relevant occurrence in an AEGIS session is normalized into a
single canonical JSONL format. All components — agent hooks, the egress proxy,
sandbox lifecycle control, PreFlight scanners, and the policy/response engine —
produce or normalize into this schema. Downstream consumers (TUI feed,
correlator, reports, future advisory analysts) read only canonical events.

## Wire format

One JSON object per line (JSONL) in:

```
~/.local/state/aegis/sessions/<session-id>/events.jsonl
```

### Authority invariants

- This log is **authoritative evidence**. It lives under the AEGIS state
  directory, which is **never mounted into any agent container**.
- The store enforces `0600` permissions on creation and on every open.
- Every appended line is validated against this schema before it is written;
  invalid events are refused, never persisted.
- Reads validate every line; malformed or tampered lines surface as errors so
  silent evidence corruption cannot go unnoticed.

## Required fields

| Field         | Type   | Description                                              |
|---------------|--------|----------------------------------------------------------|
| `event_id`    | string | UUIDv4, unique per event                                 |
| `session_id`  | string | UUIDv4 of the owning session                             |
| `timestamp`   | string | RFC3339 with nanoseconds, always UTC                     |
| `source`      | enum   | One of: `hook`, `proxy`, `sandbox`, `scanner`, `policy`  |
| `type`        | string | Namespaced event type, see registry below                |
| `severity`    | enum   | One of: `info`, `low`, `medium`, `high`, `critical`      |
| `data`        | object | Arbitrary structured payload; never null                 |

## Optional fields

| Field            | Type          | Description                                        |
|------------------|---------------|----------------------------------------------------|
| `actor`          | string        | Name of the acting entity (`claude`, `aegis`, ...) |
| `correlation_id` | string / null | Groups events belonging to one logical activity    |

## Sources

| Source     | Producer                                                        |
|------------|-----------------------------------------------------------------|
| `hook`     | Agent adapter hooks (e.g. Claude Code PreToolUse/PostToolUse)   |
| `proxy`    | AEGIS egress gateway sidecar (connection decisions)             |
| `sandbox`  | Sandbox manager (container/network lifecycle)                   |
| `scanner`  | PreFlight scanners (gitleaks, npm audit, pip-audit)             |
| `policy`   | Policy engine, correlator, response engine, session manager     |

## Severity definitions

| Severity   | Meaning                                                            |
|------------|--------------------------------------------------------------------|
| `info`     | Routine lifecycle/observation record                               |
| `low`      | Worth recording; no policy impact                                   |
| `medium`   | Suspicious; action blocked where possible                           |
| `high`     | Confirmed violation; blocked and/or session paused                  |
| `critical` | Incident; evidence preserved, sandbox killed, session failed        |

## Event type registry

Types are `namespace.name`, lowercase. Two reserved top-level types exist per
the canonical spec: `finding` and `incident`. Everything else is namespaced.
Known namespaces are reserved; new types may be added within existing
namespaces without schema changes (validation enforces the format and the
reserved bare types, not a closed set).

Initial catalog:

| Type               | Source           | Emitted when                                     |
|--------------------|------------------|--------------------------------------------------|
| `file.read`        | hook             | Agent reads a file inside the workspace          |
| `file.write`       | hook             | Agent writes/edits a file                        |
| `file.delete`      | hook             | Agent deletes a file                             |
| `command.exec`     | hook             | Agent executes a shell command                   |
| `tool.use`         | hook             | Any other agent tool invocation                  |
| `network.connect`  | proxy            | Connection attempt observed by gateway           |
| `finding`          | scanner          | PreFlight finding (normalized)                   |
| `incident`         | policy           | Correlator raised an incident                    |
| `session.created`  | policy           | Session created                                  |
| `session.state`    | policy           | Session state machine transition                 |
| `sandbox.start`    | sandbox          | Agent container started                          |
| `sandbox.exec`     | sandbox          | AEGIS-initiated verification command in sandbox  |
| `sandbox.kill`     | sandbox          | Agent container killed                           |

Hook normalization map (Claude Code adapter):

| Claude tool                        | Canonical type      | data fields                          |
|------------------------------------|---------------------|--------------------------------------|
| Bash                               | `command.exec`      | `command`                            |
| Read                               | `file.read`         | `path`, `sensitive`                  |
| Write / Edit / MultiEdit / NotebookEdit | `file.write`   | `path`, `sensitive`                  |
| WebFetch / WebSearch               | `network.connect`   | `url`, `decision: "intent"`          |
| anything else                      | `tool.use`          | tool_input keys verbatim             |

`sensitive` is set by the deterministic policy layer (env files, key
material, credential names, .ssh/.aws paths). It is advisory annotation
for correlation; it does not itself block anything.

`data` payload conventions (non-exhaustive):

- `file.*`: `{ "path": "...", "sensitive": bool }`
- `network.connect`: `{ "domain": "...", "ip": "...", "port": n, "decision": "allow"|"block", "reason": "...", "layer": "connect"|"dns" }`
- `finding`: scanner finding fields (see PreFlight finding schema)
- `incident`: `{ "rule_id": "...", "matched_event_ids": [...], ... }`
- `session.state`: `{ "from": "...", "to": "..." }`

Severity mapping for egress decisions: allowed = info; DNS-layer blocks =
low; allowlist/port blocks = medium; raw-IP or private-range attempts =
high.

## Correlation rules

- Events belonging to one logical activity chain share a `correlation_id`.
- The correlator evaluates rules over a per-session time window using
  `(session_id, timestamp)` ordering; correlation IDs link direct causal chains.
- The v1 high-confidence rule correlates a sensitive-resource access event with
  a subsequent non-allowlisted network attempt in the same session window.

## Normalization responsibilities

Raw sources are normalized at ingestion, before persistence:

| Raw source          | Normalized to                                  |
|---------------------|------------------------------------------------|
| Claude Code hooks   | `command.exec`, `file.read/write/delete`       |
| Proxy access log    | `network.connect` (with allow/block decision)  |
| Docker lifecycle    | `sandbox.*` events                             |
| Scanner JSON output | `finding`                                      |

## Honest observation limits

Hook-based observation captures agent tool calls, **not** syscalls. Activity
performed outside instrumented tool paths (e.g. a compiled binary run via a
shell command reading files directly) is not visible as `file.*` events.
Network egress remains enforced and logged at the topology/proxy layer
independently of hooks.

Additional integrity caveat: the hook script runs inside the container as the
same user as the agent. The agent can therefore tamper with its own raw hook
stream or rewrite project-level hook settings. Mitigations for v1: the host
tailer drains the raw stream continuously (tamper window is sub-second), and
enforcement never depends on hooks — filesystem isolation and network
topology are the authoritative boundaries.

## Versioning

Schema v1. Additive changes only (new optional fields, new types within
existing namespaces). Breaking changes require a major version bump and a
migration note here.
