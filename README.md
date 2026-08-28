# AEGIS — Zero-Trust Security Runtime for AI Coding Agents

**Repository:** `aegis-preflight-cli`

AEGIS is a security runtime and control plane for AI coding agents. It treats the agent as **untrusted by design**: the agent can only write to an isolated copy of the project, its network egress is controlled, all of its observations are recorded, and changes reach the trusted codebase only after PreFlight security validation passes.

## What problem it solves

AI coding agents operate with broad, unchecked authority: they can read any file, write anywhere, run arbitrary shell commands, and reach out to the network. When an agent is given direct access to a trusted repository, a single mistake or a maliciously prompted action can leak secrets, corrupt the codebase, or exfiltrate data before anyone notices.

AEGIS places an enforcement boundary around the agent so that it is **never its own security authority**:

- The agent runs in an isolated sandbox with no direct access to the host filesystem.
- Network egress is allowlisted at the network layer (DNS + HTTP/CONNECT proxy).
- Every tool call, file access, and command is observed and recorded.
- Changes never reach the trusted project until PreFlight validation passes.

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                       Trusted Project                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │             AEGIS Control Plane                      │   │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────────────┐  │   │
│  │  │  Session   │ │ Snapshot  │ │  Event Store      │  │   │
│  │  │  Manager   │ │ & Diff    │ │  (JSONL, 0600)    │  │   │
│  │  └───────────┘ └───────────┘ └───────────────────┘  │   │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────────────┐  │   │
│  │  │ PreFlight  │ │  Network  │ │   Correlation     │  │   │
│  │  │  Scanner   │ │  Gateway  │ │   Engine          │  │   │
│  │  └───────────┘ └───────────┘ └───────────────────┘  │   │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────────────┐  │   │
│  │  │  Response  │ │   TUI     │ │  Evidence Bundle  │  │   │
│  │  │  Engine    │ │ (live)    │ │  (committed)      │  │   │
│  │  └───────────┘ └───────────┘ └───────────────────┘  │   │
│  └───────────────────┬─────────────────────────────────┘   │
│                      │  write (verified diff only)          │
│                 ┌────▼─────┐                                │
│                 │  Sandbox  │ ← network gateway (DNS+proxy) │
│                 │ (Docker)  │ ← observation hooks           │
│                 └──────────┘                                │
└────────────────────────────────────────────────────────────┘
```

The control plane runs fully **offline** — it makes no external calls of its own. All network decisions, session state, and scanning logic execute locally. The only network traffic in a session is the agent's own, and it is constrained by the allowlist.

## Key features

- **Agent-contained sandbox** — hardened Docker isolation (`--cap-drop ALL`, `no-new-privileges`, non-root user, read-only root, tmpfs overlays for `/root`, `/home`, `/var`, `/boot`).
- **Egress control** — DNS allowlist + HTTP/CONNECT proxy allowlist; raw-IP and private/loopback destinations are blocked by policy.
- **Deterministic observation** — hooks injected into the workspace capture every tool call before it executes, normalized into a canonical event stream.
- **Event store** — authoritative, append-only JSONL events (mode `0600`) that live outside the agent's reach.
- **PreFlight enforcement** — gates every promotion to the trusted project behind a security scan with a BLOCK → FIX → relaunch → PASS cycle.
- **Remediation loop** — same-session remediation: blocked agents are told what to fix, can relaunch bounded by the same sandbox, and are rescanned.
- **Correlation engine** — detects patterns (e.g., sensitive file access followed by a blocked egress attempt) within a time window.
- **Real-time TUI** — a split-pane terminal with the live agent PTY on one side and the AEGIS security feed on the other, plus a stable status bar.
- **Evidence preservation** — the container is snapshotted before any destructive action so evidence survives an agent kill.

## Offline vs. network-aware mode

AEGIS has two network operating modes:

| Mode | Flag | Behavior |
|------|------|----------|
| **strict (default)** | `--net strict` | Only `api.anthropic.com` is reachable. Everything else, including raw IPs and private ranges, is blocked. Suitable for the highest-assurance workloads. |
| **dev** | `--net dev` | Adds common development hosts to the allowlist (`registry.npmjs.org`, `pypi.org`, `proxy.golang.org`, `github.com`, `opencode.ai`, etc.). Enables dependency fetching and toolchains inside the sandbox. |

The **control plane itself is always offline** — it never phones home. Its decisions are deterministic and computed locally. The optional local advisor is a self-hosted LLM served from `127.0.0.1` and is advisory only; it never affects the security verdict.

## How the security / remediation workflow works

```
ENTRY → SNAPSHOT → SANDBOX → AGENT (ACTIVE) → AGENT_FINISHED → SECURITY_SCAN
                                                                     │
                                             ┌─────────┐  ┌──────────┴──────────┐
                                             │  PASS   │  │       BLOCK         │
                                             └────┬────┘  └──────────┬──────────┘
                                                  │                   │
                                          RELEASE_READY           WRITE FIX REQUEST
                                                  │                   │
                                              apply to          agent relaunches
                                             trusted project       & rescans
                                                                   (≤ 3 cycles)
```

1. A session is created and the trusted project is snapshotted into an isolated workspace.
2. The agent launches inside the sandbox under simultaneous file / tool / network monitoring.
3. When the agent finishes, its workspace is security-scanned (secrets via gitleaks, vulnerable dependencies via `npm-audit` / `pip-audit`).
4. If findings are non-blocking, the session passes and changes can be promoted with `aegis apply`.
5. If blocking findings exist, a fix request is written and the agent may re-run (same session) to remediate; it is rescanned. This BLOCK → FIX → relaunch → PASS cycle runs at most 3 times.
6. Every meaningful event is recorded to the session's authoritative event store for audit.

## Installation / build

**Requirements:** Linux (first-class support), Go 1.27+, Docker, and `gitleaks` (host-side).

### From source

```bash
git clone <your-aegis-preflight-cli-url>
cd aegis-preflight-cli
go build -o aegis ./cmd/aegis
```

### One-line installer

```bash
curl -sSL https://raw.githubusercontent.com/<owner>/aegis-preflight-cli/main/scripts/install.sh | bash
```

The installer downloads a release binary (falls back to a source build), installs it into `~/bin`, and optionally builds the sandbox Docker images. Adjust `REPO` and the download URL in `scripts/install.sh` to match your fork before publishing a release.

## How to run

```bash
# Build the sandbox image and initialize environment checks
aegis init

# Verify your environment (Docker, gitleaks, sandbox image)
aegis doctor

# Launch an interactive sandbox shell (split TUI)
aegis run

# Launch opencode in the sandbox (strict network)
aegis run opencode

# Launch opencode with dev network access
aegis run --net dev opencode

# Run a one-shot command in the sandbox
aegis run "ls -la"

# Inspect session state
aegis status

# See live session events
aegis report --follow <session-id>
```

## Example commands

```bash
# Full lifecycle: sandbox → agent → preflight → promote
aegis run --net dev opencode "add a feature"
aegis preflight <session-id>
aegis apply <session-id>
```

## How to run tests

```bash
# Build everything
go build ./...

# Run all unit tests with race detection
go test -count=1 -race ./...

# Run a single package
go test -count=1 -race ./internal/preflight/...

# Run live integration tests (requires Docker + gitleaks)
go test -count=1 -v -run Integration ./internal/preflight/...
go test -count=1 -v -run Integration ./internal/response/...

# Run end-to-end tests
go test -count=1 -v -run EndToEnd ./internal/e2e/...
```

Some tests (those named `*_live_test.go`) talk to Docker and a live sandbox and will be skipped when Docker is unavailable. Task runner `aegis e2e`/pipeline tests run without a live daemon.

## Project structure

```
cmd/aegis/              CLI entry points (run, init, doctor, report, apply, status, ...)
cmd/aegis-proxy/        Network egress proxy + DNS sidecar binary
internal/agent/         Detected agent metadata
internal/agents/        Agent auto-detection helpers
internal/config/        Configuration loading
internal/correlate/     Correlation engine (time-window pattern detection)
internal/e2e/           End-to-end integration tests
internal/egress/        Egress classification + secret redaction
internal/events/        Canonical event schema + JSONL store
internal/findings/      Finding schema + scanner parsers
internal/images/        Embedded Dockerfiles (agent, proxy)
internal/model/         Local (offline) advisory model client
internal/network/       Egress gateway lifecycle + network profiles
internal/observer/      Hook injection + normalization + tailer + live feed
internal/paths/         Path constants (state dir, sessions)
internal/pipeline/      Full session lifecycle orchestration
internal/policy/        Sensitive-path classification
internal/preflight/     PreFlight scan controller + verified diff
internal/report/        Markdown report renderer
internal/response/      Incident response + evidence bundles
internal/sandbox/       Docker container management + isolation verification
internal/session/       Session state machine + manager
internal/tui/           Bubbletea split TUI (PTY, feed, status bar)
internal/workspace/     Snapshot + diff + apply + manifest
scripts/install.sh      Installer
docs/                   Threat model and event-schema documentation
```

## Documentation

- [Event Schema](docs/EVENT-SCHEMA.md) — the canonical event format shared by all components.
- [Threat Model](docs/THREAT-MODEL.md) — detailed security boundaries and STRIDE/PASTA analysis.

## Current project status

Early-stage but functional (`v0.1.0`). The core end-to-end pipeline works: sandbox launch, agent execution, file/tool/network observation, PreFlight scanning, and the BLOCK/FIX/remediation loop are implemented and covered by unit, live, and end-to-end tests. The split TUI renders the live agent terminal and security feed in real time.

## Known limitations

- **Linux + Docker primary target.** macOS/Windows support is not provided.
- **Secrets scanning relies on `gitleaks`** and dependency auditing on `npm-audit` / `pip-audit`; these must be available inside the sandbox image for full coverage.
- **Allowlists are domain-based**; they block at the DNS/HTTP layer, not as a full outbound data-loss-prevention system.
- **The local advisor is advisory only.** It never gates promotion; verdicts are deterministic and scanner-driven.

## License

MIT
