# AEGIS — a security enforcement layer for AI coding agents

**Repository:** `aegis-preflight-cli`
**Maintainer:** [Roshan Mallick](https://github.com/Roshan-Mallick) · Copyright (c) 2026 Roshan Mallick

AEGIS is an execution‑time security enforcement layer that sits between an AI coding agent and the project it works on. It treats the agent as **untrusted by design**, contains it inside a hardened sandbox, controls its network egress, records everything it does, and — before the agent is allowed to finish a task — runs deterministic security checks plus an optional **Local AI Exit Gate** that performs a final security review.

## What is AEGIS?

AEGIS is not a model and not a linter that runs once. It is a **control plane placed around the agent** so that the agent is never its own security authority:

```
Cloud AI Agent
      |
      v
     AEGIS
      |
      v
Sandboxed Project
      |
      v
Deterministic Security Checks
      |
      v
Local AI Exit Gate
  PASS / BLOCK
      |
      v
Safe Exit or Remediation
```

The agent works on a project that is bind‑mounted into a hardened Docker sandbox as `/workspace`. Everything outside that launch directory — the rest of your home directory, sibling projects, the host filesystem — is deliberately absent from the container's filesystem. Network egress is allowlisted at the DNS and HTTP/CONNECT proxy layers. Every tool call, file access, and command is observed and recorded into an append‑only event store.

When the agent reports that it is finished, AEGIS does **not** immediately let it exit. The change set is baselined and security‑scanned, and — if enabled — a local AI advisor reviews compact evidence of the whole task before the session may reach a `PASS` state.

## Why AEGIS?

AI coding agents have broad authority: they read and write files, execute arbitrary shell commands, invoke tools, and reach out to the network. Given direct access to a trusted repository, a single mistake or a maliciously prompted action can:

- read and leak secrets or sensitive files,
- modify or corrupt the codebase,
- reach external services the developer never approved,
- install dependencies that carry known vulnerabilities, or
- leave behind code with injection, auth‑bypass, or other security flaws.

AEGIS contains that authority and adds a **final security review** so that release, promotion, or "task complete" is a deliberate, inspection‑gated decision rather than the agent's word.

## Core Security Architecture

The components below are implemented in `internal/` and orchestrated by `internal/pipeline/`:

- **Project boundary + deterministic preflight** — the launch directory is baselined into an audit manifest at session start (`internal/workspace`). On exit, the live change set is scanned in place by deterministic scanners (`gitleaks` for secrets, `npm-audit` / `pip-audit` for vulnerable dependencies) and gated behind a BLOCK → FIX → relaunch → PASS loop (`internal/preflight`).
- **Sandbox enforcement** — a hardened Docker container (`--cap-drop ALL`, `no-new-privileges`, non‑root user `1000:1000`, `--read-only` root, private tmpfs for `/tmp`, `/run`, and the agent scratch space `/agent/cache`) running on a **minimal pruned runtime image** where `/home`, `/root`, `/var`, `/srv`, `/opt`, `/media`, `/mnt`, `/boot` are deleted from the filesystem itself and `/etc/passwd`/`/etc/group` are root‑owned and unreadable (`internal/sandbox`).
- **Network / API monitoring & enforcement** — a DNS + HTTP/CONNECT proxy sidecar (`cmd/aegis-proxy`) with domain allowlists per profile. `strict` permits only `api.anthropic.com`; `dev` also allows common package registries and git hosts. Raw IPs, private/loopback ranges, and non‑allowlisted ports are blocked by policy (`internal/network`, `internal/egress`).
- **Secret detection & redaction** — secrets are detected deterministically (gitleaks) and, wherever a value must travel toward the local AI advisor or the terminal, `Redact` masks recognizable secret shapes before they can reach a prompt (`internal/egress`, `internal/exitgate/redact.go`).
- **Compact security evidence** — the local advisor receives a small structured summary (paths, hashes, counts, command names, observed destinations, findings, tiny redacted snippets) capped at 16 KB, never the conversation or full file contents (`internal/exitgate/evidence.go`).
- **Local AI Exit Gate** — an optional final security review run against a self‑hosted OpenAI‑compatible model endpoint (`internal/exitgate`, `internal/model`).
- **Deterministic BLOCK overriding AI PASS** — the Local AI is advisory only. If the deterministic check blocks, the AI review is skipped entirely and the deterministic block is final.
- **AI BLOCK → remediation → re‑review** — an AI block writes a concise `.aegis/FIX_REQUEST.md` into the workspace and the agent is relaunched in the same session to fix and resubmit; the exit gate re‑reviews.
- **Fail‑closed on unavailable advisor** — if the advisor cannot be reached or its answer cannot be parsed, the session blocks by default (or passes with an explicit "advisory skipped" warning under an opt‑in `warn` policy). An unavailable advisor is never treated as an approval.
- **AEGIS_REPO_ROOT** — lets a globally installed `aegis` binary locate the source repository (which contains `cmd/aegis-proxy`) so the egress proxy sidecar can be (re)built when it is run from a directory other than the repo.

## Local AI Exit Gate

The cloud AI agent works on the project normally. When it reports that the task is finished, AEGIS does **not** immediately allow it to exit:

```
agent "I'm finished"
         |
         v
   AEGIS EXIT GATE
         |
         v
   LOCAL AI ADVISOR
   reviews compact evidence:
     • What changed?
     • Were security-sensitive files accessed?
     • Were APIs/network resources accessed?
     • Were secrets encountered?
     • Were unsafe changes introduced?
     • Are there security concerns?
         |
     PASS / BLOCK
         |
    allow exit  OR  remediation loop
```

The advisor returns a strict JSON verdict — `{"decision":"PASS"|"BLOCK","risk":"NONE"|...|"CRITICAL","summary":...,"findings":[...]}`.

**Important invariant:** the Local AI advisor is **advisory only**. A deterministic AEGIS BLOCK can **never** be overridden by an AI PASS. When the advisor blocks, AEGIS writes the remediation request (`.aegis/FIX_REQUEST.md`), keeps the agent in the workflow, and performs another review after remediation. If the advisor is unavailable, the system fails closed according to the configured policy (`block` by default, `warn` opt‑in).

## Security Evidence

The Local AI does **not** receive the agent conversation, source files, raw command output, or secrets. It receives compact security evidence generated by AEGIS (`internal/exitgate`), containing only what is needed for the review:

- task/request summary and network profile,
- changed‑file paths with size and a hash prefix (summarized by change counts; capped),
- executed command names (capped),
- security‑sensitive file accesses (paths only),
- observed network destinations with the proxy decision (permitted vs. blocked),
- scanner findings (severity, rule, file, line, message),
- correlated incident summaries,
- tiny redacted code snippets, only when a finding or sensitive access points at a file.

Evidence is redacted for secrets and capped to a fixed byte budget. Reviews are cached by a digest of the evidence so unchanged material between remediation retries is **never re‑sent** to the model.

## Quickstart / Fresh User Setup

### Prerequisites

- **Linux amd64** — required (the installer and the sandbox target Linux x86‑64; macOS/Windows are not supported).
- **Docker Engine** with the **daemon running** and your user able to talk to it (see the `docker` group note below).
- **Go 1.27+** — to build from source.
- **opencode** (for `aegis run opencode`) — the CLI agent launched inside the sandbox. Claude Code and Codex are detected too.
- **gitleaks** *(optional but recommended)* — host‑side secret scanner; the PreFlight gate reports `scanner-unavailable` (and blocks) if it is missing.
- **First‑run internet access** — `aegis init` builds the sandbox Docker images, and the first build may download base layers.

### Clone, build, initialize

```bash
git clone https://github.com/Roshan-Mallick/aegis-preflight-cli
cd aegis-preflight-cli

# Build the CLI
go build -o aegis ./cmd/aegis

# Build sandbox images and verify dependencies (first run may download layers)
./aegis init

# Verify your environment (Docker daemon, images, gitleaks)
./aegis doctor

# Launch opencode inside the hardened sandbox (strict network)
./aegis run opencode
```

### Docker permission (`docker` group)

A simple mistake here produces a confusing `permission denied` on the first run. Your user must be able to reach the Docker daemon:

```bash
sudo usermod -aG docker "$USER"
# log out and back in (or run 'newgrp docker') so the new group applies
```

> Note: The group membership only applies on a fresh login shell. If you just added yourself to `docker`, `docker ps` returning `permission denied` means the new group hasn't loaded — log out and back in, or run `newgrp docker`.

### Project directory ownership (UID 1000)

The sandbox runs as user `1000:1000` and the runtime image chowns `/workspace` to UID 1000. For the agent to read and write the mounted project, the launch directory must be owned by (or at least readable/writable by) UID 1000. If the agent cannot write files, check the project directory owner:

```bash
sudo chown -R 1000:1000 /path/to/your/project
```

### Credential persistence behavior

Agent credentials and tool caches are **not** read from your host. Inside the sandbox, `HOME` and `TMPDIR` point at `/agent/cache` — a private, ephemeral tmpfs created per container. Agent runtime state (e.g. `.local`, `.config`, opencode/Claude caches) lives there and is discarded when the container is killed. The only things AEGIS writes into your project are the observation hook files under `.aegis/` and hook settings (an existing `.claude/settings.json` or `.opencode/plugins/aegis.js` is backed up as `*.aegis-backup`).

### Common setup failures and exact fixes

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `permission denied` talking to Docker | user not in the `docker` group, or group not loaded in this shell | `sudo usermod -aG docker "$USER"` then re‑login / `newgrp docker`; `docker ps` to verify |
| `gitleaks not found` in `doctor` | gitleaks missing | install gitleaks or `go install github.com/gitleaks/gitleaks/v8@latest` |
| agent cannot write files in the sandbox | project dir not readable/writable by UID 1000 | `sudo chown -R 1000:1000 <project>` |
| `aegis init` "first run may download base layers" | image layers not yet cached locally | ensure internet is available the first time; after that images are cached |

## Usage

### Normal clone-based workflow

```bash
# Build + initialize once
go build -o aegis ./cmd/aegis
./aegis init
./aegis doctor

# Launch opencode in the sandbox (strict network by default)
./aegis run opencode

# Launch with dev network access (package registries, git, opencode.ai)
./aegis run --net dev opencode

# Open an interactive sandbox shell (split TUI)
./aegis run

# Run a one-shot command
./aegis run "ls -la"

# Inspect session state / list sessions / follow live events
./aegis status
./aegis sessions
./aegis report --follow <session-id>

# Post-exit: validate and record a verified session
./aegis preflight <session-id>
./aegis apply <session-id>
```

### Installed / global binary workflow

Install via the one‑line installer (downloads a release binary, falls back to a source build; requires Go for the source fallback):

```bash
curl -sSL https://raw.githubusercontent.com/Roshan-Mallick/aegis-preflight-cli/main/scripts/install.sh | bash
```

It installs `aegis` into `~/bin` (override with `AEGIS_INSTALL_DIR`). When running an installed binary from a directory **outside** the source repository, point `AEGIS_REPO_ROOT` at the cloned repo so the egress proxy sidecar can be built:

```bash
export AEGIS_REPO_ROOT="$HOME/aegis-preflight-cli"
aegis init
aegis run opencode
```

## Demo

### Working demo

[▶ View / download the working demo](assets/working.mp4)

The demo walks through a real session: the agent works on a project inside the sandbox, AEGIS observes its file/tool/network activity, the deterministic preflight scan and the Local AI Exit Gate run at the end, and the session is either released or routed back into the remediation loop.

## Security Model

AEGIS layers two distinct kinds of control:

- **Deterministic enforcement** — the hard, reliable boundary: sandbox isolation, network allowlisting, secret scanning, the PreFlight BLOCK gate. These never depend on a model and can never be overridden.
- **Local AI reasoning** — an optional *advisory* final review that reasons over compact evidence to catch issues a signature scanner might not. It can add a BLOCK, but it **cannot** grant a pass that deterministic checks refuse.
- **Sandbox / proxy controls** — the mechanical containment the AI cannot bypass: the pruned runtime filesystem, `--cap-drop ALL`, non‑root user, read‑only root, and DNS + HTTP/CONNECT egress control.
- **Fail‑closed behavior** — when an advisory review cannot run, it is never treated as approval; the session blocks (or passes with an explicit "advisory skipped" warning only under the opt‑in `warn` policy).

The Local AI **does not replace** deterministic security controls. Both are useful, but only the deterministic sandbox grants access, and only deterministic checks can permit a final exit.

## Project Structure

```
cmd/aegis/              CLI entry points (run, init, doctor, report, apply, preflight, status, ...)
cmd/aegis-proxy/        Network egress proxy + DNS sidecar
internal/agent/         Agent process interaction metadata
internal/agents/        Agent detection metadata
internal/config/        Layered configuration (aegis.json)
internal/correlate/     Correlation engine (time-window pattern detection)
internal/egress/        Egress classification + secret redaction
internal/events/        Canonical event schema + append-only JSONL store
internal/exitgate/      Local AI Exit Gate (evidence, redaction, review)
internal/findings/      Finding schema + scanner parsers
internal/images/        Embedded Dockerfiles (agent, proxy) + image names
internal/model/         Self-hosted (local) advisory model client
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
internal/workspace/     PROJECT_ROOT boundary, manifest baseline + in-place diff/apply
scripts/install.sh      Installer
docs/                   Threat model and event-schema documentation
```

## Testing

```bash
go vet ./...
go test ./... -race
```

These commands pass on the current tree. Some test files (`*_live_test.go`, the e2e suite) exercise a live Docker sandbox and are skipped automatically when Docker or `gitleaks` is unavailable.

## Configuration

Environment variables and config keys read by the source:

| Setting | Type | Purpose |
|---------|------|---------|
| `AEGIS_REPO_ROOT` | env | Path to the source repo so a globally installed binary can build the proxy sidecar. |
| `AEGIS_EXIT_GATE` | env (`1`) / `aegis.json` `exit_gate.enabled` | Enable the Local AI Exit Gate (disabled by default). |
| `AEGIS_STATE_DIR` | env | Override the session state directory (default `~/.local/state/aegis`). |
| `AEGIS_ALLOWLIST` | env | Comma-separated egress allowlist for the proxy (default `api.anthropic.com`). |
| `AEGIS_UPSTREAM_DNS` | env | Upstream DNS resolver for the proxy (default `1.1.1.1`). |
| `AEGIS_DOCKER_BIN` | env | Override the `docker` binary path. |
| `AEGIS_REBUILD_PROXY` | env | Force the proxy image to be rebuilt even if present. |
| `AEGIS_INSTALL_DIR` | env | Install target directory for `scripts/install.sh`. |
| `aegis.json` | file | Project-level config: `default_network`, `gitleaks_path`, `scanners`, `limits`, `allowed_domains`, `exit_gate`. |

Enable the exit gate in the project's `aegis.json` (config is also layered from `~/.config/aegis/config.json`):

```json
{
  "exit_gate": {
    "enabled": true,
    "on_unavailable": "block",
    "base_url": "http://127.0.0.1:8080",
    "model": "qwen2.5-coder-1.5b-instruct"
  }
}
```

The exit gate is **disabled by default**. `on_unavailable` is `"block"` by default (fail‑closed) or `"warn"`. `base_url` is the local model server root (the client appends `/v1/chat/completions`; default `http://127.0.0.1:8080`) and `model` defaults to `qwen2.5-coder-1.5b-instruct`.

## Limitations / Notes

- **Linux + Docker is the primary target.** macOS/Windows support is not provided.
- **Secrets scanning relies on `gitleaks`**, and dependency auditing on `npm-audit` / `pip-audit`; they must be present (inside the sandbox) for full coverage.
- **Allowlists are domain-based.** They block at the DNS/HTTP layer; they are not a full outbound data‑loss‑prevention system.
- **The Local AI advisor is advisory only.** Verdicts are deterministic and scanner‑driven; the AI can add a block but cannot override a deterministic one.
- **Agent runtimes are ephemeral.** `HOME`/`TMPDIR` live on a per‑container tmpfs, so agent credential caches are not persisted across sessions.
- Network profile `strict` permits only `api.anthropic.com`; use `--net dev` for package registries, git hosts, and `opencode.ai`.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright (c) 2026 [Roshan Mallick](https://github.com/Roshan-Mallick) — see [AUTHORS.md](AUTHORS.md) and [OWNERSHIP_EVIDENCE.md](OWNERSHIP_EVIDENCE.md).
