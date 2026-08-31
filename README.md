# AEGIS

**An execution‑time security enforcement layer for AI coding agents.**

The agent runs inside a controlled boundary, not on a trusted machine with full access. AEGIS sits between the agent and the project, and treats the agent as **untrusted by design**:

```
AI Coding Agent
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
      |
      v
   PASS / BLOCK
```

---

## Demo

[▶ View / download the working demo](assets/working.mp4)

The demo walks through a real session: the agent works on a project inside the sandbox, AEGIS observes its file/tool/network activity, the deterministic preflight scan and the Local AI Exit Gate run at the end, and the session is either released or routed back into the remediation loop.

> Note: GitHub may not render an inline HTML `<video>` player for repository‑relative paths, so the demo is provided as a direct link to the tracked file.

---

## What is AEGIS?

AEGIS is a **control plane placed around an AI coding agent** so that the agent is never its own security authority. It is not a model and not a one‑time linter.

The agent works on a project bind‑mounted into a **hardened Docker sandbox** as `/workspace`. Everything outside that launch directory — the rest of the home directory, sibling projects, the host filesystem — is deliberately absent from the container's filesystem. **Network egress is allowlisted** at the DNS and HTTP/CONNECT proxy layers. Every tool call, file access, and command is observed and recorded into an **append‑only event store**.

When the agent reports that it is finished, AEGIS does **not** immediately let it exit:

- the change set is **baselined** and scanned by deterministic security checks, and
- if enabled, a **Local AI Exit Gate** reviews compact security evidence of the whole task before the session may reach a `PASS` state.

Why this matters: AI coding agents have broad authority — they read and write files, execute arbitrary shell commands, invoke tools, and reach out to the network. Unchecked, a mistake or a maliciously prompted action can leak secrets, corrupt code, reach services the developer never approved, or introduce vulnerable/insecure changes. AEGIS contains that authority and adds a **final, inspection‑gated security review**.

---

## How It Works

1. A developer/AI agent starts work on a project.
2. AEGIS establishes the controlled execution environment (the sandbox, proxy, and session).
3. The project is inspected and executed **inside** the sandbox as `/workspace`.
4. Outbound network access is mediated through the DNS + HTTP/CONNECT proxy allowlist.
5. Every tool call, file access, and command is observed and recorded.
6. On completion, **deterministic security checks** run against the change set.
7. Compact **security evidence** is built, with secrets redacted.
8. The **Local AI Exit Gate** performs a final review of that evidence.
9. A `PASS` allows completion; a `BLOCK` prevents completion and may trigger remediation and re‑review.

---

## Core Security Architecture

```
         Cloud AI Agent
               |
               v
             AEGIS
               |
      +--------+--------+
      |                 |
      v                 v
Sandbox / Proxy    Deterministic
Network Control    Security Checks
      |                 |
      +--------+--------+
               |
               v
        Security Evidence
        (secrets redacted)
               |
               v
        Local AI Exit Gate
               |
        +------+------+
        |             |
      PASS           BLOCK
        |             |
        v             v
     Finish       Remediate
                     |
                     v
                  Re-review
```

The components below are implemented in `internal/` and orchestrated by `internal/pipeline/`:

- **Project boundary + deterministic preflight** — the launch directory is baselined into an audit manifest at session start (`internal/workspace`). On exit, the live change set is scanned in place by deterministic scanners (`gitleaks` for secrets, `npm-audit` / `pip-audit` for vulnerable dependencies) and gated behind a BLOCK → FIX → relaunch → PASS loop (`internal/preflight`).
- **Sandbox enforcement** — a hardened Docker container (`--cap-drop ALL`, `no-new-privileges`, non‑root user `1000:1000`, `--read-only` root, private tmpfs for `/tmp`, `/run`, and the agent scratch space `/agent/cache`) running on a **minimal pruned runtime image** where `/home`, `/root`, `/var`, `/srv`, `/opt`, `/media`, `/mnt`, `/boot` are deleted from the filesystem itself and `/etc/passwd`/`/etc/group` are root‑owned and unreadable (`internal/sandbox`).
- **Network / API monitoring & enforcement** — a DNS + HTTP/CONNECT proxy sidecar (`cmd/aegis-proxy`) with domain allowlists per profile. `strict` permits only `api.anthropic.com`; `dev` also allows common package registries and git hosts. Raw IPs, private/loopback ranges, and non‑allowlisted ports are blocked by policy (`internal/network`, `internal/egress`).
- **Secret detection & redaction** — secrets are detected deterministically and, wherever a value must travel toward the local AI advisor or the terminal, `Redact` masks recognizable secret shapes before they can reach a prompt (`internal/egress`, `internal/exitgate/redact.go`).
- **Compact security evidence** — the local advisor receives a small structured summary (paths, hashes, counts, command names, observed destinations, findings, tiny redacted snippets) capped at 16 KB — never the conversation or full file contents (`internal/exitgate/evidence.go`).
- **Local AI Exit Gate** — an optional final security review run against a self‑hosted OpenAI‑compatible model endpoint (`internal/exitgate`, `internal/model`).
- **Deterministic BLOCK overriding AI PASS** — the Local AI is advisory only; if the deterministic check blocks, the AI review is skipped entirely and the deterministic block is final.

---

## Security Model

### Deterministic preflight
Security‑sensitive checks are **deterministic** and are not delegated entirely to an AI model. Sandbox isolation, network allowlisting, secret scanning, and the PreFlight BLOCK gate never depend on a model and can never be overridden.

### Network enforcement
Outbound network access is controlled through the sandbox/proxy mechanism: domain allowlists per profile, with raw IPs, private/loopback ranges, and non‑allowlisted ports blocked by policy.

### Secret redaction
Sensitive values are removed/masked before security evidence reaches the Local AI advisor, so the AI never sees the conversation, full source files, raw command output, or secrets.

### AI Exit Gate
The Local AI receives compact security evidence for a final review and returns a strict JSON verdict (`PASS`/`BLOCK`, a risk level, a summary, and findings).

### BLOCK precedence
A deterministic security BLOCK **cannot** be overridden by an AI PASS. The AI can add a BLOCK, but it cannot grant a pass that deterministic checks refuse.

### Remediation loop
When the Local AI returns `BLOCK`, AEGIS writes a concise `.aegis/FIX_REQUEST.md` into the workspace, keeps the agent in the workflow, and performs another review after remediation.

### Fail closed
If the advisor is unavailable or cannot safely complete its role, the security decision **fails closed** (`block` by default) rather than treating an unavailable advisor as approval. An opt‑in `warn` policy records an explicit "advisory skipped" warning instead.

---

## Key Features

- **Deterministic security preflight** — gitleaks secret scan + `npm-audit` / `pip-audit` dependency scan gated behind a BLOCK → FIX → relaunch → PASS loop
- **Sandboxed execution** — hardened Docker container on a pruned, minimal runtime image
- **Network / proxy enforcement** — DNS + HTTP/CONNECT egress proxy with `strict` / `dev` allowlist profiles
- **Local AI Exit Gate** — optional final review against a self‑hosted OpenAI‑compatible model
- **Compact security evidence** — 16 KB‑capped summary; secrets redacted before review
- **Deterministic BLOCK precedence** — an AI PASS can never override a deterministic BLOCK
- **AI remediation / review loop** — BLOCK writes `.aegis/FIX_REQUEST.md` and triggers re‑review
- **Fail‑closed advisor behavior** — unavailable advisor is never treated as approval
- **AEGIS_REPO_ROOT support** — a globally installed binary can build the proxy sidecar from any directory
- **Clone‑based workflow** — build, init, run, and verify from a local checkout
- **Go implementation** — single static CLI plus a proxy sidecar

---

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
assets/                 Working demo video (assets/working.mp4)
```

---

## Quick Start

### Prerequisites

- **Linux amd64** — required (the installer and the sandbox target Linux x86‑64; macOS/Windows are not supported).
- **Docker Engine** with the **daemon running** and your user able to talk to it.
- **Go 1.27+** — to build from source.
- **opencode** (for `aegis run opencode`) — the CLI agent launched inside the sandbox. Claude Code and Codex are also detected.
- **gitleaks** *(strongly recommended)* — host‑side secret scanner; the PreFlight gate reports `scanner-unavailable` (and blocks) if it is missing.
- **First‑run internet access** — `aegis init` builds the sandbox Docker images; the first build may download base layers.

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

### Common setup notes

- **`docker` group** — your user must be able to reach the Docker daemon. `sudo usermod -aG docker "$USER"`, then log out and back in (or run `newgrp docker`). If `docker ps` still returns `permission denied`, the new group hasn't loaded in the current shell.
- **Project directory ownership (UID 1000)** — the sandbox runs as user `1000:1000` and chowns `/workspace` to UID 1000, so the launch directory must be readable/writable by UID 1000: `sudo chown -R 1000:1000 /path/to/your/project`.
- **Credential persistence** — agent credentials and tool caches are **not** read from your host. Inside the sandbox, `HOME` and `TMPDIR` point at `/agent/cache` — a private, ephemeral tmpfs created per container and discarded when the container is killed. AEGIS only writes observation hooks (`.aegis/` and hook settings; an existing `.claude/settings.json` or `.opencode/plugins/aegis.js` is backed up as `*.aegis-backup`).

### Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `permission denied` talking to Docker | user not in the `docker` group, or group not loaded in this shell | `sudo usermod -aG docker "$USER"`, then re‑login / `newgrp docker`; `docker ps` to verify |
| `gitleaks not found` in `doctor` | gitleaks missing | install gitleaks or `go install github.com/gitleaks/gitleaks/v8@latest` |
| agent cannot write files in the sandbox | project dir not readable/writable by UID 1000 | `sudo chown -R 1000:1000 <project>` |
| `aegis init` "first run may download base layers" | image layers not yet cached locally | ensure internet is available the first time; after that images are cached |

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

---

## Usage

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

---

## Testing

```bash
go vet ./...
go test ./... -race
```

Both commands pass on the current tree. Some test files (`*_live_test.go`, the e2e suite) exercise a live Docker sandbox and are skipped automatically when Docker or `gitleaks` is unavailable.

---

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

---

## Limitations / Notes

- **Linux + Docker is the primary target.** macOS/Windows support is not provided.
- **Secrets scanning relies on `gitleaks`**, and dependency auditing on `npm-audit` / `pip-audit`; they must be present (inside the sandbox) for full coverage.
- **Allowlists are domain‑based.** They block at the DNS/HTTP layer; they are not a full outbound data‑loss‑prevention system.
- **The Local AI advisor is advisory only.** Verdicts are deterministic and scanner‑driven; the AI can add a block but cannot override a deterministic one.
- **Agent runtimes are ephemeral.** `HOME`/`TMPDIR` live on a per‑container tmpfs, so agent credential caches are not persisted across sessions.
- Network profile `strict` permits only `api.anthropic.com`; use `--net dev` for package registries, git hosts, and `opencode.ai`.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright (c) 2026 [Roshan Mallick](https://github.com/Roshan-Mallick) — see [AUTHORS.md](AUTHORS.md) and [OWNERSHIP_EVIDENCE.md](OWNERSHIP_EVIDENCE.md).
