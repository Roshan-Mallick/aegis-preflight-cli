# AEGIS Threat Model

**Methodology:** STRIDE per-element + PASTA risk scoring
**Severity/Likelihood:** Qualitative framework (Critical/High/Moderate/Low × High/Medium/Low)
**MITRE ATT&CK:** Mapped to Enterprise + Containers matrix
**Version:** 1.0 — August 2026

---

## 1. System Overview

AEGIS is a zero-trust security runtime for AI coding agents. The agent is treated as
untrusted. AEGIS controls where it runs, what it reads, what it changes, where it
connects, what data may leave, how its behavior is observed, and whether its changes
reach the trusted project.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY 1                           │
│                     HOST / CONTROL PLANE                           │
│                                                                     │
│  aegis binary (Go, offline, no external calls)                      │
│    ├── Session Manager        ├── Event Store (JSONL, mode 0600)   │
│    ├── Workspace Snapshot     ├── Correlation Engine                │
│    ├── PreFlight Scanner      ├── Response Engine                   │
│    └── TUI                    └── Network Gateway                   │
│                                                                     │
│  TRUSTED PROJECT (never mounted to agent)                           │
│                                                                     │
│ ┌─────────────────────────── TRUST BOUNDARY 2 ────────────────────┐ │
│ │                   AEGIS SANDBOX NETWORK                         │ │
│ │                   (Docker internal bridge)                       │ │
│ │                                                                  │ │
│ │  ┌──────────────────┐       ┌──────────────────────────┐        │ │
│ │  │  AGENT CONTAINER │       │  PROXY SIDECAR           │        │ │
│ │  │  (untrusted)     │──────▶│  (AEGIS-controlled)      │────┼──┼──▶ Internet
│ │  │                  │       │  - Domain allowlist       │  only   │
│ │  │  RW: workspace   │       │  - DNS control            │ allowed │
│ │  │  RO: /agent/bin  │       │  - Raw IP blocked         │ dest   │
│ │  │  No host access  │       │  - Logs every attempt     │        │ │
│ │  └──────────────────┘       └──────────────────────────┘        │ │
│ │                                                                  │ │
│ │  TRUST BOUNDARY 3: Network ↔ External                           │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  TRUST BOUNDARY 4: Workspace ↔ Trusted Project                     │
│  TRUST BOUNDARY 5: Agent ↔ Observations                            │
│  TRUST BOUNDARY 6: PreFlight ↔ Promotion                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Trust Boundaries

### TB-1: Host ↔ Container (Kernel-enforced)

| Property | Enforcement |
|----------|------------|
| Filesystem | Only workspace copy mounted at `/workspace` (RW). No host FS mounts. |
| Capabilities | `--cap-drop ALL` — zero Linux capabilities retained |
| Privileges | `--security-opt no-new-privileges` — no setuid escalation |
| User | `--user 1000:1000` — unprivileged non-root |
| Resources | `--memory 2g --cpus 2 --pids-limit 512` |
| Network | `--network none` by default; `internal` bridge when proxy active |
| Docker socket | Never mounted; verified by `VerifyIsolation()` |

**Boundary type:** Kernel-enforced. Holds against the workload.

### TB-2: Workspace ↔ Trusted Project

| Property | Enforcement |
|----------|------------|
| Snapshot | `workspace.Snapshot()` copies project content; no hard/symlink to source |
| Symlinks | Skipped during snapshot; rejected in `ValidateChanges()` |
| Path traversal | `validRel()` rejects `../` in change paths |
| Exclusions | `.git`, `.aegis`, `.claude`, `node_modules`, `__pycache__`, etc. |
| Validation | `workspace.ValidateChanges()` checks conflicts + traversal + symlinks |
| Apply gate | `workspace.Apply()` requires `RELEASE_READY` state |

**Boundary type:** Software-enforced. Holds against honest and moderately adversarial agents.

### TB-3: Network ↔ External

| Property | Enforcement |
|----------|------------|
| Default | `--network none` — zero connectivity |
| Strict profile | Only `api.anthropic.com` (or configured origin) allowed |
| Dev profile | Origin + registries (npmjs, pypi, github) |
| DNS | Controlled by proxy sidecar — NXDOMAIN for non-allowlisted |
| Raw IP | Blocked at evaluation layer — `net.ParseIP()` detection |
| Private IPs | `isRestricted()` blocks loopback, private, link-local, unspecified |
| Ports | Only 80, 443 allowed |
| Logging | Every attempt logged as canonical `network.connect` event |

**Boundary type:** Network-topology enforced. Agent has no route to internet except through proxy.

### TB-4: Agent ↔ Observations

| Property | Enforcement |
|----------|------------|
| Hook injection | `observer.InjectHooks()` embeds hooks into workspace |
| Normalization | `observer.NormalizeHook()` maps Claude tools → canonical events |
| Storage | Append-only JSONL, mode 0600, session-dir (outside workspace) |
| Self-observation | Hooks observe themselves — modification is visible |
| Integrity | No cryptographic signing (v1 limitation) |

**Boundary type:** Cooperative. Honest workloads see their own events. Adversarial agents cannot delete events (outside workspace).

### TB-5: PreFlight ↔ Promotion

| Property | Enforcement |
|----------|------------|
| Scanners | gitleaks (host), npm-audit, pip-audit |
| Fail-closed | Missing scanner → `scanner-unavailable` finding (blocking) |
| BLOCK/FIX | Up to 3 cycles; FIX_REQUEST.md sent to agent |
| Verified diff | SHA256 manifest comparison; recorded as artifacts |
| State gate | `RELEASE_READY` is terminal — cannot revert |

**Boundary type:** Deterministic. No LLM in the enforcement path.

### TB-6: Data Egress (Context Classification)

| Property | Enforcement |
|----------|------------|
| Connection-level | Domain allowlist enforced at proxy |
| File-level | `policy.IsSensitivePath()` classifies sensitive reads |
| Context policy | `egress.Classify()` categorizes data as ALLOWED/BLOCKED |
| Redaction | `egress.Redact()` strips sensitive content before external flow |
| TLS limitation | **Not enforced in v1** — see Section 7 |

**Boundary type:** Partial. Connection-level is enforced; payload-level is advisory in v1.

---

## 3. Threat Analysis (STRIDE per Element)

### 3.1 Agent Container (Process)

| STRIDE | Threat | Severity | Likelihood | Mitigation | Residual |
|--------|--------|----------|------------|------------|----------|
| **S**poofing | Agent impersonates AEGIS components | Low | Low | Agent has no access to AEGIS internal IPC; workspace is its only interface | Minimal — agent could forge hook output within workspace |
| **T**ampering | Agent modifies hook scripts to suppress events | Moderate | Medium | Hooks observe themselves; normalization produces events regardless of hook content; agent modifications to `.aegis/bin/hook.sh` are themselves observed | Agent could modify hook to emit garbage events; correlation engine may miss patterns |
| **R**epudiation | Agent denies performing a file write | Low | Low | All writes captured by hooks as canonical events with timestamps; append-only store | Hook-level, not syscall-level — compiled binaries bypass hooks |
| **I**nformation Disclosure | Agent reads host files outside workspace | High | Medium | `--cap-drop ALL`, no host mounts, `VerifyIsolation()` validates mounts post-start | Docker escape (kernel vulnerability) bypasses all controls |
| **D**enial of Service | Agent exhausts container resources | Low | Medium | `--memory 2g --cpus 2 --pids-limit 512` | Agent can still consume full allocation within limits |
| **E**levation of Privilege | Agent escapes container to host | Critical | Low | `--cap-drop ALL`, `no-new-privileges`, non-root user, Docker isolation | Kernel exploit required; see TCB-001 |

### 3.2 Proxy Sidecar (Process)

| STRIDE | Threat | Severity | Likelihood | Mitigation | Residual |
|--------|--------|----------|------------|------------|----------|
| **S**poofing | Agent forges proxy logs | Low | Low | Proxy runs in separate container; agent cannot write to proxy's stdout | Agent could emit fake `network.connect` events via hook |
| **T**ampering | Agent modifies proxy configuration | Low | Low | Proxy has no shared filesystem with agent; config baked into image | None — no attack surface |
| **R**epudiation | Proxy connection decision not recorded | Low | Low | Every decision logged as canonical event; events appended to session store | None — defense-in-depth |
| **I**nformation Disclosure | Proxy leaks DNS resolution data | Moderate | Low | DNS resolves only allowlisted domains; NXDOMAIN for rest | NXDOMAIN confirms domain is blocked (information leak) |
| **D**enial of Service | Proxy crashes under load | Moderate | Medium | Proxy is stateless; restart recovers. Agent DNS fails closed (NXDOMAIN) | Brief window during restart |
| **E**levation of Privilege | Agent gains proxy's network access | High | Low | Proxy on separate container; internal bridge only; agent has no route to proxy's uplink | None if topology intact |

### 3.3 Workspace (Data Store)

| STRIDE | Threat | Severity | Likelihood | Mitigation | Residual |
|--------|--------|----------|------------|------------|----------|
| **S**poofing | Agent creates fake workspace copy | Low | Low | Workspace created by AEGIS before agent starts; agent only has RW to designated path | None |
| **T**ampering | Agent modifies `.aegis/` internal state | Moderate | Medium | Agent has RW to workspace including `.aegis/` within it; FIX_REQUEST.md is advisory | Agent could delete FIX_REQUEST.md or modify hooks |
| **R**epudiation | Agent denies file changes | Low | Low | Manifest + SHA256 before/after; diff is deterministic | None |
| **I**nformation Disclosure | Workspace leaks to other containers | Low | Low | Internal Docker bridge; no cross-container mounts | Agent could write to shared workspace and another container reads it (not applicable in single-agent v1) |
| **D**enial of Service | Agent fills workspace disk | Low | Medium | Host filesystem limits; workspace is ephemeral per session | None — within container limits |
| **E**levation of Privilege | Agent uses workspace symlinks to escape | High | Low | Symlinks skipped in snapshot; `ValidateChanges()` rejects symlinks; path traversal guard | None — structural defense |

### 3.4 Event Store (Data Store)

| STRIDE | Threat | Severity | Likelihood | Mitigation | Residual |
|--------|--------|----------|------------|------------|----------|
| **S**poofing | Agent forges events in store | Moderate | Low | Store at session-dir (outside workspace); mode 0600; append-only | Agent cannot write outside container's filesystem |
| **T**ampering | Agent modifies past events | High | Low | JSONL append-only; no deletion API; mode 0600 | Agent could truncate file if it had access (it doesn't) |
| **R**epudiation | Events missing for an action | Moderate | Medium | Hook-level observation — not syscall-level; compiled binaries bypass | Rogue binary actions invisible at hook level |
| **I**nformation Disclosure | Events expose secrets | Moderate | Low | Events record file paths and tool names, not file contents; `--redact` in gitleaks | Hook could capture file content in edge cases |
| **D**enial of Service | Agent generates massive event volume | Low | Medium | Ring buffer in TUI; events append to file (disk-bound) | Large JSONL files may slow analysis |
| **E**levation of Privilege | Agent gains write access to store | High | Low | Store outside workspace; container has no mount to session-dir | None — structural defense |

### 3.5 Docker Daemon (TCB)

| STRIDE | Threat | Severity | Likelihood | Mitigation | Residual |
|--------|--------|----------|------------|------------|----------|
| **T**ampering | Agent exploits Docker vulnerability | Critical | Low | Docker daemon is TCB; AEGIS uses hardened flags; `VerifyIsolation()` post-start | Known CVEs in Docker/runc can escape |
| **E**levation of Privilege | Container escape via kernel | Critical | Low | `--cap-drop ALL`, `no-new-privileges`, non-root; defense-in-depth layers | Kernel privilege-escalation bug = escape |

---

## 4. Attack Trees

### Attack Tree 1: Secret Exfiltration

```
GOAL: Exfiltrate .env contents from trusted project
│
├── PATH A: Direct host access (BLOCKED)
│   ├── Mount host filesystem → No mount configured
│   ├── Read /etc/passwd → No host mount
│   └── Docker socket → Never mounted
│
├── PATH B: Workspace escape (BLOCKED)
│   ├── Symlink to host → Symlinks skipped + rejected
│   ├── Path traversal (../) → validRel() guard
│   └── .aegis/ manipulation → Advisory only; events still recorded
│
├── PATH C: Network exfiltration (BLOCKED/DETECTED)
│   ├── Direct curl to attacker.com → DNS NXDOMAIN + proxy 403
│   ├── Raw IP connection → Blocked by network.Evaluate()
│   ├── POST to allowed domain (api.anthropic.com) → ALLOWED but logged
│   │   └── v1 limitation: payload inspection not enforced
│   └── DNS tunnel → Proxy controls DNS; NXDOMAIN for non-allowlisted
│
└── PATH D: Correlated detection (DETECTED)
    ├── Sensitive file read → Hook event (file.read + sensitive flag)
    ├── Blocked egress attempt → Proxy event (decision=block)
    └── SENSITIVE_EGRESS_ATTEMPT_V1 → INCIDENT → evidence preserved → kill
```

### Attack Tree 2: Container Escape

```
GOAL: Gain host code execution from agent container
│
├── PATH A: Kernel exploit (OUT OF SCOPE)
│   └── Requires unpatched kernel vulnerability
│
├── PATH B: Docker misconfiguration (MITIGATED)
│   ├── --privileged → Not set
│   ├── --cap-add → Not set (--cap-drop ALL)
│   ├── /var/run/docker.sock → Not mounted
│   └── --pid host → Not set
│
├── PATH C: Runtime exploit (MITIGATED)
│   ├── CVE-2019-5736 (runc) → Fixed in modern Docker
│   ├── cgroup escape → no-new-privileges + non-root
│   └── Mount API abuse → seccomp (future v2)
│
└── PATH D: Supply chain (MITIGATED)
    ├── Malicious base image → Pre-built agent image
    └── Compromised dependency → npm-audit + pip-audit in PreFlight
```

### Attack Tree 3: Evidence Destruction

```
GOAL: Agent destroys evidence of its actions
│
├── PATH A: Delete event store (BLOCKED)
│   ├── Session dir outside workspace → Agent has no mount
│   └── Mode 0600 → Agent runs as uid 1000; store owned by host user
│
├── PATH B: Modify hooks to stop recording (PARTIALLY BLOCKED)
│   ├── Modify .aegis/bin/hook.sh → Observed by observer
│   ├── Modify .claude/settings.json → Agent has RW; but AEGIS re-injects on next session
│   └── Delete hook → Next tool call fails to log; correlation gap
│
├── PATH C: Kill container before evidence preserved (BLOCKED)
│   └── docker commit runs BEFORE docker kill in response engine
│
└── PATH D: Overflow event store (DEGRADED)
    └── Generate massive events → Disk fills; but events already written
```

---

## 5. Risk Summary Matrix

| ID | Component | STRIDE | Threat | Severity | Likelihood | Mitigation Status |
|----|-----------|--------|--------|----------|------------|-------------------|
| C-001 | Container | EoP | Container escape via kernel exploit | Critical | Low | Mitigated (defense-in-depth); residual = kernel CVE |
| C-002 | Container | Info Disc | Host filesystem access | High | Medium | Mitigated (no mounts, isolation verified) |
| C-003 | Container | DoS | Resource exhaustion within limits | Low | Medium | Mitigated (memory/cpu/pid limits) |
| P-001 | Proxy | Info Disc | DNS NXDOMAIN reveals blocked domains | Moderate | Low | Accepted (v1 limitation) |
| P-002 | Proxy | DoS | Proxy crash disrupts DNS | Moderate | Medium | Mitigated (stateless, fail-closed DNS) |
| W-001 | Workspace | Tamper | Agent modifies .aegis/ state | Moderate | Medium | Accepted (advisory; events still recorded) |
| W-002 | Workspace | EoP | Symlink escape to host | High | Low | Mitigated (symlinks skipped + rejected) |
| E-001 | Event Store | Repudiation | Hook-level observation gaps | Moderate | Medium | Accepted (v1 limitation; syscall = v2) |
| E-002 | Event Store | Tamper | Agent modifies events | High | Low | Mitigated (store outside workspace) |
| N-001 | Network | Info Disc | Payload exfil via allowed domain | High | Medium | **NOT MITIGATED** (v1 limitation; TLS) |
| T-001 | TCB | EoP | Docker/runc vulnerability | Critical | Low | Accepted (TCB dependency) |
| T-002 | TCB | Tamper | Docker daemon compromise | Critical | Low | Accepted (TCB dependency) |

---

## 6. Mitigations by STRIDE Category

### Spoofing
- Agent identity is untrusted by design — no authentication to AEGIS internals
- Hook events are attributed by source (hook/proxy/scanner) not by agent claim
- Session IDs are UUIDv4, generated by AEGIS, not agent

### Tampering
- Workspace changes validated by `workspace.ValidateChanges()` before promotion
- Event store is append-only, mode 0600, outside workspace
- PreFlight findings are deterministic (gitleaks, npm-audit, pip-audit)
- Evidence bundle written BEFORE container kill (`docker commit` before `docker rm -f`)

### Repudiation
- All agent actions produce canonical events with timestamps
- Events are correlated across sources (hook + proxy + scanner)
- Incident reports include full event timeline with correlation IDs

### Information Disclosure
- Workspace isolation prevents host file access
- Network allowlist prevents unauthorized data egress
- `policy.IsSensitivePath()` flags sensitive file reads
- **Limitation:** Payload-level inspection not enforced in v1 (TLS)

### Denial of Service
- Container resource limits prevent host exhaustion
- Proxy is stateless — crash recovery is fast
- Event store is disk-bound (no in-memory accumulation)

### Elevation of Privilege
- `--cap-drop ALL` removes all Linux capabilities
- `--security-opt no-new-privileges` prevents setuid escalation
- Non-root user (uid 1000) in container
- Docker socket never mounted
- **Limitation:** Kernel exploit bypasses all controls (v2: Landlock/eBPF)

---

## 7. Honest Limitations

### 7.1 TLS Payload Inspection Not Enforced

The proxy handles HTTP/CONNECT tunneling as a passthrough. It enforces domain-level
allowlisting but does NOT terminate or inspect TLS payloads.

**Impact:** An agent could POST stolen secrets to `api.anthropic.com` (an allowed
destination) as part of a legitimate API call. Domain-level logging cannot see the
payload content.

**v2 path:** TLS inspection via sandbox-local CA certificate, or context brokering
at the provider side.

**Documentation obligation:** This limitation must appear in every security report
and in the README. AEGIS v1 provides connection-level control, not payload-level control.

### 7.2 Hook-Level Observation, Not Syscall-Level

AEGIS observes agent activity through Claude Code hooks (PreToolUse/PostToolUse).
These capture tool calls (Bash, Read, Write, etc.) but NOT:
- Direct syscalls from compiled binaries
- File operations by non-hooked processes
- Kernel-level network activity

**Impact:** A rogue compiled binary could read files and make network connections
without hook observation. The NETWORK still gets caught at the proxy.

**v2 path:** eBPF-based syscall observation (cilium/ebpf, Falco).

### 7.3 Docker ≠ microVM

Docker containers share the host kernel. A kernel privilege-escalation vulnerability
can escape the container.

**Impact:** Defense-in-depth (capabilities, no-new-privileges, non-root) raises the
bar but does not eliminate escape risk.

**v2 path:** Firecracker microVMs or gVisor for kernel-level isolation.

### 7.4 Single Agent Support

v1 supports Claude Code as the primary agent adapter. Other agents (Codex, aider)
require adapter implementation.

### 7.5 No Cryptographic Event Integrity

Events are JSONL files with mode 0600. There is no digital signature or Merkle tree.
An attacker with host access could modify events.

### 7.6 No Resource Consumption Limits Beyond Container

AEGIS limits container resources but does not monitor host-level resource consumption
by the Docker daemon itself.

---

## 8. Threat Agent Profiles

### Profile A: Misconfigured Agent (Most Likely)

An AI coding agent that follows instructions but makes mistakes — reads `.env` when
asked to "use the environment variables", sends configuration to an API endpoint.

**Capability:** Tool-level access within workspace
**Motivation:** Follows user/attacker prompt instructions
**Likelihood:** High
**Mitigation:** Workspace isolation + network allowlist + PreFlight

### Profile B: Prompt-Injected Agent (Moderate Likelihood)

An agent whose context is poisoned by malicious file content or user prompt injection,
causing it to attempt unauthorized actions.

**Capability:** Tool-level access; may attempt sensitive reads + network
**Motivation:** Attacker-controlled via prompt injection
**Likelihood:** Medium
**Mitigation:** Sensitive path detection + correlation engine + incident response

### Profile C: Adversarial Agent (Low Likelihood, High Impact)

An agent specifically designed to escape sandbox, exfiltrate data, or destroy evidence.

**Capability:** May attempt container escape, hook modification, event tampering
**Motivation:** Deliberate attack
**Likelihood:** Low (requires deliberate adversarial design)
**Mitigation:** Defense-in-depth; kernel-level isolation in v2

### Profile D: Supply Chain Compromise (Low Likelihood)

A compromised dependency or base image that executes malicious code during agent operation.

**Capability:** Full container context
**Motivation:** Backdoor, cryptomining, lateral movement
**Likelihood:** Low (pre-built images; dependency auditing)
**Mitigation:** npm-audit + pip-audit in PreFlight; minimal base images

---

## 9. Non-Goals (Explicitly Out of Scope for v1)

| Non-Goal | Reason | Future Path |
|----------|--------|-------------|
| TLS payload inspection | Requires CA management + provider cooperation | v2: sandbox-local CA |
| Syscall-level observation | Requires eBPF + kernel module | v2: cilium/ebpf |
| Kernel-level isolation | Requires microVM or gVisor | v2/v3: Firecracker |
| Multi-agent coordination | Single agent per session | v3 |
| Cryptographic event integrity | Performance + complexity | v2: signed JSONL |
| Resource consumption monitoring | Host-level visibility | v2: cgroup accounting |
| LLM-based threat analysis | Advisory only; never enforcement | v2: Ollama analyst |
| Interactive approve/deny | Auto-enforce + report | v2: developer-in-the-loop |

---

## 10. Verification Checklist

Before claiming AEGIS v1 is secure, verify:

- [ ] TEST-1: `cat ~/.ssh/id_rsa` inside sandbox → file does not exist
- [ ] TEST-2: Agent modifies files → only workspace changes; trusted project untouched
- [ ] TEST-3: `curl https://api.anthropic.com` → allowed through proxy
- [ ] TEST-4: `curl https://evil.com` → blocked + logged
- [ ] TEST-5: Raw IP connection → blocked
- [ ] TEST-6: Sensitive read + blocked egress → incident → evidence preserved → kill
- [ ] TEST-7: Planted secret → gitleaks blocks → agent fixes → rescan passes
- [ ] TEST-8: AEGIS control plane makes zero external network calls
- [ ] `VerifyIsolation()` passes against live container
- [ ] Evidence bundle contains all 10 artifacts
- [ ] Reports document TLS limitation
- [ ] All 15 packages pass `go test -race ./...`
