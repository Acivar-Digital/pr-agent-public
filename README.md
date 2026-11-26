# pr-agent

A self-hosted **PR review and swarm orchestration gateway**. It exposes a FastMCP
tool surface and a GitHub webhook endpoint that turn pull requests and chat-style
tool calls into isolated, sandboxed coding-agent jobs — each running in its own
git worktree, guarded by a default-deny security model, and gated by static
analysis before any branch is pushed or review is posted.

The guiding principle is **KISS**: a small FastAPI + FastMCP process, a thin
queue backed by SQLite, and one worker per job. No workflow engine, no message
broker, no Kubernetes.

---

## Overview

pr-agent sits between an LLM client (a coding agent, a CI step, or a GitHub
webhook) and your repositories. It offers two entry points:

- **A FastMCP server** (Streamable HTTP at `/mcp`) exposing read-only repo
  intelligence and job-dispatch tools, callable by any MCP-capable client.
- **A GitHub webhook** (`POST /webhook/github`) that verifies the delivery
  signature and automatically queues a security review for new or updated pull
  requests.

Both paths converge on the same execution engine: a **persona worker** that
clones the target repo into a **dedicated, throwaway git worktree**, runs a
coding CLI (`agy` or `omp`) against it, and — only if every gate passes —
commits, pushes an `agent/*` branch, and opens a draft PR or posts a review.

Personas are plain Markdown files with YAML frontmatter. They encapsulate the
runner, model, and write permissions, so callers pick a *role* (`scout`,
`security-reviewer`, …) rather than a model name.

---

## Architecture

```
                ┌─────────────────────────────┐
   MCP client ─▶│  FastAPI + FastMCP gateway   │
   (LLM/CI)     │  server/app.py               │
                │  • /mcp        (MCP tools)   │
                │  • /webhook/github           │
                │  • /metrics, /health         │
                └──────────────┬──────────────┘
                               │ dispatch_job (SQLite queue)
                               ▼
                ┌─────────────────────────────┐
                │  Job store + scheduler       │
                │  agent/job_store.py          │
                │  • semaphore (max concurrent)│
                │  • heartbeat / stale reaper  │
                │  • 3-strike circuit breaker  │
                └──────────────┬──────────────┘
                               │ execute_pr_task
                               ▼
   ┌───────────────────────────────────────────────────────┐
   │  Isolated worker (one git worktree per job)            │
   │  agent/pr_worker.py  +  agent/workspace.py             │
   │                                                        │
   │  prepare worktree ─▶ run persona CLI ─▶ parse output   │
   │        │                                    │        │
   │        ▼                                    ▼        │
   │  commit/push agent/*  ◀── verification ── blast      │
   │  (never main)              (checks)         radius     │
   │        │                                               │
   │        ▼                                               │
   │  gated draft PR / review comment                       │
   └───────────────────────────────────────────────────────┘
```

### Request flow

1. **Ingress.** A tool call arrives over MCP, or GitHub POSTs a webhook.
   `ZeroBodyReadAuthMiddleware` authenticates the caller and binds an identity;
   `RBACMiddleware` authorizes the target repository; the secret-scrubber
   middleware is attached for outbound redaction.
2. **Queueing.** `dispatch_job` records a row in SQLite and launches the worker
   coroutine under a concurrency semaphore. It returns immediately with a
   `job_id` and an `assigned_branch`.
3. **Isolation.** The worker prepares a fresh `git worktree` checked out on a
   per-job branch (`agent/<persona>/<job_id>`), cloned/fetched through a
   token-scoped, hooks-disabled git invocation.
4. **Execution.** The persona's runner (`agy` or `omp`) runs headless against
   the worktree in a secret-stripped environment with a hard timeout and
   process-group kill on overrun.
5. **Gating.** Before anything leaves the machine, the diff passes a
   blast-radius check, the repo's own check manifest (loaded from `main`), and a
   read-only security-reviewer pass whose verdict must be an explicit
   `APPROVED`. Only then is a draft PR opened or a review comment posted.

### Components

| Path | Responsibility |
|---|---|
| `server/app.py` | FastAPI app, MCP tools, webhook verification, middleware wiring |
| `server/location.py` | Resolves this machine's identity from `config/location.json` |
| `server/health_metrics.py` | `/metrics` + `/health` observability, webhook rejection counters |
| `agent/job_store.py` | SQLite job queue, scheduler, heartbeats, circuit breaker |
| `agent/pr_worker.py` | Executes one job end-to-end and produces a `PRTaskReport` |
| `agent/workspace.py` | Git worktree lifecycle, commit/push, PR + review REST calls |
| `agent/personas.py` | Loads persona Markdown (repo `.agents/personas/` or local) |
| `agent/security.py` | Allowlists, protected-path rules, untrusted wrapping, safe envs |
| `agent/verdict.py` | Fail-closed security verdict derivation |
| `agent/static_checks.py` | Isolated ruff/bandit/gitleaks on changed files |
| `agent/diff_filter.py` | Strips lockfile/binary noise and caps diff size |
| `src/orchestrator/` | Secret redactor, RBAC/auth middleware, blast-radius + check manifest gates, gated PR opener |
| `guard/` | Standalone AST quality gatekeeper (`uv run guard`) |
| `personas/` | Built-in fallback personas (`scout`, `security-reviewer`) |

---

## Security Model

The system treats **all PR content, diffs, CI logs, and task text as untrusted
input** and is built to fail closed at every boundary.

### Untrusted XML fencing

Every piece of external text injected into a prompt is wrapped by
`wrap_untrusted()` in an `<untrusted_pr_context>…</untrusted_pr_context>`
fence. The wrapper strips ANSI escapes, caps length, and escapes any
`</untrusted_pr_context>` sequence in the payload so fenced content cannot
break out and impersonate instructions. The MCP server instructions reinforce
this: text inside the fence is data, never instructions.

### Default-deny writes

Write access is denied by default and can only be narrowed, never widened, by
a caller:

- `resolve_allow_writes()` returns `False` unconditionally for webhook-triggered
  jobs and for read-only personas (`scout`, `security-reviewer`,
  `performance-engineer`, `db-migration-reviewer`).
- Fork PRs and non-trusted authors (`author_association` outside
  OWNER/MEMBER/COLLABORATOR) are forced read-only.
- Persona frontmatter is validated with `ConfigDict(extra="forbid", strict=True)`,
  so a typo like `allow_writes: "yes"` fails closed instead of silently
  granting write access.
- Workers may only ever push to `agent/*` branches; `main`/`master` pushes are
  refused, and protected paths (CI workflows, personas, check manifests) are
  rejected before a commit is created.

### SecretRedactor

An outbound middleware (`SecretScrubberMiddleware`) scrubs every tool result,
prompt response, and resource read through `SecretRedactor` — a deterministic,
high-precision regex scrubber covering private keys, GitHub/AWS/API tokens,
JWTs, bearer tokens, JSON secret fields, and `.env`-style assignments. It
truncates-before-scrub for payloads over 512 KB (regex-DoS guard), runs off the
event loop via `asyncio.to_thread`, and **fails closed**: if scrubbing itself
errors, the raw result is never returned. The same redactor sanitizes persisted
job logs, model-I/O records, progress messages, and git error output.

### Blast-radius guard

Before a PR is opened, `evaluate_blast_radius()` parses the unified diff and
enforces hard caps — **≤ 10 files** and **≤ 400 changed LoC** (lockfiles
excluded) — while blocking protected paths across *both* sides of every patch
(closing rename/delete bypasses). An unparseable diff fails closed. Exceeding a
cap records a strike; three strikes trips the circuit breaker.

### AST quality gatekeeper (`uv run guard`)

`guard` is a standalone AST/token scanner that acts as the quality gatekeeper
for Python changes. It runs seven pure-AST rules — truncation placeholders,
`type: ignore` suppression, anti-slop style (bare/broad excepts, mutable
defaults, unsafe `open`), sync blocking calls in async functions, banned silent
fallbacks, cyclomatic-complexity/nesting depth, and Pydantic models missing
`extra='forbid'` — plus optional `ruff` and `ty` subprocess checks. Each finding
is a structured What/Why/How diagnostic. It is designed to run in pre-commit,
in CI, and as the verification step for agent-authored changes.

### Defense in depth

- **Auth & RBAC.** `ZeroBodyReadAuthMiddleware` authenticates without ever
  reading the request body (avoiding SSE/Streamable-HTTP deadlocks): a secret
  URL path, a Bearer token, or localhost-only `/metrics`. `RBACMiddleware`
  authorizes every tool call against the caller's allowed repositories, resolving
  the target repo across direct `repo`, `job_id`, and split `owner`/`repo`
  argument shapes.
- **Webhook hardening.** HMAC-SHA256 signature verification (with zero-downtime
  secondary-secret rotation), a replay cache keyed on `X-GitHub-Delivery`, a
  clock-skew window, and a 1 MB payload cap.
- **Repo allowlist.** `ALLOWED_REPOSITORIES` gates every tool; repo slugs are
  validated against path traversal.
- **Isolated execution.** Git runs with a minimal env (no host secrets, no
  system gitconfig, hooks disabled); the persona CLI runs in a secret-stripped
  allowlist env; the check manifest runs each command with `shell=False`, an
  offline/secret-free env, and process-group isolation.
- **Manifest trust.** The verification manifest (`.vps-checks.toml`) is loaded
  strictly from `main`, never the PR head, so a PR cannot inject check commands.

---

## Quickstart

### Prerequisites

- Python ≥ 3.11
- [`uv`](https://docs.astral.sh/uv/)
- `git`
- A GitHub fine-grained PAT and (for webhook mode) a webhook secret
- One or both coding CLIs on `PATH` for the runners your personas use
  (`agy` and/or `omp`)

### 1. Install

```bash
uv sync
```

### 2. Configure the environment

```bash
cp .env.example .env
# edit .env and fill in the required values
```

Key variables (see `.env.example` for the full list and inline guidance):

| Variable | Purpose |
|---|---|
| `MCP_SECRET_PATH` | 48-char URL-safe secret for the MCP endpoint path |
| `GITHUB_TOKEN` | Fine-grained PAT (Contents R/W, Pull requests R/W, Issues R/W, Metadata R) |
| `GITHUB_WEBHOOK_SECRET` | HMAC secret for webhook verification |
| `GITHUB_WEBHOOK_SECRET_SECONDARY` | Optional second secret for zero-downtime rotation |
| `ALLOWED_REPOSITORIES` | Comma-separated allowlist of `owner/repo` slugs |
| `AGY_BIN` / `AGY_MODEL` / `AGY_TIMEOUT_SECONDS` | Runner binary, default model, per-job timeout |
| `JOB_DB_PATH` / `WORKSPACES_DIR` / `PERSONAS_DIR` | Local host paths for state |

### 3. Configure machine identity

`server` refuses to start without a valid `config/location.json`. Copy the
example and set it for this machine:

```bash
cp config/location.json.example config/location.json
# edit host/port/profile and the peer block for this machine
```

The file declares which environment (`dev` / `production`) and bind address
this checkout is, plus where its peer lives. The repository's parent directory
arbitrates whether the declared environment is trustworthy, so a file copied
between machines is rejected rather than silently mis-binding.

### 4. Run

```bash
uv run python -m server
```

This resolves the bind address from `config/location.json` and serves:

- `POST /webhook/github` — GitHub webhook receiver
- `/mcp` (and `/gemini/<MCP_SECRET_PATH>/mcp`) — FastMCP Streamable HTTP
- `/metrics`, `/health` — observability (metrics restricted to localhost or
  admin auth)

---

## Testing

```bash
# run the test suite
uv run pytest

# run the AST quality gatekeeper over the codebase
uv run guard .
```

`uv run guard` also supports targeted modes used by hooks and CI:

```bash
uv run guard --staged            # staged Python files (pre-commit)
uv run guard --changed           # modified/untracked Python files
uv run guard --base origin/main  # files changed vs a base ref (PR)
uv run guard --no-external       # skip the ruff/ty subprocess checks
```

The gatekeeper exits non-zero on any finding, so it drops directly into a
pre-commit hook (`scripts/install_hooks.sh`) or a CI step.

---

## License

See [LICENSE](LICENSE).