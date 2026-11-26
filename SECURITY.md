# Security Policy

`pr-agent-public` is a FastMCP server with a coding-agent-CLI worker that reviews pull requests and orchestrates review swarm jobs. Because that work involves executing tooling against untrusted pull-request content and handling repository credentials, security is treated as a first-class design constraint rather than an afterthought. This document describes how to report a vulnerability privately and summarises the controls that protect the system. If you believe you have found a security issue, please report it through the private channel described below rather than a public issue.

## Reporting a Vulnerability

Please report vulnerabilities privately using GitHub's built-in **Private Vulnerability Reporting**: open the repository's **Security** tab, choose **Advisories**, and click **Report a vulnerability**. This creates a private advisory visible only to you and the maintainers.

Do **not** open a public issue, pull request, or discussion for a security vulnerability. Public disclosure before a fix is available puts every deployment at risk.

A useful report includes:

- A description of the vulnerability and the security impact you believe it has.
- The affected version or commit (this release is `0.1.0`).
- Reproduction steps, including any relevant configuration.
- The observed versus expected behaviour.
- A suggested fix or mitigation, if you have one.

You can expect an acknowledgement within **72 hours** of a report. Once a fix is ready, it is coordinated with you before any public disclosure, and you are credited if you wish to be.

## Supported Versions

This is the initial public release, so only the current `0.1.x` line is supported.

| Version | Supported |
| ------- | --------- |
| `0.1.x` | Yes       |

Security fixes are applied to the `0.1.x` line. There are no older release lines to backport to at this time.

## Security Architecture

Four mechanisms form the core of the security model. Each is enforced in code, not left to configuration discipline.

### HMAC Webhook Verification

Every GitHub webhook delivered to `POST /webhook/github` is verified with `hmac.compare_digest` over `"sha256=" + HMAC-SHA256(secret, raw_body)`. The `X-Hub-Signature-256` header must be present and start with `sha256=`; a missing or malformed signature is rejected with HTTP 401. A primary and a secondary secret (`GITHUB_WEBHOOK_SECRET`, `GITHUB_WEBHOOK_SECRET_SECONDARY`) may be configured, and comma-separated lists are accepted, so the secret can be rotated with zero downtime while both values verify during the overlap. Payloads are capped at 1 MB (HTTP 413), an optional delivery-timestamp freshness check rejects stale deliveries outside the allowed clock skew (HTTP 401), and a duplicate `X-GitHub-Delivery` id is rejected as a replay (HTTP 409). Rejections are audit-logged and counted, and the auditing path never turns a 401 into a 500. This matters because the webhook endpoint is the only unauthenticated ingress into the system, so authenticity, freshness, and replay resistance must be established before any payload is trusted.

### XML Prompt Fencing

All untrusted pull-request context — the PR body, the filtered diff, CI logs, and orchestrator command text — passes through `wrap_untrusted` in `agent/security.py` before it enters any prompt. The sanitiser strips ANSI escape sequences, caps length (adding a truncation marker when it does), escapes any embedded closing-tag variant (for example `</label>` with optional whitespace or casing) to `&lt;/label&gt;`, and then wraps the content in a labelled element such as `<untrusted_pr_context>…</untrusted_pr_context>`. This prevents a prompt-injection breakout in which attacker-controlled text forges a closing tag and escapes the fence to issue its own instructions to the model.

### SecretRedactor

`SecretRedactor` in `src/orchestrator/middleware/redactor.py` is a deterministic, high-precision regex scrubber applied to all outbound data. It detects and redacts PEM private-key blocks, GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), AWS access keys (`AKIA`, `ASIA`), `sk-`, `sk-proj-`, and `sk-ant-` API keys, JWTs, generic `Bearer` tokens, secret-named JSON or quoted fields, and `*_KEY` / `*_TOKEN` / `*_SECRET` / `*_PASSWORD` environment assignments. Payloads over 512 KB are truncated with a `[TRUNCATED]` marker before scanning to prevent regex denial of service, and the scan recurses over dictionaries, lists, tuples, and Pydantic models. Scrubbing runs off the event loop via `asyncio.to_thread`, and the `SecretScrubberMiddleware` FastMCP middleware scrubs `tools/call`, `resources/read`, and `prompts/get` results and **fails closed** — returning an error result rather than the raw payload — if scrubbing itself raises. The same redactor scrubs persisted job logs, model I/O records, and stored job commands, which are written with mode `0600`. This matters because review output and logs routinely echo repository content and tool output, and any of it may contain credentials that must never leave the process.

### Default-Deny Writes

Write access is off unless it is explicitly and legitimately enabled (`resolve_allow_writes` in `agent/security.py`). Webhook-originated jobs are **always** read-only, as are the read-only personas (`security-reviewer`, `scout`, `performance-engineer`, `db-migration-reviewer`). Fork or non-trusted pull requests — where the author is not `OWNER`, `MEMBER`, or `COLLABORATOR`, or where the head repository differs from the base repository — are read-only. In every other case, writes require an explicit opt-in. This matters because an automated reviewer that can write to a repository is a supply-chain risk; default-deny keeps the common path incapable of modifying code, and confines any write capability to explicitly trusted contexts.

### Defense-in-Depth Controls

- **Protected-path guard** (`assert_no_protected_paths`): CI workflows under `.github/workflows/**`, persona definitions, and checks manifests cannot be modified, and path traversal is rejected.
- **Blast-radius and verdict gate** (`src/orchestrator/tools/gated_pr.py`): a draft PR opens only when the blast radius is within limits, fewer than three strikes have been recorded, and an `APPROVED` security verdict with passing checks exists for the head commit; otherwise the gate fails closed and records a strike. A three-strike circuit breaker stops repeated failures.
- **Repository allowlist and slug validation**: only repositories on `ALLOWED_REPOSITORIES` are accepted (HTTP 403 otherwise), and repository slugs are validated.
- **Bearer-token RBAC** (`src/orchestrator/auth.py`): authenticated callers are scoped by per-caller repository allowlists.
- **Hardened subprocess environments**: `git` runs with `GIT_TERMINAL_PROMPT=0` and `GIT_CONFIG_NOSYSTEM=1` and no host secrets; the agent CLI runs with a secret-stripped environment allowlist that drops `*_SECRET` / `*_TOKEN` and known secret keys; static-analysis subprocesses run with a minimal environment and an empty `HOME`.
- **Structured audit logging**: tool calls and security verdicts are recorded in structured logs, and webhook rejections are counted, so security-relevant decisions are observable after the fact.