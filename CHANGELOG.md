# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-26

Initial public release.

### Added

- FastMCP server exposing pull-request review and swarm tools with bearer-token authentication and per-caller role-based access control (RBAC).
- GitHub webhook receiver that automatically triggers a security review on pull request opened and synchronize events, with HMAC-SHA256 signature verification, replay protection, and a repository allowlist.
- Persona-based reviewers with frontmatter validation and read-only enforcement.
- Coding-agent-CLI worker with isolated per-job workspaces, timeouts, whole-process-group cleanup, and heartbeats.
- Default-deny write governance: writes disabled unless explicitly and legitimately enabled, a protected-path guard, blast-radius limits, a 3-strike circuit breaker, and an APPROVED-verdict gate before draft pull requests.
- XML prompt fencing that sanitizes untrusted pull-request context before it reaches model prompts.
- Outbound secret redaction across tool results, persisted job logs, and model I/O records.
- Structured audit logging of security-relevant events.
- `guard` CLI providing ruff and ty wrappers plus custom guardrail rules.
- MIT License.