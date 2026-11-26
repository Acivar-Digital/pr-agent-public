"""G1 #1 — webhook signature hardening, clock-skew, rotation, audit trail."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import server.app as m
from agent.security import REPLAY_TTL_SECONDS
from agent.workspace import _remote_url, _run_git, _sanitize_title

BODY = b'{"zen":"Keep it logically awesome."}'


def _sig(secret: str, body: bytes = BODY) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class _FakeAudit:
    def __init__(self) -> None:
        self.events: list[dict] = []

    async def log_event(self, **kwargs) -> None:
        self.events.append(kwargs)


@pytest.fixture
def client() -> TestClient:
    """No context manager: the MCP session manager can only run once per process."""
    return TestClient(m.app)


@pytest.fixture
def audit(monkeypatch: pytest.MonkeyPatch) -> _FakeAudit:
    fake = _FakeAudit()
    monkeypatch.setattr("agent.audit_shared.get_audit_logger", lambda: fake)
    return fake


@pytest.fixture
def secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "primary-secret")
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET_SECONDARY", raising=False)


def _post(client: TestClient, signature: str, delivery: str, **extra: str):
    headers = {
        "X-GitHub-Event": "ping",
        "X-Hub-Signature-256": signature,
        "X-GitHub-Delivery": delivery,
        **extra,
    }
    return client.post("/webhook/github", content=BODY, headers=headers)


def test_primary_secret_verifies(secrets: None) -> None:
    assert m._verify_github_signature(BODY, _sig("primary-secret")) is True


def test_secondary_secret_verifies_during_rotation(
    secrets: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET_SECONDARY", "secondary-secret")
    assert m._verify_github_signature(BODY, _sig("secondary-secret")) is True
    assert m._verify_github_signature(BODY, _sig("primary-secret")) is True


def test_comma_separated_secret_list_is_supported(
    secrets: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "a-secret,b-secret")
    assert m._verify_github_signature(BODY, _sig("b-secret")) is True


def test_no_secret_configured_rejects_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET_SECONDARY", raising=False)
    assert m._verify_github_signature(BODY, _sig("anything")) is False


def test_bad_signature_returns_401_and_is_audited(
    client: TestClient, secrets: None, audit: _FakeAudit
) -> None:
    resp = _post(client, _sig("wrong-secret"), "d-1")
    assert resp.status_code == 401
    assert [e["payload"]["reason"] for e in audit.events] == ["bad_signature"]
    payload = audit.events[0]["payload"]
    assert "signature" not in payload
    assert payload["signature_len"] == len(_sig("wrong-secret"))


def test_stale_timestamp_returns_401_and_is_audited(
    client: TestClient, secrets: None, audit: _FakeAudit
) -> None:
    stale = str(int(time.time()) - (m.WEBHOOK_MAX_SKEW_SECONDS + 60))
    resp = _post(
        client,
        _sig("primary-secret"),
        "d-2",
        **{"X-GitHub-Timestamp": stale},
    )
    assert resp.status_code == 401
    assert [e["payload"]["reason"] for e in audit.events] == ["stale_timestamp"]


def test_future_timestamp_returns_401(
    client: TestClient, secrets: None, audit: _FakeAudit
) -> None:
    future = str(int(time.time()) + (m.WEBHOOK_MAX_SKEW_SECONDS + 60))
    resp = _post(
        client,
        _sig("primary-secret"),
        "d-5",
        **{"X-GitHub-Timestamp": future},
    )
    assert resp.status_code == 401
    assert [e["payload"]["reason"] for e in audit.events] == ["stale_timestamp"]


def test_malformed_timestamp_returns_401(
    client: TestClient, secrets: None, audit: _FakeAudit
) -> None:
    resp = _post(
        client,
        _sig("primary-secret"),
        "d-3",
        **{"X-GitHub-Timestamp": "not-a-number"},
    )
    assert resp.status_code == 401
    assert [e["payload"]["reason"] for e in audit.events] == ["bad_timestamp"]


def test_fresh_timestamp_passes_auth(
    client: TestClient,
    secrets: None,
    audit: _FakeAudit,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(m, "register_webhook_delivery", lambda *a, **k: True)
    resp = _post(
        client,
        _sig("primary-secret"),
        "d-4",
        **{"X-GitHub-Timestamp": str(int(time.time()))},
    )
    assert resp.status_code == 200
    assert audit.events == []


def test_bad_signature_is_checked_before_replay_cache(
    client: TestClient, secrets: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        m,
        "register_webhook_delivery",
        lambda *a, **k: calls.append("cache") or True,
    )
    resp = _post(client, _sig("wrong-secret"), "d-6")
    assert resp.status_code == 401
    assert calls == [], "unauthenticated caller must not reach the replay cache"


def test_replay_window_is_five_minutes() -> None:
    assert REPLAY_TTL_SECONDS == 300


def test_sanitize_title_falls_back_when_empty() -> None:
    assert _sanitize_title("   ") == "Automated PR update"
    assert _sanitize_title("Real title") == "Real title"


def test_remote_url_is_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GIT_REMOTE_TEMPLATE", "  https://github.com/{slug}.git  ")
    assert (
        _remote_url("example-org/sample-repo")
        == "https://github.com/example-org/sample-repo.git"
    )


def test_git_failure_redacts_token_case_insensitively(tmp_path: Path) -> None:
    async def run() -> str:
        with pytest.raises(RuntimeError) as exc:
            await _run_git(
                ["--definitely-not-a-flag"],
                cwd=tmp_path,
                auth_token="ghp_SUPERSECRETTOKEN",
            )
        return str(exc.value)

    message = asyncio.run(run())
    assert "ghp_SUPERSECRETTOKEN" not in message
    assert "extraheader" not in message.lower()


@pytest.mark.parametrize("value", ["inf", "-inf", "nan"])
def test_non_finite_timestamp_returns_401(
    client: TestClient, secrets: None, audit: _FakeAudit, value: str
) -> None:
    resp = _post(
        client,
        _sig("primary-secret"),
        "d-7",
        **{"X-GitHub-Timestamp": value},
    )
    assert resp.status_code == 401
    assert [e["payload"]["reason"] for e in audit.events] == ["bad_timestamp"]


def test_max_skew_follows_replay_ttl() -> None:
    assert m.WEBHOOK_MAX_SKEW_SECONDS == REPLAY_TTL_SECONDS
