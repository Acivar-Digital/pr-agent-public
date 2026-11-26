from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent.job_store import init_db
from server.health_metrics import inc_webhook_rejection, router


def _make_client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _point_paths_at_tmp(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("JOB_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("WORKSPACES_DIR", str(tmp_path / "workspaces"))


def test_health_ok_with_real_db(tmp_path, monkeypatch):
    _point_paths_at_tmp(tmp_path, monkeypatch)
    init_db()

    resp = _make_client().get("/health")

    assert resp.status_code == 200
    body = resp.json()
    assert body["db_ok"] is True
    assert body["workspaces_free_mb"] > 0


def test_health_returns_503_on_low_disk(tmp_path, monkeypatch):
    _point_paths_at_tmp(tmp_path, monkeypatch)
    init_db()

    class _FakeUsage:
        free = 10 * 1024 * 1024

    from server import health_metrics

    monkeypatch.setattr(health_metrics.shutil, "disk_usage", lambda _path: _FakeUsage())

    resp = _make_client().get("/health")

    assert resp.status_code == 503
    assert resp.json()["status"] == "degraded"


def test_metrics_prometheus_format(tmp_path, monkeypatch):
    _point_paths_at_tmp(tmp_path, monkeypatch)
    init_db()
    inc_webhook_rejection("replay")

    resp = _make_client().get("/metrics")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    text = resp.text
    assert "pr_agent_workspaces_free_bytes" in text
    assert 'pr_agent_webhook_rejections_total{reason="replay"}' in text
