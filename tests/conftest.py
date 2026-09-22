"""pytest 夹具：确定性时钟、受控应用、TestClient 与日志输出。

关键测试需要"手动推进时钟"，因此不使用 fastapi TestClient 的线程隔离，
直接调用 ASGITransport + httpx 同步 client，并在同一线程操作 ctx.clock。
"""
from __future__ import annotations

import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.api import create_app  # noqa: E402
from app.auth_service import AuthConfig  # noqa: E402
from app.bootstrap import build_context  # noqa: E402
from app.clock import Clock  # noqa: E402

FIXED_NOW = 1_000_000.0


@pytest.fixture
def ctx_factory():
    def _make(ttl_access: int = 900, ttl_refresh: int = 86400, leeway: float = 0.0):
        clock = Clock(instant=FIXED_NOW)
        ctx = build_context(
            clock=clock,
            config=AuthConfig(
                access_ttl=ttl_access,
                refresh_ttl=ttl_refresh,
                leeway=leeway,
            ),
        )
        return ctx

    return _make


@pytest.fixture
def ctx(ctx_factory):
    return ctx_factory()


@pytest.fixture
def client(ctx):
    from fastapi.testclient import TestClient

    app = create_app(ctx.store, ctx.clock, ctx.auth, ctx.guard)
    return TestClient(app)


@pytest.fixture(autouse=True)
def _auth_logs(caplog):
    """让 auth/access/api 判定日志进入测试报告（-rA 或失败时可见）。"""
    caplog.set_level(logging.INFO, logger="auth")
    caplog.set_level(logging.INFO, logger="access")
    caplog.set_level(logging.WARNING, logger="api")
    yield


def login(client, username: str, password: str) -> dict:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def auth_header(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}
