"""访问控制：未认证 / 权限不足 / 资源不存在三类结论可区分；含 HTTP 入口验证。"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from auth.app import create_app
from auth.clock import OffsetClock
from auth.errors import AuthFailure, FailureCode
from auth.service import AuthService
from auth.tokens import TokenCodec


def test_missing_token(service):
    with pytest.raises(AuthFailure) as exc:
        service.access_resource("", "doc-1")
    assert exc.value.code in (FailureCode.MISSING_TOKEN, FailureCode.MALFORMED_TOKEN)


def test_forbidden_vs_not_found_are_distinguishable(service):
    bob = service.login("bob", "pw-bob")       # viewer: resource:read
    carol = service.login("carol", "pw-carol") # auditor: audit:read

    # bob 有权限的资源存在 => 允许
    assert service.access_resource(bob.access_token, "doc-1").allowed

    # 存在但权限不足 => FORBIDDEN（doc-2 需要 audit:read）
    with pytest.raises(AuthFailure) as exc:
        service.access_resource(bob.access_token, "doc-2")
    assert exc.value.code is FailureCode.FORBIDDEN
    assert "audit:read" in exc.value.reason

    # 不存在的资源 => NOT_FOUND（carol 能确认存在性；与 403 严格区分）
    with pytest.raises(AuthFailure) as exc2:
        service.access_resource(carol.access_token, "nope")
    assert exc2.value.code is FailureCode.NOT_FOUND

    # 反例对照：carol 访问存在但无权限的 doc-1 是 FORBIDDEN，而不是 NOT_FOUND
    with pytest.raises(AuthFailure) as exc3:
        service.access_resource(carol.access_token, "doc-1")
    assert exc3.value.code is FailureCode.FORBIDDEN


def test_http_status_mapping_and_error_bodies():
    clock = OffsetClock()
    svc = AuthService(__import__("auth.storage", fromlist=["Store"]).Store(),
                      TokenCodec(b"x"), clock)
    from auth.app import seed
    seed(svc._store)
    client = TestClient(create_app(service=svc))

    assert client.get("/resources/doc-1").status_code == 401  # 无令牌
    assert client.get("/resources/doc-1", headers={
        "Authorization": "Bearer garbage"}).status_code == 401  # 坏令牌

    login = client.post("/auth/login", json={"username": "bob", "password": "pw-bob"}).json()
    h = {"Authorization": f"Bearer {login['access_token']}"}
    r_ok = client.get("/resources/doc-1", headers=h)
    assert r_ok.status_code == 200 and r_ok.json()["decision"] == "allow"

    r_forbidden = client.get("/resources/doc-2", headers=h)
    assert r_forbidden.status_code == 403
    assert r_forbidden.json()["error"] == "permission_denied"

    r_missing = client.get("/resources/nope", headers=h)
    assert r_missing.status_code == 404
    assert r_missing.json()["error"] == "resource_not_found"


def test_http_concurrent_refresh_conflict_status():
    """HTTP 入口下并发刷新：一个 200，其余 409，错误码可区分。"""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    svc_store = __import__("auth.storage", fromlist=["Store"]).Store()
    from auth.app import seed
    seed(svc_store)
    svc = AuthService(svc_store, TokenCodec(b"x"), OffsetClock())
    client = TestClient(create_app(service=svc))
    pair = client.post("/auth/login", json={"username": "alice", "password": "pw-alice"}).json()

    n = 8
    barrier = threading.Barrier(n)
    def call(_):
        barrier.wait()
        return client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    with ThreadPoolExecutor(max_workers=n) as pool:
        statuses = sorted(r.status_code for r in pool.map(call, range(n)))
    assert statuses.count(200) == 1
    assert statuses.count(409) == n - 1
