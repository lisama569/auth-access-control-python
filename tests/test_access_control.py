"""访问控制：未认证/权限不足/资源不存在三类结论严格可区分；
按会话、主体、全局三种粒度吊销后，已签发令牌立即失效。
"""
from __future__ import annotations

import logging

from app.tokens import decode

from .conftest import auth_header, login

log = logging.getLogger("tests")


# ---------- 401 / 403 / 404 可区分 ----------

def test_anonymous_access_is_401_even_for_missing_resource(client):
    """未认证访问不存在资源 => 401，不得借 404 泄露资源存在性。"""
    resp_missing = client.get("/docs/no-such-doc")
    resp_existing = client.get("/docs/doc-1")
    assert resp_missing.status_code == 401
    assert resp_existing.status_code == 401
    assert resp_missing.json()["error"] == "unauthenticated"
    log.info("判定依据: 匿名访问无论资源是否存在均为 401 unauthenticated")


def test_viewer_can_read_but_cannot_write_403(client):
    data = login(client, "carol", "carol-pw")
    ok = client.get("/docs/doc-1", headers=auth_header(data))
    denied = client.put("/docs/doc-1", headers=auth_header(data))
    assert ok.status_code == 200
    assert denied.status_code == 403
    assert denied.json()["error"] == "forbidden"
    assert "doc:write" in denied.json()["reason"]
    log.info("判定依据: viewer 读放行/写拒绝 reason=%s", denied.json()["reason"])


def test_forbidden_does_not_mask_resource_existence(client):
    """关键语义：viewer 对不存在资源仍得 403 而非 404，
    保证"资源缺失"不会借越权响应被枚举。"""
    data = login(client, "carol", "carol-pw")
    existing = client.delete("/docs/doc-1", headers=auth_header(data))
    missing = client.delete("/docs/no-such-doc", headers=auth_header(data))
    assert existing.status_code == 403
    assert missing.status_code == 403
    log.info("判定依据: 权限不足时存在/不存在资源均为 403，无法区分")


def test_authorized_user_gets_404_for_missing_resource(client):
    """权限通过后资源缺失才暴露为 404。"""
    data = login(client, "alice", "alice-pw")
    resp = client.get("/docs/missing-doc", headers=auth_header(data))
    assert resp.status_code == 404
    assert resp.json()["error"] == "resource_not_found"
    log.info("判定依据: 已认证有权限 + 资源缺失 => 404 resource_not_found")


def test_existing_resource_accessible_to_authorized_role(client):
    data = login(client, "bob", "bob-pw")  # editor
    resp = client.get("/docs/doc-2", headers=auth_header(data))
    assert resp.status_code == 200
    assert resp.json()["id"] == "doc-2"


# ---------- 吊销 ----------

def _admin(client):
    return auth_header(login(client, "alice", "alice-pw"))


def test_session_revocation_blocks_both_access_and_refresh(client, ctx):
    victim = login(client, "bob", "bob-pw")
    sid = decode(victim["access_token"], ctx.auth.config.secret).sid
    rotated = client.post(
        "/auth/refresh", json={"refresh_token": victim["refresh_token"]}
    ).json()

    r = client.post(f"/admin/sessions/{sid}/revoke", headers=_admin(client))
    assert r.status_code == 200

    access = client.get("/docs/doc-1", headers=auth_header(rotated))
    refresh = client.post(
        "/auth/refresh", json={"refresh_token": rotated["refresh_token"]}
    )
    assert access.status_code == 401
    assert access.json()["error"] == "token_revoked"
    assert refresh.status_code == 401
    assert refresh.json()["error"] == "token_revoked"
    log.info("判定依据: 会话级吊销后，轮换后的新访问/刷新令牌同样失效")


def test_subject_revocation_blocks_existing_tokens_immediately(client, ctx):
    victim = login(client, "bob", "bob-pw")
    before = client.get("/docs/doc-1", headers=auth_header(victim))
    assert before.status_code == 200

    client.post("/admin/revoke/subject/bob", headers=_admin(client))

    after = client.get("/docs/doc-1", headers=auth_header(victim))
    assert after.status_code == 401
    assert after.json()["error"] == "token_revoked"
    log.info("判定依据: 主体吊销时间点之后，吊销前签发的令牌 => 401 token_revoked")


def test_tokens_issued_after_subject_revocation_are_valid(client, ctx):
    """吊销语义：iat > 吊销时间 的重新登录令牌不受影响。"""
    victim = login(client, "bob", "bob-pw")
    client.post("/admin/revoke/subject/bob", headers=_admin(client))
    assert client.get("/docs/doc-1", headers=auth_header(victim)).status_code == 401

    ctx.clock.advance(10)
    relogin = login(client, "bob", "bob-pw")
    resp = client.get("/docs/doc-1", headers=auth_header(relogin))
    assert resp.status_code == 200
    log.info("判定依据: 吊销后重新登录（iat>revoked_at）令牌有效")


def test_global_revocation_blocks_everyone_old_tokens(client, ctx):
    bob = login(client, "bob", "bob-pw")
    carol = login(client, "carol", "carol-pw")
    client.post("/admin/revoke/all", headers=_admin(client))

    for name, tokens in (("bob", bob), ("carol", carol)):
        resp = client.get("/docs/doc-1", headers=auth_header(tokens))
        assert resp.status_code == 401
        assert resp.json()["error"] == "token_revoked"
    log.info("判定依据: 全局吊销后，所有主体吊销点之前的令牌均被拒")


def test_non_admin_cannot_revoke(client):
    bob = login(client, "bob", "bob-pw")
    resp = client.post("/admin/revoke/all", headers=auth_header(bob))
    assert resp.status_code == 403
    assert resp.json()["error"] == "forbidden"
