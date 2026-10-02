"""会话治理：按主体列出会话、批量注销、单会话注销结论可区分。

判定顺序与资源接口一致：认证(401) -> 权限(403) -> 目标存在性(404)，
无权主体看不到任何会话信息；列表不暴露令牌内容。
"""
from __future__ import annotations

import logging

from app.tokens import decode

from .conftest import auth_header, login

log = logging.getLogger("tests")


def _admin(client):
    return auth_header(login(client, "alice", "alice-pw"))


def _list(client, username: str, headers):
    return client.get(f"/admin/subjects/{username}/sessions", headers=headers)


def _revoke_all(client, username: str, headers):
    return client.post(f"/admin/subjects/{username}/sessions/revoke", headers=headers)


# ---------- 判定顺序：401 -> 403 -> 404 ----------

def test_list_sessions_requires_authentication(client):
    resp = _list(client, "bob", {})
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthenticated"


def test_list_sessions_forbidden_without_permission(client):
    bob = login(client, "bob", "bob-pw")  # editor：无 admin:sessions
    resp = _list(client, "bob", auth_header(bob))
    assert resp.status_code == 403
    assert resp.json()["error"] == "forbidden"
    assert "admin:sessions" in resp.json()["reason"]


def test_forbidden_masks_subject_existence(client):
    """无权主体查询不存在的主体 => 403 而非 404，不泄露主体是否存在。"""
    bob = login(client, "bob", "bob-pw")
    resp = _list(client, "ghost", auth_header(bob))
    assert resp.status_code == 403
    resp2 = _revoke_all(client, "ghost", auth_header(bob))
    assert resp2.status_code == 403
    log.info("判定依据: 无权查询任意主体均为 403，存在性不外泄")


def test_unknown_subject_is_404_after_permission(client):
    resp = _list(client, "ghost", _admin(client))
    assert resp.status_code == 404
    assert resp.json()["error"] == "resource_not_found"
    resp2 = _revoke_all(client, "ghost", _admin(client))
    assert resp2.status_code == 404
    log.info("判定依据: 权限通过后主体不存在 => 404 resource_not_found")


# ---------- 列出会话 ----------

def test_list_sessions_shows_status_without_token_material(client, ctx):
    bob1 = login(client, "bob", "bob-pw")
    bob2 = login(client, "bob", "bob-pw")
    login(client, "carol", "carol-pw")  # 其他主体不应混入

    resp = _list(client, "bob", _admin(client))
    assert resp.status_code == 200
    body = resp.json()
    assert body["subject"] == "bob"
    assert body["count"] == 2
    sessions = body["sessions"]
    assert {s["status"] for s in sessions} == {"active"}
    for s in sessions:
        assert set(s) == {
            "sid", "subject", "created_at", "status", "revoked_reason", "rotations"
        }
        assert s["subject"] == "bob"
        assert s["revoked_reason"] is None
    # 不暴露任何令牌内容
    for tokens in (bob1, bob2):
        assert tokens["access_token"] not in resp.text
        assert tokens["refresh_token"] not in resp.text
    log.info("判定依据: 列表含 sid/created_at/status，令牌内容不出现在响应中")


def test_list_sessions_reflects_reuse_detected_reason(client, ctx):
    victim = login(client, "bob", "bob-pw")
    r0 = victim["refresh_token"]
    client.post("/auth/refresh", json={"refresh_token": r0})
    ctx.clock.advance(ctx.auth.config.refresh_retry_window + 0.1)
    client.post("/auth/refresh", json={"refresh_token": r0})  # 触发整串作废

    sessions = _list(client, "bob", _admin(client)).json()["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["status"] == "revoked"
    assert sessions[0]["revoked_reason"] == "reuse_detected"
    log.info("判定依据: 泄露作废的会话在列表中标记 revoked/reuse_detected")


# ---------- 批量注销 ----------

def test_batch_revoke_then_relogin_appears_in_list(client, ctx):
    bob1 = login(client, "bob", "bob-pw")
    bob2 = login(client, "bob", "bob-pw")

    resp = _revoke_all(client, "bob", _admin(client))
    assert resp.status_code == 200
    body = resp.json()
    assert body["revoked_count"] == 2
    assert len(body["revoked_sids"]) == 2

    # 列表中两个会话均为 revoked/admin
    sessions = _list(client, "bob", _admin(client)).json()["sessions"]
    assert all(s["status"] == "revoked" for s in sessions)
    assert all(s["revoked_reason"] == "admin" for s in sessions)

    # 旧令牌全部失效（常规注销语义）
    for tokens in (bob1, bob2):
        r = client.get("/docs/doc-1", headers=auth_header(tokens))
        assert r.status_code == 401
        assert r.json()["error"] == "token_revoked"

    # 再次批量注销：没有活着的会话 => 0，且与"刚注销 2 个"可区分
    again = _revoke_all(client, "bob", _admin(client)).json()
    assert again["revoked_count"] == 0
    assert again["revoked_sids"] == []

    # 重新登录成功，新会话出现在列表中且为 active
    ctx.clock.advance(1)
    fresh = login(client, "bob", "bob-pw")
    assert client.get("/docs/doc-1", headers=auth_header(fresh)).status_code == 200
    sessions = _list(client, "bob", _admin(client)).json()["sessions"]
    active = [s for s in sessions if s["status"] == "active"]
    assert len(active) == 1
    assert active[0]["sid"] == decode(
        fresh["access_token"], ctx.auth.config.secret
    ).sid
    log.info("判定依据: 批量注销->旧令牌失效->重新登录->新会话出现在列表")


def test_batch_revoke_does_not_touch_other_subjects(client, ctx):
    bob = login(client, "bob", "bob-pw")
    carol = login(client, "carol", "carol-pw")

    _revoke_all(client, "bob", _admin(client))
    assert client.get("/docs/doc-1", headers=auth_header(bob)).status_code == 401
    assert client.get("/docs/doc-1", headers=auth_header(carol)).status_code == 200
    log.info("判定依据: 批量注销只影响目标主体")


# ---------- 单会话注销结论可区分 ----------

def test_single_session_revoke_statuses_are_distinguishable(client, ctx):
    victim = login(client, "bob", "bob-pw")
    sid = decode(victim["access_token"], ctx.auth.config.secret).sid
    admin = _admin(client)

    first = client.post(f"/admin/sessions/{sid}/revoke", headers=admin)
    assert first.status_code == 200
    assert first.json()["status"] == "revoked"

    second = client.post(f"/admin/sessions/{sid}/revoke", headers=admin)
    assert second.status_code == 200
    assert second.json()["status"] == "already_revoked"
    assert second.json()["revoked_reason"] == "admin"

    missing = client.post("/admin/sessions/sess-nope/revoke", headers=admin)
    assert missing.status_code == 404
    assert missing.json()["error"] == "resource_not_found"
    log.info("判定依据: revoked / already_revoked / not_found(404) 三者可区分")
