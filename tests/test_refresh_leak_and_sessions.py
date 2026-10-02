"""刷新令牌泄露整串作废 + 按主体会话治理。

覆盖：
- 整串作废后，该串历史访问令牌访问资源被拒，结论与普通注销可区分；
- 整串作废与普通会话注销、过期、篡改各自独立；
- 容忍窗口内重试回放（在 test_refresh_rotation 中已覆盖，此处补泄露后
  再登录的新会话不受牵连）；
- 按主体列会话 / 批量注销 / 注销后重新登录再入列 / 单会话注销三态；
- 治理入口沿用"认证 -> 权限 -> 目标存在性"的判定顺序。
"""
from __future__ import annotations

import logging

from app.tokens import decode

from .conftest import auth_header, login

log = logging.getLogger("tests")


def _refresh(client, token: str):
    return client.post("/auth/refresh", json={"refresh_token": token})


def _admin(client):
    return auth_header(login(client, "alice", "alice-pw"))


# ---------- 整串作废的访问拒绝与结论区分 ----------

def test_compromised_chain_access_denied_distinct_from_revocation(client, ctx):
    victim = login(client, "bob", "bob-pw")
    rotated = _refresh(client, victim["refresh_token"]).json()
    ctx.clock.advance(ctx.auth.config.retry_window + 1)
    leak = _refresh(client, victim["refresh_token"])
    assert leak.status_code == 401
    assert leak.json()["error"] == "refresh_chain_revoked"

    # 整串里登录时与轮换出的访问令牌都被拒，且原因不是普通 token_revoked
    for tokens, label in ((victim, "登录访问令牌"), (rotated, "轮换访问令牌")):
        resp = client.get("/docs/doc-1", headers=auth_header(tokens))
        assert resp.status_code == 401, label
        assert resp.json()["error"] == "refresh_chain_revoked", (label, resp.json())
    log.info("判定依据: 整串作废后访问资源 => refresh_chain_revoked（非 token_revoked）")


def test_normal_logout_reports_token_revoked_not_chain_revoked(client, ctx):
    """对照组：普通会话注销的结论仍是 token_revoked，两类失效明确分开。"""
    victim = login(client, "bob", "bob-pw")
    sid = decode(victim["access_token"], ctx.auth.config.secret).sid
    client.post(f"/admin/sessions/{sid}/revoke", headers=_admin(client))

    resp = client.get("/docs/doc-1", headers=auth_header(victim))
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_revoked"

    refresh_resp = _refresh(client, victim["refresh_token"])
    assert refresh_resp.status_code == 401
    assert refresh_resp.json()["error"] == "token_revoked"
    log.info("判定依据: 普通注销 => token_revoked，与泄露整串作废结论可区分")


def test_compromised_chain_does_not_affect_new_login(client, ctx):
    """整串作废只波及该会话本身：重新登录的新会话不受牵连且可正常使用。"""
    victim = login(client, "bob", "bob-pw")
    _refresh(client, victim["refresh_token"])
    ctx.clock.advance(ctx.auth.config.retry_window + 1)
    assert _refresh(client, victim["refresh_token"]).status_code == 401

    fresh = login(client, "bob", "bob-pw")
    resp = client.get("/docs/doc-1", headers=auth_header(fresh))
    assert resp.status_code == 200
    assert _refresh(client, fresh["refresh_token"]).status_code == 200

    # 旧会话仍处于作废态，新会话 active，二者同属一个主体、互不牵连
    sid_old = decode(victim["access_token"], ctx.auth.config.secret).sid
    sid_new = decode(fresh["access_token"], ctx.auth.config.secret).sid
    assert sid_old != sid_new
    assert ctx.store.get_session(sid_old).compromised
    assert not ctx.store.get_session(sid_new).compromised
    log.info("判定依据: 整串作废不阻止重新登录，新会话 active")


def test_expired_still_classified_as_expired_even_if_chain_revoked(client, ctx):
    """判定顺序：过期优先于泄露作废（令牌本身先站得住，才讨论串状态）。"""
    victim = login(client, "bob", "bob-pw")
    _refresh(client, victim["refresh_token"])
    ctx.clock.advance(ctx.auth.config.retry_window + 1)
    _refresh(client, victim["refresh_token"])  # 整串已作废
    # 再把时间推进到访问令牌也过期之后
    ctx.clock.advance(ctx.auth.config.access_ttl + 1)
    resp = client.get("/docs/doc-1", headers=auth_header(victim))
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_expired"
    log.info("判定依据: 又过期又作废 => 固定顺序归类 token_expired")


# ---------- 按主体会话治理 ----------

def test_list_sessions_by_subject_hides_tokens_and_shows_status(client):
    _admin(client)
    login(client, "bob", "bob-pw")
    login(client, "bob", "bob-pw")  # 第二个会话

    resp = client.get("/admin/subjects/bob/sessions", headers=_admin(client))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 2
    assert [s["status"] for s in body["sessions"]] == ["active", "active"]
    for s in body["sessions"]:
        assert "token" not in s and "jti" not in s
        assert s["created_at"] > 0
    log.info("判定依据: 列表只暴露 sid/时间/状态，不暴露令牌内容: %s",
             [(s["sid"], s["status"]) for s in body["sessions"]])


def test_list_sessions_shows_revoked_and_compromised(client, ctx):
    admin = _admin(client)
    bob_a = login(client, "bob", "bob-pw")
    bob_b = login(client, "bob", "bob-pw")
    sid_a = decode(bob_a["access_token"], ctx.auth.config.secret).sid
    sid_b = decode(bob_b["access_token"], ctx.auth.config.secret).sid

    # A 普通注销；B 因旧刷新泄露整串作废
    client.post(f"/admin/sessions/{sid_a}/revoke", headers=admin)
    _refresh(client, bob_b["refresh_token"])
    ctx.clock.advance(ctx.auth.config.retry_window + 1)
    _refresh(client, bob_b["refresh_token"])

    body = client.get("/admin/subjects/bob/sessions", headers=admin).json()
    statuses = {s["sid"]: s["status"] for s in body["sessions"]}
    assert statuses[sid_a] == "revoked"
    assert statuses[sid_b] == "compromised"
    log.info("判定依据: 同主体列表区分 revoked / compromised: %s", statuses)


def test_bulk_revoke_logs_out_all_live_sessions_then_relogin_listed(client, ctx):
    admin = _admin(client)
    bob1 = login(client, "bob", "bob-pw")
    bob2 = login(client, "bob", "bob-pw")

    r = client.post("/admin/subjects/bob/sessions/revoke", headers=admin)
    assert r.status_code == 200
    assert r.json()["revoked_count"] == 2

    # 两个会话的令牌立即失效
    for tokens in (bob1, bob2):
        assert client.get("/docs/doc-1", headers=auth_header(tokens)).status_code == 401

    # 再批量注销一次：没有活会话，数量为 0（幂等）
    r = client.post("/admin/subjects/bob/sessions/revoke", headers=admin)
    assert r.json()["revoked_count"] == 0

    # 注销后重新登录成功，且新会话出现在列表里、状态 active
    bob3 = login(client, "bob", "bob-pw")
    assert client.get("/docs/doc-1", headers=auth_header(bob3)).status_code == 200
    body = client.get("/admin/subjects/bob/sessions", headers=admin).json()
    assert len(body["sessions"]) == 3
    assert body["sessions"][-1]["status"] == "active"
    log.info("判定依据: 批量注销→重新登录，新会话入列且 active；旧会话保留为 revoked")


def test_single_session_revoke_three_way_distinction(client, ctx):
    admin = _admin(client)
    bob = login(client, "bob", "bob-pw")
    sid = decode(bob["access_token"], ctx.auth.config.secret).sid

    # 从不存在的会话
    missing = client.post("/admin/sessions/no-such-sid/revoke", headers=admin)
    assert missing.status_code == 404
    assert missing.json()["error"] == "session_not_found"

    # 存在且存活 -> 本次刚刚注销
    first = client.post(f"/admin/sessions/{sid}/revoke", headers=admin)
    assert first.status_code == 200
    assert first.json()["result"] == "revoked"

    # 已被清掉 -> 明确是 already_revoked，不与首次混淆
    second = client.post(f"/admin/sessions/{sid}/revoke", headers=admin)
    assert second.status_code == 200
    assert second.json()["result"] == "already_revoked"
    log.info("判定依据: not_found / revoked / already_revoked 三态明确可区分")


def test_compromised_session_revoke_reports_already_revoked(client, ctx):
    admin = _admin(client)
    bob = login(client, "bob", "bob-pw")
    sid = decode(bob["access_token"], ctx.auth.config.secret).sid
    _refresh(client, bob["refresh_token"])
    ctx.clock.advance(ctx.auth.config.retry_window + 1)
    _refresh(client, bob["refresh_token"])  # 整串作废

    r = client.post(f"/admin/sessions/{sid}/revoke", headers=admin)
    assert r.status_code == 200
    assert r.json()["result"] == "already_revoked"
    log.info("判定依据: 对已泄露终态会话注销 => already_revoked，不重复计数")


def test_governance_requires_authn_then_authz_before_existence(client):
    bob = login(client, "bob", "bob-pw")
    # 未认证：无论目标会话是否存在都 401，不泄露存在性
    assert client.get("/admin/subjects/bob/sessions").status_code == 401
    assert client.post("/admin/subjects/bob/sessions/revoke").status_code == 401
    assert client.post("/admin/sessions/whatever/revoke").status_code == 401
    # 已认证但无权限：403，目标存在与否都不暴露
    hdr = auth_header(bob)
    assert client.get("/admin/subjects/bob/sessions", headers=hdr).status_code == 403
    assert client.post("/admin/subjects/bob/sessions/revoke", headers=hdr).status_code == 403
    assert client.post("/admin/sessions/whatever/revoke", headers=hdr).status_code == 403
    log.info("判定依据: 治理入口顺序固定 认证(401)->权限(403)->目标(404/200)")
