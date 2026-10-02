"""刷新令牌泄露检测：整串作废的语义与可区分性。

核心语义：
- 窗口外重复使用旧刷新令牌 => 该次登录签发的整串令牌（访问+刷新）作废；
- 访问路径 => 401 token_family_revoked，刷新路径 => 401 refresh_reuse_detected，
  与普通注销（token_revoked）、过期（token_expired）、篡改（token_tampered）区分；
- 只作废"那一串"：同一用户的其他会话、其他用户的会话不受影响；
- 整串作废不阻止重新登录，新会话是全新的一串。
"""
from __future__ import annotations

import logging

from app.tokens import decode

from .conftest import auth_header, login

log = logging.getLogger("tests")


def _refresh(client, token: str):
    return client.post("/auth/refresh", json={"refresh_token": token})


def _trigger_reuse_detection(client, ctx, refresh_token: str) -> None:
    """先正常轮换，再超出窗口重用旧令牌，触发整串作废。"""
    assert _refresh(client, refresh_token).status_code == 200
    ctx.clock.advance(ctx.auth.config.refresh_retry_window + 0.1)
    resp = _refresh(client, refresh_token)
    assert resp.status_code == 401
    assert resp.json()["error"] == "refresh_reuse_detected"


def test_family_revoked_distinct_from_normal_logout(client, ctx):
    """同一主体两个会话：一个泄露整串作废、一个常规注销，结论必须可区分。"""
    victim = login(client, "bob", "bob-pw")
    logout = login(client, "bob", "bob-pw")
    sid_logout = decode(logout["access_token"], ctx.auth.config.secret).sid

    _trigger_reuse_detection(client, ctx, victim["refresh_token"])

    admin = login(client, "alice", "alice-pw")
    r = client.post(f"/admin/sessions/{sid_logout}/revoke", headers=auth_header(admin))
    assert r.status_code == 200 and r.json()["status"] == "revoked"

    leaked = client.get("/docs/doc-1", headers=auth_header(victim))
    logged_out = client.get("/docs/doc-1", headers=auth_header(logout))
    assert leaked.status_code == 401
    assert leaked.json()["error"] == "token_family_revoked"
    assert logged_out.status_code == 401
    assert logged_out.json()["error"] == "token_revoked"
    log.info("判定依据: 泄露=>%s 常规注销=>%s，排查时可直接区分",
             leaked.json()["error"], logged_out.json()["error"])


def test_reuse_detection_only_kills_that_family(client, ctx):
    """整串作废只针对出事的那次登录：同用户其他会话、其他用户会话不受影响。"""
    victim = login(client, "bob", "bob-pw")
    other_session = login(client, "bob", "bob-pw")   # 同用户另一串
    other_user = login(client, "carol", "carol-pw")  # 另一用户

    _trigger_reuse_detection(client, ctx, victim["refresh_token"])

    assert client.get("/docs/doc-1", headers=auth_header(victim)).status_code == 401
    ok1 = client.get("/docs/doc-1", headers=auth_header(other_session))
    ok2 = client.get("/docs/doc-1", headers=auth_header(other_user))
    assert ok1.status_code == 200
    assert ok2.status_code == 200
    log.info("判定依据: 仅出事的一串作废，同用户另一会话与另一用户均正常")


def test_relogin_after_family_revocation_works(client, ctx):
    """整串作废后重新登录：签发全新一串，正常使用。"""
    victim = login(client, "bob", "bob-pw")
    old_sid = decode(victim["access_token"], ctx.auth.config.secret).sid
    _trigger_reuse_detection(client, ctx, victim["refresh_token"])

    ctx.clock.advance(1)
    fresh = login(client, "bob", "bob-pw")
    new_sid = decode(fresh["access_token"], ctx.auth.config.secret).sid
    assert new_sid != old_sid

    resp = client.get("/docs/doc-1", headers=auth_header(fresh))
    assert resp.status_code == 200
    rotated = _refresh(client, fresh["refresh_token"])
    assert rotated.status_code == 200
    log.info("判定依据: 重新登录签发新串 sid=%s，访问与轮换均正常", new_sid)


def test_family_revocation_is_terminal_and_stable(client, ctx):
    """整串作废是终态：重复判定结论一致，且不会被后续操作复活。"""
    victim = login(client, "bob", "bob-pw")
    r0 = victim["refresh_token"]
    p1 = _refresh(client, r0).json()
    ctx.clock.advance(ctx.auth.config.refresh_retry_window + 0.1)
    assert _refresh(client, r0).json()["error"] == "refresh_reuse_detected"

    conclusions = set()
    for _ in range(3):
        a = client.get("/docs/doc-1", headers=auth_header(p1))
        r = _refresh(client, p1["refresh_token"])
        conclusions.add((a.status_code, a.json()["error"]))
        conclusions.add((r.status_code, r.json()["error"]))
    assert conclusions == {
        (401, "token_family_revoked"),
        (401, "refresh_reuse_detected"),
    }
    log.info("判定依据: 3 次重复判定结论集合=%s，终态稳定", sorted(conclusions))


def test_reuse_detection_distinct_from_expired_and_tampered(client, ctx):
    """泄露结论与过期、篡改可区分（同一响应表内不同 error 码）。"""
    victim = login(client, "bob", "bob-pw")
    _trigger_reuse_detection(client, ctx, victim["refresh_token"])
    leaked = client.get("/docs/doc-1", headers=auth_header(victim))

    expired = login(client, "carol", "carol-pw")
    ctx.clock.advance(ctx.auth.config.access_ttl + 1)
    expired_resp = client.get("/docs/doc-1", headers=auth_header(expired))

    tampered_resp = client.get(
        "/docs/doc-1", headers={"Authorization": "Bearer a.b.c"}
    )

    errors = {
        leaked.json()["error"],
        expired_resp.json()["error"],
        tampered_resp.json()["error"],
    }
    assert errors == {"token_family_revoked", "token_expired", "token_tampered"}
    log.info("判定依据: 泄露/过期/篡改三类结论两两可区分 => %s", sorted(errors))
