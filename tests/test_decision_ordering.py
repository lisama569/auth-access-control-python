"""失败归类的优先级（保证结论可解释、无自相矛盾）：

访问/刷新统一的判定顺序：
  1. 结构与签名（token_tampered）
  2. 令牌类型（token_tampered）
  3. 过期（token_expired）
  4. 会话存在 / 会话吊销（token_revoked）
  5. 主体/全局吊销（token_revoked）
  6. 刷新重放（refresh_replayed）/ 并发冲突（refresh_conflict，仅刷新）
即"令牌本身先站得住，才讨论它是否被吊销或重放"。
"""
from __future__ import annotations

import logging

from app.tokens import decode

from .conftest import auth_header, login

log = logging.getLogger("tests")


def test_expired_and_session_revoked_reports_expired_first(client, ctx):
    tokens = login(client, "bob", "bob-pw")
    sid = decode(tokens["access_token"], ctx.auth.config.secret).sid
    client.post(f"/admin/sessions/{sid}/revoke", headers=auth_header(
        login(client, "alice", "alice-pw")))
    ctx.clock.advance(1000)  # 同时也已过期

    resp = client.get("/docs/doc-1", headers=auth_header(tokens))
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_expired"
    log.info("判定依据: 同时过期+吊销时按固定顺序归类为 token_expired")


def test_tampered_token_never_evaluated_against_revocation(client, ctx):
    tokens = login(client, "bob", "bob-pw")
    client.post("/admin/revoke/subject/bob", headers=auth_header(
        login(client, "alice", "alice-pw")))
    head, payload, _sig = tokens["access_token"].split(".")
    bogus = f"{head}.{payload}.{'B' * len(_sig)}"

    resp = client.get("/docs/doc-1", headers={"Authorization": f"Bearer {bogus}"})
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_tampered"
    log.info("判定依据: 签名非法优先于吊销判定 => token_tampered")


def test_replay_of_revoked_session_reports_revoked(client, ctx):
    tokens = login(client, "bob", "bob-pw")
    sid = decode(tokens["refresh_token"], ctx.auth.config.secret).sid
    # 先成功轮换一次，使旧刷新令牌成为"已使用"
    client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    # 再吊销会话
    client.post(f"/admin/sessions/{sid}/revoke", headers=auth_header(
        login(client, "alice", "alice-pw")))

    resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_revoked"
    log.info("判定依据: 已重放令牌所属会话被吊销，优先归类 token_revoked")


def test_refresh_expired_boundary_deterministic(client, ctx):
    """刷新令牌在 exp 临界瞬间的判定确定性（与访问令牌同一规则）。"""
    tokens = login(client, "bob", "bob-pw")
    exp = decode(tokens["refresh_token"], ctx.auth.config.secret).exp

    ctx.clock.instant = exp - 0.001
    fresh = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert fresh.status_code == 200

    # 重新登录拿一对新令牌推进到恰好 exp
    again = login(client, "bob", "bob-pw")
    exp2 = decode(again["refresh_token"], ctx.auth.config.secret).exp
    ctx.clock.instant = exp2
    resp = client.post("/auth/refresh", json={"refresh_token": again["refresh_token"]})
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_expired"
    log.info("判定依据: now==exp 刷新令牌确定判过期（等号即过期）")
