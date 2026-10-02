"""重复提交容忍窗口：窗口内幂等重试、边界确定性、窗口外泄露判定。

窗口规则（确定性，与过期判定同风格）：
    now - rotated_at <  window  => 幂等重试，返回首次轮换签发的那对令牌
    now - rotated_at >= window  => 等号即超出窗口，按泄露处理（整串作废）
窗口只锚定首次轮换时刻 rotated_at，不因重试而顺延。
"""
from __future__ import annotations

import logging

from app.tokens import decode

from .conftest import FIXED_NOW, login

log = logging.getLogger("tests")


def _refresh(client, token: str):
    return client.post("/auth/refresh", json={"refresh_token": token})


def _session(ctx):
    assert len(ctx.store.sessions) == 1
    return next(iter(ctx.store.sessions.values()))


def test_retry_within_window_returns_identical_pair(client, ctx):
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    first = _refresh(client, r0).json()

    ctx.clock.advance(ctx.auth.config.refresh_retry_window - 0.5)  # 窗口内
    retry = _refresh(client, r0)
    assert retry.status_code == 200
    body = retry.json()
    assert body["access_token"] == first["access_token"]
    assert body["refresh_token"] == first["refresh_token"]
    log.info("判定依据: 窗口内重试返回与首次完全相同的令牌对")


def test_retry_does_not_advance_session(client, ctx):
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    _refresh(client, r0)

    session = _session(ctx)
    chain_before = list(session.refresh_chain)
    current_before = session.current_refresh_jti
    used_before = dict(ctx.store.used_refresh_jti)

    for _ in range(3):  # 窗口内反复重试
        resp = _refresh(client, r0)
        assert resp.status_code == 200

    assert session.refresh_chain == chain_before       # 链未推进
    assert session.current_refresh_jti == current_before
    assert ctx.store.used_refresh_jti == used_before   # 已使用表未增长
    assert not session.revoked
    log.info("判定依据: 3 次窗口内重试，链长=%d 不变，会话未推进", len(chain_before))


def test_window_boundary_is_deterministic_equality_exceeded(client, ctx):
    """now - rotated_at == window 的临界瞬间确定地按泄露处理。"""
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    first = _refresh(client, r0).json()

    window = ctx.auth.config.refresh_retry_window
    # 窗口内侧 0.001 秒：仍是重试
    ctx.clock.instant = FIXED_NOW + window - 0.001
    inside = _refresh(client, r0)
    assert inside.status_code == 200
    assert inside.json()["refresh_token"] == first["refresh_token"]

    # 恰好等于窗口边界：确定地判泄露（等号即超出）
    ctx.clock.instant = FIXED_NOW + window
    at_boundary = _refresh(client, r0)
    assert at_boundary.status_code == 401
    assert at_boundary.json()["error"] == "refresh_reuse_detected"

    # 边界外侧：结论一致（此时整串已作废，稳定返回同一错误码）
    ctx.clock.instant = FIXED_NOW + window + 0.001
    beyond = _refresh(client, r0)
    assert beyond.status_code == 401
    assert beyond.json()["error"] == "refresh_reuse_detected"
    log.info("判定依据: window=%.3f 内侧重试/等号及外侧泄露，临界确定", window)


def test_window_anchored_to_first_rotation_not_extended_by_retry(client, ctx):
    """重试不顺延窗口：锚点始终是首次轮换时刻。"""
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    _refresh(client, r0)  # rotated_at = FIXED_NOW
    window = ctx.auth.config.refresh_retry_window

    ctx.clock.instant = FIXED_NOW + window - 0.5  # 窗口内重试一次
    assert _refresh(client, r0).status_code == 200

    # 若窗口被顺延，此处仍在窗口内；锚定语义下已超出 => 泄露
    ctx.clock.instant = FIXED_NOW + window + 0.5
    resp = _refresh(client, r0)
    assert resp.status_code == 401
    assert resp.json()["error"] == "refresh_reuse_detected"
    log.info("判定依据: 重试不顺延窗口，锚定首次轮换时刻")


def test_older_token_within_window_is_reuse_not_retry(client, ctx):
    """窗口只覆盖"上一次刚被换掉的"那一任；更早的旧令牌立即判泄露。"""
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    p1 = _refresh(client, r0).json()
    assert _refresh(client, p1["refresh_token"]).status_code == 200  # r1 -> r2

    # 此刻仍在 r1 的窗口内，但 r0 是"更早之前"的旧令牌 => 泄露
    resp = _refresh(client, r0)
    assert resp.status_code == 401
    assert resp.json()["error"] == "refresh_reuse_detected"
    session = _session(ctx)
    assert session.revoked and session.revoked_reason == "reuse_detected"
    log.info("判定依据: 更早旧令牌不受窗口保护，立即整串作废")


def test_zero_window_disables_retry(client, ctx_factory):
    """窗口配置为 0：任何重试都立即按泄露处理（兼容旧的严格语义）。"""
    ctx = ctx_factory()
    ctx.auth.config.refresh_retry_window = 0.0
    from fastapi.testclient import TestClient

    from app.api import create_app
    client = TestClient(create_app(ctx.store, ctx.clock, ctx.auth, ctx.guard))

    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    assert _refresh(client, r0).status_code == 200
    resp = _refresh(client, r0)  # 同一时刻重试，窗口为 0 => 泄露
    assert resp.status_code == 401
    assert resp.json()["error"] == "refresh_reuse_detected"
    log.info("判定依据: window=0 时同一时刻重试也判泄露")


def test_retried_pair_is_usable_for_next_rotation(client, ctx):
    """重试拿回的那对令牌就是真实的新令牌：可继续推进轮换链。"""
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    first = _refresh(client, r0).json()
    retry = _refresh(client, r0).json()  # 窗口内重试，拿回同一对

    nxt = _refresh(client, retry["refresh_token"])
    assert nxt.status_code == 200
    assert nxt.json()["refresh_token"] != first["refresh_token"]
    session = _session(ctx)
    assert len(session.refresh_chain) == 3  # 初始 + 首次轮换 + 本次推进
    log.info("判定依据: 重试令牌对可正常推进下一次轮换，链长=3")


def test_retry_response_carries_valid_access_token(client, ctx):
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    _refresh(client, r0)
    retry = _refresh(client, r0).json()

    claims = decode(retry["access_token"], ctx.auth.config.secret)
    assert claims.sub == "alice"
    resp = client.get("/docs/doc-1", headers={
        "Authorization": f"Bearer {retry['access_token']}"
    })
    assert resp.status_code == 200
    log.info("判定依据: 重试返回的访问令牌可正常访问资源 sid=%s", claims.sid)
