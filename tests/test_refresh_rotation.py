"""刷新轮换：重试窗口幂等、窗口外泄露判定、并发刷新只推进一次。

状态机（每个会话只认一个当前刷新 jti，CAS 原子切换）：
- 窗口内再用"上一次刚被换掉的"旧令牌 => 200，原样返回首次签发的令牌对
- 超出窗口或更早的旧令牌 => 401 refresh_reuse_detected，整串令牌作废
- 与轮换并发、读到"未使用"快照后 CAS 失败 => 409 refresh_conflict
三种结论可区分，且任何情况下会话状态只前进、不回滚、不推进两次。
"""
from __future__ import annotations

import logging
import threading

from .conftest import auth_header, login

log = logging.getLogger("tests")


def _refresh(client, token: str):
    return client.post("/auth/refresh", json={"refresh_token": token})


def test_refresh_rotates_both_tokens(client, ctx):
    data = login(client, "alice", "alice-pw")
    sid_before = __import__("app.tokens", fromlist=["decode"]).decode(
        data["access_token"], ctx.auth.config.secret
    ).sid

    resp = _refresh(client, data["refresh_token"])
    assert resp.status_code == 200, resp.text
    new = resp.json()
    assert new["refresh_token"] != data["refresh_token"]
    assert new["access_token"] != data["access_token"]
    assert new["sid"] == sid_before
    log.info("判定依据: 轮换成功 sid=%s（新令牌对，同会话）", sid_before)

    # 旧访问令牌在新刷新发生后仍然有效（访问令牌独立过期/吊销）
    resp = client.get("/docs/doc-1", headers=auth_header(data))
    assert resp.status_code == 200


def test_reuse_of_rotated_refresh_beyond_window_kills_family(client, ctx):
    """超出容忍窗口再用旧刷新令牌 => refresh_reuse_detected，且结论稳定。"""
    data = login(client, "alice", "alice-pw")
    old_refresh = data["refresh_token"]
    assert _refresh(client, old_refresh).status_code == 200

    ctx.clock.advance(ctx.auth.config.refresh_retry_window + 0.1)
    resp = _refresh(client, old_refresh)
    body = resp.json()
    assert resp.status_code == 401
    assert body["error"] == "refresh_reuse_detected"

    # 整串作废是终态：再次使用同串任何令牌，结论一致
    current = _refresh(client, old_refresh)
    assert current.status_code == 401
    assert current.json()["error"] == "refresh_reuse_detected"
    log.info("判定依据: 窗口外旧刷新重用 reason=%s，整串作废且结论稳定", body["reason"])


def test_whole_family_unusable_after_reuse_detection(client, ctx):
    """泄露判定后：这一串里所有刷新/访问令牌都不可用，且与常规注销可区分。"""
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    p1 = _refresh(client, r0).json()
    p2 = _refresh(client, p1["refresh_token"]).json()

    ctx.clock.advance(ctx.auth.config.refresh_retry_window + 0.1)
    assert _refresh(client, r0).status_code == 401  # 触发整串作废

    # 这一串里后来签发的刷新令牌同样被拒，且错误码是泄露语义
    for tok in (p1["refresh_token"], p2["refresh_token"]):
        resp = _refresh(client, tok)
        assert resp.status_code == 401
        assert resp.json()["error"] == "refresh_reuse_detected"

    # 这一串的访问令牌也被拒，且与普通注销（token_revoked）可区分
    for tokens in (data, p1, p2):
        resp = client.get("/docs/doc-1", headers=auth_header(tokens))
        assert resp.status_code == 401
        assert resp.json()["error"] == "token_family_revoked"
    log.info("判定依据: 整串作废后访问=>token_family_revoked 刷新=>refresh_reuse_detected")


def test_concurrent_refresh_rotates_exactly_once(client, ctx):
    """N 个线程同时用同一个刷新令牌：会话只推进一次。

    成功响应可能不止一个（窗口内重试），但所有 200 必须返回
    完全相同的一对令牌；失败者只能是并发冲突 refresh_conflict。
    """
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]

    barrier = threading.Barrier(8)
    results: list[tuple[int, str, str]] = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        resp = _refresh(client, r0)
        body = resp.json()
        with lock:
            results.append(
                (resp.status_code, body.get("error", "ok"), body.get("refresh_token", ""))
            )

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[0] == 200]
    failures = [r for r in results if r[0] != 200]
    assert len(successes) >= 1, results
    # 所有成功响应必须是同一对令牌（重试不推进会话）
    assert len({r[2] for r in successes}) == 1, results
    assert all(code == 409 and err == "refresh_conflict" for code, err, _ in failures)
    log.info(
        "判定依据: 8 并发刷新 => 成功 %d（同一对令牌），冲突 %d",
        len(successes), len(failures),
    )

    # 存储层验证状态一致性：每个会话只有一个 current jti，链长度恰好为 2
    sessions = list(ctx.store.sessions.values())
    assert len(sessions) == 1
    chain = sessions[0].refresh_chain
    assert len(chain) == 2  # 初始 + 唯一一次轮换
    assert sessions[0].current_refresh_jti == chain[-1]
    log.info("判定依据: 会话链长度=%d，current=%s，无不确定状态",
             len(chain), sessions[0].current_refresh_jti[:8])


def test_refresh_after_expiry_is_token_expired(client, ctx):
    data = login(client, "alice", "alice-pw")
    ctx.clock.advance(ctx.auth.config.refresh_ttl + 1)
    resp = _refresh(client, data["refresh_token"])
    body = resp.json()
    assert resp.status_code == 401
    assert body["error"] == "token_expired"
    log.info("判定依据: 过期刷新被拒 reason=%s", body["reason"])


def test_refresh_with_garbage_is_token_tampered(client):
    resp = _refresh(client, "not-a-token")
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_tampered"
