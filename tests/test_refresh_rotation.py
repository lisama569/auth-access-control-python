"""刷新轮换：旧令牌重放、并发刷新只有一次成功。

状态机（每个会话只认一个当前刷新 jti，CAS 原子切换）：
- 已被标记使用的旧令牌再次使用 => 401 refresh_replayed
- 与轮换并发、读到"未使用"快照后 CAS 失败 => 409 refresh_conflict
两种失败原因可区分，且任何情况下会话状态只前进、不回滚。
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


def test_replay_of_rotated_refresh_is_rejected_distinctly(client, ctx):
    data = login(client, "alice", "alice-pw")
    old_refresh = data["refresh_token"]
    assert _refresh(client, old_refresh).status_code == 200

    resp = _refresh(client, old_refresh)
    body = resp.json()
    assert resp.status_code == 401
    assert body["error"] == "refresh_replayed"

    # 会话状态未被重放破坏：再次重放同样被拒
    current = _refresh(client, old_refresh)
    assert current.status_code == 401
    assert current.json()["error"] == "refresh_replayed"
    log.info("判定依据: 旧刷新重放被拒 reason=%s，会话状态保持一致", body["reason"])


def test_newest_refresh_token_remains_usable_after_replay_attempts(client):
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    r1 = _refresh(client, r0).json()["refresh_token"]
    assert _refresh(client, r0).status_code == 401  # 重放 r0
    resp = _refresh(client, r1)                      # r1 仍正常轮换
    assert resp.status_code == 200
    r2 = resp.json()["refresh_token"]
    assert _refresh(client, r1).status_code == 401  # r1 现在也成了旧令牌
    assert _refresh(client, r2).status_code == 200  # r2 可用
    log.info("判定依据: 重放不影响最新令牌，轮换链单调推进")


def test_concurrent_refresh_exactly_one_wins(client, ctx):
    """N 个线程同时用同一个刷新令牌：恰好一次成功，其余为冲突/重放。"""
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]

    barrier = threading.Barrier(8)
    results: list[tuple[int, str]] = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        resp = _refresh(client, r0)
        with lock:
            results.append((resp.status_code, resp.json().get("error", "ok")))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[0] == 200]
    failures = [r for r in results if r[0] != 200]
    assert len(successes) == 1, results
    assert all(code in (401, 409) for code, _ in failures)
    assert {err for _, err in failures} <= {"refresh_replayed", "refresh_conflict"}
    log.info(
        "判定依据: 8 并发刷新 => 成功 %d，失败归类 %s",
        len(successes), sorted(err for _, err in failures),
    )

    # 存储层验证状态一致性：每个会话只有一个 current jti，链长度恰好为 2
    sessions = list(ctx.store.sessions.values())
    assert len(sessions) == 1
    chain = sessions[0].refresh_chain
    assert len(chain) == 2  # 初始 + 唯一成功轮换
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
