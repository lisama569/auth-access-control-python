"""同一会话并发刷新：恰好一次成功，其余为 CONFLICT 且状态确定不变。"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from auth.errors import AuthFailure, FailureCode


def test_concurrent_refresh_exactly_one_wins(service, caplog):
    pair = service.login("alice", "pw-alice")
    n = 32
    barrier = threading.Barrier(n)
    results: list[object] = []

    def do_refresh():
        barrier.wait()          # 尽量让所有线程同时进入临界区
        try:
            return ("ok", service.refresh(pair.refresh_token))
        except AuthFailure as e:
            return ("fail", e.code)

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(lambda _: do_refresh(), range(n)))

    oks = [r for r in results if r[0] == "ok"]
    fails = [r for r in results if r[0] == "fail"]
    assert len(oks) == 1, f"成功次数必须恰好为 1，实际 {len(oks)}: {results}"
    assert all(r[1] is FailureCode.REFRESH_CONFLICT for r in fails), fails
    assert len(fails) == n - 1

    # 状态确定：会话未被吊销，当前刷新令牌即中标者签发的那一个
    session = service._store.get_session(pair.sid)
    assert session.revoked_at is None
    winner_token = oks[0][1].refresh_token
    winner_claims = service._codec.decode(winner_token, at=session.created_at + 1, leeway=3600)
    assert session.refresh.jti == winner_claims.jti
    assert len(session.history) == 1 and session.history[0].consumed

    logs = [r.getMessage() for r in caplog.records]
    assert any("refresh ok" in m for m in logs)
    assert any("并发" in m and "会话状态不变" in m for m in logs), logs


def test_conflict_does_not_consume_winner_token(service):
    """落败请求不得让中标令牌失效：中标返回后可继续轮换。"""
    pair = service.login("bob", "pw-bob")
    p1 = service.refresh(pair.refresh_token)
    with __import__("pytest").raises(AuthFailure) as exc:
        service.refresh(pair.refresh_token)   # 窗口内落败
    assert exc.value.code is FailureCode.REFRESH_CONFLICT
    p2 = service.refresh(p1.refresh_token)    # 中标令牌仍可正常轮换
    sub, _ = service.authenticate(p2.access_token)
    assert sub == "bob"


def test_race_after_grace_is_replay_not_conflict(service, clock):
    """宽限窗口外的再次出现必须归类为重放而非并发冲突。"""
    pair = service.login("carol", "pw-carol")
    service.refresh(pair.refresh_token)
    clock.set_offset(6.0)  # 超过 replay_grace=5s
    with __import__("pytest").raises(AuthFailure) as exc:
        service.refresh(pair.refresh_token)
    assert exc.value.code is FailureCode.REFRESH_REPLAYED
    assert service._store.get_session(pair.sid).revoked_at is not None
