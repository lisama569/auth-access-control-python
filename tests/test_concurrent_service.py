"""服务层真实并发：在锁内交错，确保 CAS 竞争路径（refresh_conflict）被覆盖。

HTTP TestClient 经门户串行化请求，难以制造"两个线程都通过已使用检查、
同时 CAS"的窗口；这里直接在同一 AuthService 上用多线程 + 存储锁屏障，
人工构造该交错，验证：
- 恰好一次轮换成功；
- 竞争者得到 refresh_conflict（409 语义）而不是重放；
- 会话状态确定（链长度恰为 2，current 唯一）。
"""
from __future__ import annotations

import logging
import threading

from app.bootstrap import build_context
from app.errors import RefreshConflict, TokenReplayed

log = logging.getLogger("tests")


def test_real_concurrent_rotation_has_single_winner_and_conflict():
    ctx = build_context()
    pair = ctx.auth.issue("alice", "alice-pw")
    old_refresh = pair.refresh_token

    # 让两个线程都通过"未使用"快照检查后，在 CAS 临界区门口汇合
    barrier = threading.Barrier(2)
    orig_was_used = ctx.store.was_refresh_used

    def patched_was_used(jti: str) -> bool:
        seen = orig_was_used(jti)
        if not seen:
            barrier.wait(timeout=5)  # 都看到"未使用"后再一起抢锁
        return seen

    ctx.store.was_refresh_used = patched_was_used  # type: ignore[assignment]

    outcomes: list[str] = []
    lock = threading.Lock()

    def worker():
        try:
            new_pair = ctx.auth.refresh(old_refresh)
            with lock:
                outcomes.append("ok:" + new_pair.refresh_token[:8])
        except RefreshConflict:
            with lock:
                outcomes.append("conflict")
        except TokenReplayed:
            with lock:
                outcomes.append("replayed")

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert len(outcomes) == 2
    assert outcomes.count("conflict") == 1, outcomes
    assert sum(1 for o in outcomes if o.startswith("ok:")) == 1, outcomes

    session = next(iter(ctx.store.sessions.values()))
    assert len(session.refresh_chain) == 2
    log.info("判定依据: 真实并发交错 => %s；会话链长度=2 current=%s",
             outcomes, session.current_refresh_jti[:8])

    # 再用旧令牌刷新 => 确定归类为重放
    try:
        ctx.auth.refresh(old_refresh)
        raise AssertionError("旧令牌应当被拒绝")
    except TokenReplayed:
        log.info("判定依据: 竞争结束后旧令牌再使用 => refresh_replayed")


def test_repeated_serial_rotations_always_replay_old():
    ctx = build_context()
    pair = ctx.auth.issue("bob", "bob-pw")
    r0 = pair.refresh_token
    r1 = ctx.auth.refresh(r0).refresh_token
    r2 = ctx.auth.refresh(r1).refresh_token

    for old in (r0, r1):
        try:
            ctx.auth.refresh(old)
            raise AssertionError("旧刷新令牌必须被拒")
        except TokenReplayed:
            pass
    # 最新令牌仍可用
    assert ctx.auth.refresh(r2).refresh_token != r2
    log.info("判定依据: 串行轮换链 r0->r1->r2->r3，旧令牌一律重放拒绝")
