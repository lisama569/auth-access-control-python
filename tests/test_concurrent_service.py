"""服务层真实并发：在锁内交错，确保 CAS 竞争路径（refresh_conflict）被覆盖。

HTTP TestClient 经门户串行化请求，难以制造"两个线程都通过已使用检查、
同时 CAS"的窗口；这里直接在同一 AuthService 上用多线程 + 存储锁屏障，
人工构造该交错，验证：
- 恰好一次轮换成功；
- 竞争者得到 refresh_conflict（409 语义）而不是重试/泄露；
- 会话状态确定（链长度恰为 2，current 唯一）；
- 竞争结束后：窗口内再用旧令牌 => 幂等重试返回同一对令牌；
  超出窗口再用 => refresh_reuse_detected 且整串作废。
"""
from __future__ import annotations

import logging
import threading

from app.bootstrap import build_context
from app.errors import RefreshConflict, RefreshReuseDetected

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
        except RefreshReuseDetected:
            with lock:
                outcomes.append("reuse_detected")

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

    # 竞争结束后、窗口内再用旧令牌 => 幂等重试，返回与首次完全相同的一对
    first_pair = ctx.auth.refresh(old_refresh)
    again = ctx.auth.refresh(old_refresh)
    assert again.access_token == first_pair.access_token
    assert again.refresh_token == first_pair.refresh_token
    assert len(session.refresh_chain) == 2  # 会话未被推进第二次
    log.info("判定依据: 窗口内重试返回首次令牌对，链长度仍为 2")

    # 超出容忍窗口再用 => 泄露判定，整串作废
    ctx.clock.advance(ctx.auth.config.refresh_retry_window + 0.1)
    try:
        ctx.auth.refresh(old_refresh)
        raise AssertionError("窗口外旧令牌必须被判为泄露")
    except RefreshReuseDetected:
        log.info("判定依据: 窗口外旧令牌 => refresh_reuse_detected，整串作废")
    assert session.revoked and session.revoked_reason == "reuse_detected"


def test_repeated_serial_rotations_retry_then_reuse_detected():
    """串行轮换链：窗口内重试上一任令牌 => 同一对；更早旧令牌 => 泄露。"""
    ctx = build_context()
    pair = ctx.auth.issue("bob", "bob-pw")
    r0 = pair.refresh_token
    p1 = ctx.auth.refresh(r0)
    p2 = ctx.auth.refresh(p1.refresh_token)

    # 窗口内重试"上一次刚被换掉的"r1 => 返回与 p2 完全相同的一对
    retry = ctx.auth.refresh(p1.refresh_token)
    assert retry.refresh_token == p2.refresh_token
    assert retry.access_token == p2.access_token

    # 更早的旧令牌 r0（非上一任）=> 立即判泄露，整串作废
    try:
        ctx.auth.refresh(r0)
        raise AssertionError("更早的旧令牌必须被判为泄露")
    except RefreshReuseDetected:
        pass

    session = next(iter(ctx.store.sessions.values()))
    assert session.revoked_reason == "reuse_detected"
    # 整串作废后，最新刷新令牌也不可用
    try:
        ctx.auth.refresh(p2.refresh_token)
        raise AssertionError("整串作废后任何令牌都不可用")
    except RefreshReuseDetected:
        pass
    log.info("判定依据: 串行链 r0->r1->r2，重试命中上一任；更早旧令牌触发整串作废")
