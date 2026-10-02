"""服务层真实并发：在锁内交错，确保 CAS 竞争路径（refresh_conflict）被覆盖。

HTTP TestClient 经门户串行化请求，难以制造"两个线程都通过已使用检查、
同时 CAS"的窗口；这里直接在同一 AuthService 上用多线程 + 存储锁屏障，
人工构造该交错，验证：
- 恰好一次轮换真正成功；
- 竞争者得到 refresh_conflict（409 语义），既不是回放也不是泄露；
- 竞争结束后，窗口内用同一旧令牌重试得到与成功者完全相同的令牌对，
  会话状态确定（链长度恰为 2，rotation_seq=1，current 唯一）。
"""
from __future__ import annotations

import logging
import threading

from app.bootstrap import build_context
from app.errors import RefreshChainRevoked, RefreshConflict
from app.tokens import decode

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
    winner_pair: list[str] = []
    lock = threading.Lock()

    def worker():
        try:
            new_pair = ctx.auth.refresh(old_refresh)
            with lock:
                outcomes.append("ok")
                winner_pair.append(new_pair.refresh_token)
        except RefreshConflict:
            with lock:
                outcomes.append("conflict")

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert len(outcomes) == 2
    assert outcomes.count("conflict") == 1, outcomes
    assert outcomes.count("ok") == 1, outcomes

    session = next(iter(ctx.store.sessions.values()))
    assert len(session.refresh_chain) == 2
    assert session.rotation_seq == 1
    log.info("判定依据: 真实并发交错 => %s；会话链长度=2 rotation_seq=1 current=%s",
             outcomes, session.current_refresh_jti[:8])

    # 竞争结束后（仍在容忍窗口内）用旧令牌重试：不是 409 也不是泄露，
    # 而是命中第 1 次轮换的幂等记录，回放完全相同的令牌对
    retried = ctx.auth.refresh(old_refresh)
    assert retried.refresh_token == winner_pair[0]
    assert session.rotation_seq == 1
    log.info("判定依据: 竞争后窗口内重试 => 幂等回放第 1 次轮换结果，会话仍只推进一次")


def test_chain_rotation_with_in_window_retries_never_double_advances():
    """串行轮换链中夹着窗口内重试：链只按真实轮换次数推进。"""
    ctx = build_context()
    pair = ctx.auth.issue("bob", "bob-pw")
    r0 = pair.refresh_token
    p1 = ctx.auth.refresh(r0)
    r1 = p1.refresh_token
    # r0 窗口内重试：回放 p1
    assert ctx.auth.refresh(r0).refresh_token == r1
    p2 = ctx.auth.refresh(r1)
    r2 = p2.refresh_token
    # r1 窗口内重试：回放 p2
    assert ctx.auth.refresh(r1).refresh_token == r2

    session = next(iter(ctx.store.sessions.values()))
    r2_jti = decode(r2, ctx.auth.config.secret).jti
    assert session.rotation_seq == 2
    assert session.current_refresh_jti == session.refresh_chain[-1] == r2_jti
    # 最新令牌仍可正常轮换
    assert ctx.auth.refresh(r2).refresh_token != r2
    log.info("判定依据: 两次真实轮换+两次窗口内重试 => rotation_seq=2，链不双推进")


def test_reused_old_token_outside_window_compromises_chain():
    """串行轮换后超出窗口重放旧令牌 => 整串作废，最新令牌同样失效。"""
    ctx = build_context()
    pair = ctx.auth.issue("bob", "bob-pw")
    r0 = pair.refresh_token
    r1 = ctx.auth.refresh(r0).refresh_token
    r2 = ctx.auth.refresh(r1).refresh_token

    ctx.clock.advance(ctx.auth.config.retry_window + 0.01)
    try:
        ctx.auth.refresh(r0)
        raise AssertionError("窗口外旧刷新令牌必须判泄露")
    except RefreshChainRevoked:
        pass

    session = next(iter(ctx.store.sessions.values()))
    assert session.compromised
    # 最新刷新令牌也不能再推进
    try:
        ctx.auth.refresh(r2)
        raise AssertionError("整串作废后最新令牌也应被拒")
    except RefreshChainRevoked:
        pass
    log.info("判定依据: 窗口外旧令牌 => refresh_chain_revoked，整串(含 r2)失效")
