"""刷新轮换：容忍窗口内幂等重试、窗口外/更早旧令牌判泄露整串作废、
并发刷新只有一次真正推进。

状态机（每个会话只认一个当前刷新 jti，CAS 原子切换）：
- 已被标记使用的旧令牌，在 retry_window 内、且属于最近一次轮换
  => 视为网络重试，原样回放第一次返回的令牌对，会话不二次推进；
- 超出窗口，或属于更早一次轮换的旧令牌
  => 401 refresh_chain_revoked：判定凭证泄露，整串令牌作废；
- 与轮换真正并发、读到"未使用"快照后 CAS 失败
  => 409 refresh_conflict。
三类结论可区分，任何情况下会话状态只前进、不回滚。
"""
from __future__ import annotations

import logging
import threading

from app.tokens import decode

from .conftest import auth_header, login

log = logging.getLogger("tests")


def _refresh(client, token: str):
    return client.post("/auth/refresh", json={"refresh_token": token})


def test_refresh_rotates_both_tokens(client, ctx):
    data = login(client, "alice", "alice-pw")
    sid_before = decode(data["access_token"], ctx.auth.config.secret).sid

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


def test_in_window_retry_returns_identical_pair_and_does_not_advance(client, ctx):
    """容忍窗口内重复提交上一次刚用掉的刷新令牌：原样回放，会话不推进两次。"""
    data = login(client, "alice", "alice-pw")
    first = _refresh(client, data["refresh_token"])
    assert first.status_code == 200
    first_body = first.json()

    # 时间停在容忍窗口内（默认 5s）再次提交同一个旧刷新令牌
    retry = _refresh(client, data["refresh_token"])
    assert retry.status_code == 200, retry.text
    retry_body = retry.json()
    assert retry_body["access_token"] == first_body["access_token"]
    assert retry_body["refresh_token"] == first_body["refresh_token"]
    log.info("判定依据: 窗口内重试命中第 1 次轮换，返回完全相同的令牌对")

    # 无论重试多少次，会话只推进一次：链长恰为 2、轮换序号为 1
    sessions = list(ctx.store.sessions.values())
    assert len(sessions) == 1
    assert len(sessions[0].refresh_chain) == 2
    assert sessions[0].rotation_seq == 1
    assert sessions[0].current_refresh_jti == sessions[0].refresh_chain[-1]
    log.info("判定依据: 重试后 chain_len=2 rotation_seq=1，会话未二次推进")


def test_retry_window_boundary_is_deterministic(client, ctx):
    """边界确定性：age == window 算窗口内；再向前任何一点都算窗口外。"""
    data = login(client, "alice", "alice-pw")
    first = _refresh(client, data["refresh_token"]).json()

    ctx.clock.advance(ctx.auth.config.retry_window)  # 恰好等号
    at_edge = _refresh(client, data["refresh_token"])
    assert at_edge.status_code == 200
    assert at_edge.json()["refresh_token"] == first["refresh_token"]
    log.info("判定依据: age==window(%.3f) 稳定算窗口内重试", ctx.auth.config.retry_window)

    data2 = login(client, "bob", "bob-pw")
    _refresh(client, data2["refresh_token"])
    ctx.clock.advance(ctx.auth.config.retry_window + 0.001)
    outside = _refresh(client, data2["refresh_token"])
    assert outside.status_code == 401
    assert outside.json()["error"] == "refresh_chain_revoked"
    log.info("判定依据: age>window 稳定判泄露 reason=%s", outside.json()["reason"])


def test_out_of_window_reuse_revokes_whole_chain_distinctly(client, ctx):
    """超出容忍窗口再次使用旧刷新令牌：整串作废，且结论与普通注销可区分。"""
    data = login(client, "alice", "alice-pw")
    rotated = _refresh(client, data["refresh_token"]).json()

    ctx.clock.advance(ctx.auth.config.retry_window + 1)
    resp = _refresh(client, data["refresh_token"])
    body = resp.json()
    assert resp.status_code == 401
    assert body["error"] == "refresh_chain_revoked"
    log.info("判定依据: 窗口外旧刷新 => reason=%s（区别于 token_revoked）", body["reason"])

    # 整串：登录时发的访问令牌、轮换出的访问/刷新令牌此后一律不放行
    old_access = client.get("/docs/doc-1", headers=auth_header(data))
    assert old_access.status_code == 401
    assert old_access.json()["error"] == "refresh_chain_revoked"

    new_access = client.get("/docs/doc-1", headers=auth_header(rotated))
    assert new_access.status_code == 401
    assert new_access.json()["error"] == "refresh_chain_revoked"

    newest_refresh = _refresh(client, rotated["refresh_token"])
    assert newest_refresh.status_code == 401
    assert newest_refresh.json()["error"] == "refresh_chain_revoked"

    # 会话状态在治理视图中呈现为 compromised
    sid = decode(data["access_token"], ctx.auth.config.secret).sid
    session = ctx.store.get_session(sid)
    assert session.compromised and not session.revoked
    log.info("判定依据: 整串作废后所有访问/刷新均为 refresh_chain_revoked")


def test_older_refresh_token_within_window_still_revokes_chain(client, ctx):
    """即使没超窗口，拿"更早之前"的旧刷新令牌（非上一次轮换）也判泄露。"""
    data = login(client, "bob", "bob-pw")
    r0 = data["refresh_token"]
    r1 = _refresh(client, r0).json()["refresh_token"]
    r2 = _refresh(client, r1).json()["refresh_token"]

    # r1 是上一次刚换掉的，窗口内可幂等重试
    retry_r1 = _refresh(client, r1)
    assert retry_r1.status_code == 200
    assert retry_r1.json()["refresh_token"] == r2

    # r0 属于更早一次轮换：即使时间几乎没走，也是泄露 => 整串作废
    resp = _refresh(client, r0)
    assert resp.status_code == 401
    assert resp.json()["error"] == "refresh_chain_revoked"
    log.info("判定依据: 更早的旧刷新令牌 => refresh_chain_revoked")

    # 泄露后最新令牌也不能用
    assert _refresh(client, r2).json()["error"] == "refresh_chain_revoked"


def test_in_window_retry_is_harmless_to_newest_token(client):
    """窗口内重试不污染链路：最新刷新令牌随后仍正常轮换。"""
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]
    r1 = _refresh(client, r0).json()["refresh_token"]
    # r0 窗口内重试：原样回放
    assert _refresh(client, r0).json()["refresh_token"] == r1
    # r1 仍正常轮换到 r2
    resp = _refresh(client, r1)
    assert resp.status_code == 200
    r2 = resp.json()["refresh_token"]
    assert r2 != r1
    log.info("判定依据: 窗口内重试不影响最新令牌，轮换链单调推进")


def test_concurrent_refresh_exactly_one_advances(client, ctx):
    """N 个线程同时用同一个刷新令牌：恰好一次真正轮换；

    其余请求要么 409 refresh_conflict（读到未使用快照后 CAS 失败），
    要么在窗口内拿到与成功者完全相同的令牌对（幂等重试），
    绝不出现整串作废，链长度恒为 2。
    """
    data = login(client, "alice", "alice-pw")
    r0 = data["refresh_token"]

    barrier = threading.Barrier(8)
    results: list[tuple[int, str]] = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        resp = _refresh(client, r0)
        with lock:
            results.append((resp.status_code, resp.json().get("refresh_token", "")[:12]
                            if resp.status_code == 200 else resp.json().get("error", "?")))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[0] == 200]
    conflicts = [r for r in results if r[0] == 409]
    assert len(successes) >= 1, results
    # 所有 200 必须返回同一个刷新令牌（一次轮换 + 幂等回放）
    assert len({token for _, token in successes}) == 1, results
    assert {code for code, _ in results if code not in (200, 409)} == set(), results
    assert all(err == "refresh_conflict" for code, err in conflicts)
    log.info(
        "判定依据: 8 并发刷新 => 成功(含回放) %d，409 竞争 %d，令牌对唯一",
        len(successes), len(conflicts),
    )

    sessions = list(ctx.store.sessions.values())
    assert len(sessions) == 1
    chain = sessions[0].refresh_chain
    assert len(chain) == 2  # 初始 + 唯一真正轮换
    assert sessions[0].rotation_seq == 1
    assert sessions[0].current_refresh_jti == chain[-1]
    log.info("判定依据: 会话链长度=%d rotation_seq=1，无不确定状态", len(chain))


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
