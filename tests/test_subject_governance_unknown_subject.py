"""按主体会话治理：目标主体不存在的失败结论与判定顺序。

覆盖：
- 不存在的目标主体：列会话 / 批量注销都返回 404 subject_not_found，
  不再伪装成"成功但数量为 0"的空操作；
- 已注册但从无会话的主体：两个入口都按"存在但为空"处理（200 / 0），
  不会被误判成不存在；
- 判定顺序与单个会话注销一致：认证(401) -> 权限(403) -> 目标存在性(404)；
  未认证/无权限时，对存在与不存在的主体结论逐字节一致，不泄露存在性；
- 同一时刻反复判定结论一致；已存在主体的既有治理行为不回归。
"""
from __future__ import annotations

import logging

from .conftest import auth_header, login

log = logging.getLogger("tests")

GHOST = "ghost-never-registered"


def _admin(client):
    return auth_header(login(client, "alice", "alice-pw"))


# ---------- 目标主体不存在：两个入口都明确失败 ----------

def test_list_sessions_unknown_subject_reports_subject_not_found(client):
    resp = client.get(f"/admin/subjects/{GHOST}/sessions", headers=_admin(client))
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"] == "subject_not_found"
    assert body["reason"] == "subject_not_found"
    # 绝不是一次"成功的空操作"
    assert "sessions" not in body and "count" not in body
    log.info("判定依据: 目标主体从未注册 => 列会话 404 subject_not_found，"
             "与'存在但没有会话'的 200/空列表 严格区分")


def test_bulk_revoke_unknown_subject_reports_subject_not_found(client):
    resp = client.post(f"/admin/subjects/{GHOST}/sessions/revoke", headers=_admin(client))
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"] == "subject_not_found"
    assert "revoked_count" not in body
    log.info("判定依据: 目标主体从未注册 => 批量注销 404 subject_not_found，"
             "不返回 revoked_count=0 伪装成功")


def test_unknown_subject_conclusion_stable_across_repeated_calls(client):
    """同一时刻反复判定，结论必须一致（不存在的不会忽然变成存在）。"""
    admin = _admin(client)
    for _ in range(3):
        r_list = client.get(f"/admin/subjects/{GHOST}/sessions", headers=admin)
        r_bulk = client.post(f"/admin/subjects/{GHOST}/sessions/revoke", headers=admin)
        assert r_list.status_code == 404 and r_list.json()["error"] == "subject_not_found"
        assert r_bulk.status_code == 404 and r_bulk.json()["error"] == "subject_not_found"
    log.info("判定依据: 同一时刻连续 3 次判定两个入口，结论均为 404 subject_not_found")


# ---------- 已注册但无会话的主体：不得误判为不存在 ----------

def test_registered_subject_without_sessions_is_not_confused_with_missing(client):
    admin = _admin(client)
    # carol 已注册但从未登录，没有任何会话
    r_list = client.get("/admin/subjects/carol/sessions", headers=admin)
    assert r_list.status_code == 200
    assert r_list.json()["count"] == 0
    assert r_list.json()["sessions"] == []

    r_bulk = client.post("/admin/subjects/carol/sessions/revoke", headers=admin)
    assert r_bulk.status_code == 200
    assert r_bulk.json()["revoked_count"] == 0
    log.info("判定依据: 主体已注册但无会话 => 200 + 空列表 / revoked_count=0，"
             "与 subject_not_found 明确区分")


def test_subject_with_only_dead_sessions_still_exists(client, ctx):
    """会话全部注销后主体依然存在：列会话 200（全 revoked），批量注销 200/0。"""
    admin = _admin(client)
    login(client, "bob", "bob-pw")
    first = client.post("/admin/subjects/bob/sessions/revoke", headers=admin)
    assert first.status_code == 200 and first.json()["revoked_count"] == 1

    r_list = client.get("/admin/subjects/bob/sessions", headers=admin)
    assert r_list.status_code == 200
    assert [s["status"] for s in r_list.json()["sessions"]] == ["revoked"]

    again = client.post("/admin/subjects/bob/sessions/revoke", headers=admin)
    assert again.status_code == 200 and again.json()["revoked_count"] == 0
    log.info("判定依据: 主体存在但会话已全部注销 => 仍 200，"
             "重复批量注销 revoked_count=0（幂等，不重复计数）")


# ---------- 判定顺序：认证 -> 权限 -> 目标存在性，不泄露存在性 ----------

def test_unauthenticated_hides_subject_existence(client):
    """未认证：对存在与不存在的主体，两个入口结论完全一致（401）。"""
    login(client, "bob", "bob-pw")  # bob 有会话，是"存在"的目标
    for subject in ("bob", GHOST):
        r_list = client.get(f"/admin/subjects/{subject}/sessions")
        r_bulk = client.post(f"/admin/subjects/{subject}/sessions/revoke")
        assert r_list.status_code == 401 and r_list.json()["error"] == "unauthenticated"
        assert r_bulk.status_code == 401 and r_bulk.json()["error"] == "unauthenticated"
        assert r_list.json() == client.get(
            f"/admin/subjects/{subject}/sessions").json()
    log.info("判定依据: 未带令牌 => 一律 401 unauthenticated，"
             "存在(bob)与不存在(ghost)的主体结论逐字节一致")


def test_forbidden_hides_subject_existence(client):
    """已认证但无权限：对存在与不存在的主体，结论完全一致（403），不泄露存在性。"""
    bob = login(client, "bob", "bob-pw")  # editor，无 admin:revoke
    hdr = auth_header(bob)
    conclusions = {}
    for subject in ("bob", GHOST):
        r_list = client.get(f"/admin/subjects/{subject}/sessions", headers=hdr)
        r_bulk = client.post(f"/admin/subjects/{subject}/sessions/revoke", headers=hdr)
        assert r_list.status_code == 403 and r_list.json()["error"] == "forbidden"
        assert r_bulk.status_code == 403 and r_bulk.json()["error"] == "forbidden"
        conclusions[subject] = (r_list.json(), r_bulk.json())
    assert conclusions["bob"] == conclusions[GHOST]
    log.info("判定依据: 已认证但缺 admin:revoke => 一律 403 forbidden，"
             "响应体对存在/不存在主体完全相同，存在性不外泄")


def test_decision_order_authn_then_authz_then_existence(client):
    """与单个会话注销同一条顺序：认证 -> 权限 -> 目标存在性。"""
    admin = _admin(client)
    bob = login(client, "bob", "bob-pw")

    # 1) 认证失败优先于一切：坏令牌 + 不存在的主体 => 401（不是 404）
    bad = {"Authorization": "Bearer not-a-real-token"}
    assert client.get(f"/admin/subjects/{GHOST}/sessions", headers=bad).status_code == 401
    assert client.post(
        f"/admin/subjects/{GHOST}/sessions/revoke", headers=bad).status_code == 401

    # 2) 权限不足优先于存在性：无权限 + 不存在的主体 => 403（不是 404）
    hdr = auth_header(bob)
    assert client.get(f"/admin/subjects/{GHOST}/sessions", headers=hdr).status_code == 403
    assert client.post(
        f"/admin/subjects/{GHOST}/sessions/revoke", headers=hdr).status_code == 403

    # 3) 认证与权限都通过后，才判定目标存在性 => 404
    assert client.get(f"/admin/subjects/{GHOST}/sessions", headers=admin).status_code == 404
    assert client.post(
        f"/admin/subjects/{GHOST}/sessions/revoke", headers=admin).status_code == 404
    log.info("判定依据: 固定顺序 认证(401) -> 权限(403) -> 目标存在性(404)，"
             "与 /admin/sessions/{sid}/revoke 一致")


# ---------- 已存在主体的既有行为不回归 ----------

def test_existing_subject_governance_flow_unchanged(client, ctx):
    """批量注销只清活会话 -> 重新登录成功 -> 新会话以 active 入列。"""
    admin = _admin(client)
    bob1 = login(client, "bob", "bob-pw")
    bob2 = login(client, "bob", "bob-pw")

    r = client.post("/admin/subjects/bob/sessions/revoke", headers=admin)
    assert r.status_code == 200 and r.json()["revoked_count"] == 2
    for tokens in (bob1, bob2):
        assert client.get("/docs/doc-1", headers=auth_header(tokens)).status_code == 401

    # 重复调用返回 0，且主体仍然"存在"（不是 404）
    r = client.post("/admin/subjects/bob/sessions/revoke", headers=admin)
    assert r.status_code == 200 and r.json()["revoked_count"] == 0

    bob3 = login(client, "bob", "bob-pw")
    assert client.get("/docs/doc-1", headers=auth_header(bob3)).status_code == 200
    body = client.get("/admin/subjects/bob/sessions", headers=admin).json()
    assert body["count"] == 3
    assert body["sessions"][-1]["status"] == "active"
    for s in body["sessions"]:
        assert "token" not in s and "jti" not in s
    log.info("判定依据: 已存在主体治理流程不变：注销活会话 -> 重登录 -> "
             "新会话 active 入列；列表只暴露标识/时间/状态")
