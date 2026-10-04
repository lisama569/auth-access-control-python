"""按主体的会话治理：目标主体存在性语义（bugfix-b）。

业务背景：
- GET  /admin/subjects/{username}/sessions         按主体列会话
- POST /admin/subjects/{username}/sessions/revoke  一次性注销该主体活会话

两个入口与单会话注销同构，固定按
    ① 认证 authenticate  -> 未认证一律 401（没带/带错令牌都在此结束）
    ② 权限 admin:revoke  -> 已认证但无权一律 403
    ③ 目标主体存在性     -> 认证+权限都通过后，主体从未注册才 404 subject_not_found
的顺序判定。本文件覆盖：
- 不存在的目标在两个入口都得到 404 subject_not_found（而非成功空操作）；
- 主体存在但没有会话不会被误判成不存在（200 空列表 / revoked_count=0）；
- 未认证（无令牌 / 错令牌）与无权限时，对"存在"与"不存在"目标的结论
  逐字节一致，不泄露存在性；
- 同一时刻反复判定不存在目标，结论稳定一致。
"""
from __future__ import annotations

import logging

import pytest

from .conftest import auth_header, login

log = logging.getLogger("tests")

MISSING = "ghost-user"  # 从未注册的用户名
EXISTING = "carol"      # 种子用户；本文件中始终不登录，故存在但无会话

LIST_PATH = f"/admin/subjects/{MISSING}/sessions"
REVOKE_PATH = f"/admin/subjects/{MISSING}/sessions/revoke"
LIST_PATH_EXISTING = f"/admin/subjects/{EXISTING}/sessions"
REVOKE_PATH_EXISTING = f"/admin/subjects/{EXISTING}/sessions/revoke"


def _admin(client):
    return auth_header(login(client, "alice", "alice-pw"))


def _viewer(client):
    return auth_header(login(client, "carol", "carol-pw"))


# ---------- 业务类：目标主体不存在 ----------

@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", LIST_PATH),
        ("POST", REVOKE_PATH),
    ],
    ids=["列会话-目标不存在", "批量注销-目标不存在"],
)
def test_nonexistent_subject_is_404_not_success_empty(client, method, path):
    """业务：目标主体从未注册；期望步骤①认证通过→②鉴权通过→③存在性判 404。

    旧行为把不存在当成"主体存在、只是没有会话"，返回 200 且数量 0；
    新行为必须明确给出 subject_not_found，不伪装成成功空操作。
    """
    resp = client.request(method, path, headers=_admin(client))
    assert resp.status_code == 404, resp.text
    assert resp.json()["error"] == "subject_not_found"
    log.info(
        "用例类别=目标不存在 入口=%s %s | 判定步骤: ①认证通过 -> ②权限admin:revoke通过 "
        "-> ③主体存在性=不存在 => 404 subject_not_found",
        method, path,
    )


def test_nonexistent_subject_judgement_is_stable_on_repeat(client):
    """业务：同一时刻反复判定不存在目标，两个入口的结论每次都一致。"""
    admin = _admin(client)
    for method, path in (("GET", LIST_PATH), ("POST", REVOKE_PATH)):
        answers = [
            (r.status_code, r.json()["error"])
            for r in (client.request(method, path, headers=admin) for _ in range(3))
        ]
        assert answers == [(404, "subject_not_found")] * 3, answers
    log.info(
        "用例类别=目标不存在-反复判定一致 | 判定步骤: ③主体存在性连续 3 次结论同为 "
        "404 subject_not_found（两个入口各自稳定）"
    )


# ---------- 业务类：主体存在但没有会话 ----------

def test_existing_subject_without_sessions_lists_empty_not_404(client):
    """业务：carol 已注册但从未登录（无任何会话）。

    与"不存在"严格区分：列会话返回 200、count=0、sessions=[]，
    不允许误判成 subject_not_found。
    """
    resp = client.get(LIST_PATH_EXISTING, headers=_admin(client))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["subject"] == EXISTING
    assert body["count"] == 0
    assert body["sessions"] == []
    log.info(
        "用例类别=存在但无会话 入口=列会话 | 判定步骤: ①认证通过 -> ②权限通过 -> "
        "③主体存在性=存在 => 200 空列表（与 404 不存在区分）"
    )


def test_existing_subject_without_sessions_bulk_revoke_is_zero_not_404(client):
    """业务：主体存在但无活会话时批量注销返回 200 revoked_count=0。

    重复调用仍为 0；随后该主体重新登录成功且新会话入列（不被牵连）。
    """
    admin = _admin(client)
    first = client.post(REVOKE_PATH_EXISTING, headers=admin)
    assert first.status_code == 200, first.text
    assert first.json()["revoked_count"] == 0
    second = client.post(REVOKE_PATH_EXISTING, headers=admin)
    assert second.status_code == 200
    assert second.json()["revoked_count"] == 0

    fresh = login(client, EXISTING, f"{EXISTING}-pw")
    body = client.get(LIST_PATH_EXISTING, headers=admin).json()
    assert body["count"] == 1
    assert body["sessions"][0]["status"] == "active"
    assert client.get("/docs/doc-1", headers=auth_header(fresh)).status_code == 200
    log.info(
        "用例类别=存在但无会话 入口=批量注销 | 判定步骤: ③主体存在性=存在 => "
        "200 revoked_count=0（重复仍 0），重新登录新会话 active 入列"
    )


# ---------- 业务类：未认证（存在性不得被透出） ----------

@pytest.mark.parametrize(
    "headers,label",
    [
        ({}, "未携带令牌"),
        ({"Authorization": "Bearer not-a-real-token"}, "携带非法令牌"),
    ],
    ids=["无令牌", "错令牌"],
)
def test_unauthenticated_same_conclusion_for_existing_and_missing_subject(
    client, headers, label
):
    """业务：步骤①认证即失败，结论与目标主体存不存在完全无关。

    对"存在(carol)"与"不存在(ghost-user)"目标的状态码与响应体必须逐字节一致。
    """
    for method in ("GET", "POST"):
        existing = client.request(method, LIST_PATH_EXISTING if method == "GET"
                                  else REVOKE_PATH_EXISTING, headers=headers)
        missing = client.request(method, LIST_PATH if method == "GET"
                                 else REVOKE_PATH, headers=headers)
        assert existing.status_code == 401, (label, existing.text)
        assert missing.status_code == 401, (label, missing.text)
        assert existing.json() == missing.json(), (label, existing.json(), missing.json())
        log.info(
            "用例类别=未认证(%s) 入口=%s | 判定步骤: ①认证失败(reason=%s) 即结束，"
            "存在/不存在目标响应逐字节一致，不走②③",
            label, method, existing.json()["reason"],
        )


# ---------- 业务类：已认证但无权限（存在性不得被透出） ----------

def test_forbidden_same_conclusion_for_existing_and_missing_subject(client):
    """业务：viewer 已认证但无 admin:revoke，步骤②即判 403。

    无论目标主体存在与否，状态码与响应体逐字节一致，杜绝主体枚举。
    """
    hdr = _viewer(client)
    for method, path_existing, path_missing in (
        ("GET", LIST_PATH_EXISTING, LIST_PATH),
        ("POST", REVOKE_PATH_EXISTING, REVOKE_PATH),
    ):
        existing = client.request(method, path_existing, headers=hdr)
        missing = client.request(method, path_missing, headers=hdr)
        assert existing.status_code == 403, existing.text
        assert missing.status_code == 403, missing.text
        assert existing.json() == missing.json(), (existing.json(), missing.json())
        assert existing.json()["reason"] == "missing_permission:admin:revoke"
        log.info(
            "用例类别=已认证无权限 入口=%s | 判定步骤: ①认证通过 -> ②鉴权失败 "
            "reason=missing_permission:admin:revoke 即结束，存在/不存在目标响应"
            "逐字节一致，不进入③",
            method,
        )
