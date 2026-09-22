"""权限模型演进：角色权限新增/收窄后，"既有令牌"的判定必须可预期。

本系统的设计选择：访问令牌只携带身份与会话信息，不携带权限快照；
权限在 Guard 中实时从 Store 聚合。因此：
- 新增权限 => 旧令牌下次请求立即获得新权限；
- 收窄权限 => 旧令牌下次请求立即失去该权限；
结论只取决于"当前权限表"，与令牌新旧无关，确定且可解释。
"""
from __future__ import annotations

import logging

from .conftest import auth_header, login

log = logging.getLogger("tests")


def _admin(client):
    return auth_header(login(client, "alice", "alice-pw"))


def test_grant_takes_effect_on_existing_token(client, ctx):
    carol = login(client, "carol", "carol-pw")  # viewer：无 doc:write

    before = client.put("/docs/doc-1", headers=auth_header(carol))
    assert before.status_code == 403

    r = client.post(
        "/admin/roles/permissions",
        headers=_admin(client),
        json={"role": "viewer", "permission": "doc:write"},
    )
    assert r.status_code == 200 and r.json()["added"] is True

    after = client.put("/docs/doc-1", headers=auth_header(carol))
    assert after.status_code == 200
    log.info("判定依据: 旧令牌在角色新增 doc:write 后立即放行（实时权限）")


def test_permission_narrowing_takes_effect_on_existing_token(client, ctx):
    bob = login(client, "bob", "bob-pw")  # editor：doc:read + doc:write
    assert client.get("/docs/doc-1", headers=auth_header(bob)).status_code == 200

    r = client.request(
        "DELETE",
        "/admin/roles/permissions",
        headers=_admin(client),
        json={"role": "editor", "permission": "doc:read"},
    )
    assert r.status_code == 200 and r.json()["removed"] is True

    after = client.get("/docs/doc-1", headers=auth_header(bob))
    assert after.status_code == 403
    assert after.json()["reason"] == "missing_permission:doc:read"
    log.info("判定依据: 旧令牌在角色收窄 doc:read 后立即 403，无需重新登录")


def test_permission_change_does_not_affect_other_permissions(client, ctx):
    """收窄写权限不影响读权限，判定细粒度且独立。"""
    bob = login(client, "bob", "bob-pw")
    client.request(
        "DELETE", "/admin/roles/permissions", headers=_admin(client),
        json={"role": "editor", "permission": "doc:write"},
    )
    assert client.get("/docs/doc-1", headers=auth_header(bob)).status_code == 200
    assert client.put("/docs/doc-1", headers=auth_header(bob)).status_code == 403
    log.info("判定依据: 权限逐条判定，doc:write 收窄不影响 doc:read")


def test_grant_to_nonexistent_role_is_noop(client, ctx):
    r = client.post(
        "/admin/roles/permissions", headers=_admin(client),
        json={"role": "ghost", "permission": "doc:read"},
    )
    assert r.status_code == 200
    assert r.json()["added"] is False


def test_rotated_token_also_reflects_live_permissions(client, ctx):
    """刷新轮换得到的新令牌同样不固化权限，跟随最新权限表。"""
    carol = login(client, "carol", "carol-pw")
    rotated = client.post(
        "/auth/refresh", json={"refresh_token": carol["refresh_token"]}
    ).json()

    client.post(
        "/admin/roles/permissions", headers=_admin(client),
        json={"role": "viewer", "permission": "doc:write"},
    )
    resp = client.put("/docs/doc-1", headers=auth_header(rotated))
    assert resp.status_code == 200
    log.info("判定依据: 轮换后的令牌仍按实时权限判定，新增权限立即生效")
