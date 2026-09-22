"""权限模型演进：权限实时判定，既有令牌结果随模型确定变化，令牌 pv 仅作快照。"""
from __future__ import annotations

import pytest

from auth.errors import AuthFailure, FailureCode


def test_permission_grant_applies_to_existing_token(service, caplog):
    pair = service.login("carol", "pw-carol")   # auditor 初始只有 audit:read
    # 收窄前：carol 访问 doc-1（需 resource:read）被拒
    with pytest.raises(AuthFailure) as exc:
        service.access_resource(pair.access_token, "doc-1")
    assert exc.value.code is FailureCode.FORBIDDEN

    # 新增权限后：同一个未换发的令牌立即放行
    new_pv = service.grant_permission("auditor", "resource:read")
    decision = service.access_resource(pair.access_token, "doc-1")
    assert decision.allowed
    assert decision.perm_version == new_pv

    # 判定依据日志同时包含令牌快照 pv 与模型当前 pv
    logs = [r.getMessage() for r in caplog.records]
    assert any("token_pv=0" in m and f"model_pv={new_pv}" in m for m in logs), logs


def test_permission_narrowing_revokes_existing_token_access(service):
    pair = service.login("alice", "pw-alice")   # admin: resource:read
    assert service.access_resource(pair.access_token, "doc-1").allowed

    # 收窄权限：既有令牌（未过期、未吊销）立即失去访问权，结果确定
    service.revoke_permission("admin", "resource:read")
    with pytest.raises(AuthFailure) as exc:
        service.access_resource(pair.access_token, "doc-1")
    assert exc.value.code is FailureCode.FORBIDDEN
    assert "resource:read" in exc.value.reason


def test_permission_change_does_not_revoke_session(service):
    """权限收窄只影响授权判定，不影响认证：令牌仍有效，会话仍存活。"""
    pair = service.login("bob", "pw-bob")
    service.revoke_permission("viewer", "resource:read")
    sub, sid = service.authenticate(pair.access_token)   # 认证仍通过
    assert sub == "bob" and sid == pair.sid
    with pytest.raises(AuthFailure) as exc:
        service.access_resource(pair.access_token, "doc-1")
    assert exc.value.code is FailureCode.FORBIDDEN


def test_perm_version_monotonic_and_noop_is_noop(service, store):
    pv0 = store.perm_version
    assert service.grant_permission("viewer", "audit:read") == pv0 + 1
    # 重复授予不产生版本跳变（幂等，避免无意义演进）
    assert service.grant_permission("viewer", "audit:read") == pv0 + 1
    assert service.revoke_permission("viewer", "audit:read") == pv0 + 2
    assert service.revoke_permission("viewer", "audit:read") == pv0 + 2
