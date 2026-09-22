"""吊销语义：主体级、会话级、全局三种粒度，以及吊销后令牌立即失效。"""
from __future__ import annotations

import pytest

from auth.errors import AuthFailure, FailureCode


def test_subject_revocation_blocks_existing_tokens(service, caplog):
    pair = service.login("alice", "pw-alice")
    # 吊销前访问正常
    assert service.access_resource(pair.access_token, "doc-1").allowed

    service.revoke_subject("alice")   # 吊销时刻在令牌签发之后

    with pytest.raises(AuthFailure) as exc:
        service.access_resource(pair.access_token, "doc-1")
    assert exc.value.code is FailureCode.TOKEN_REVOKED

    # 刷新令牌同样被主体吊销拦截
    with pytest.raises(AuthFailure) as exc2:
        service.refresh(pair.refresh_token)
    assert exc2.value.code is FailureCode.TOKEN_REVOKED

    logs = [r.getMessage() for r in caplog.records]
    assert any("subject revoked" in m for m in logs)
    assert any("authenticate rejected" in m and "token_revoked" in m for m in logs), logs


def test_session_revocation_via_logout(service):
    pair = service.login("bob", "pw-bob")
    service.logout(pair.sid)
    with pytest.raises(AuthFailure) as exc:
        service.authenticate(pair.access_token)
    assert exc.value.code is FailureCode.SESSION_REVOKED
    with pytest.raises(AuthFailure) as exc2:
        service.refresh(pair.refresh_token)
    assert exc2.value.code is FailureCode.SESSION_REVOKED


def test_global_revocation_blocks_everyone(service):
    pa = service.login("alice", "pw-alice")
    pb = service.login("bob", "pw-bob")
    service.revoke_global()
    for pair in (pa, pb):
        with pytest.raises(AuthFailure) as exc:
            service.authenticate(pair.access_token)
        assert exc.value.code is FailureCode.GLOBAL_REVOKED


def test_revocation_does_not_affect_tokens_issued_afterward(service, clock):
    """边界语义：iat == revoked_at 视为吊销生效同时/之后签发，放行。"""
    pair_before = service.login("alice", "pw-alice")
    revoked_at = service.revoke_subject("alice")
    # 用未吊销主体验证全局场景：直接构造一个恰好在吊销时刻签发的令牌
    from auth.tokens import Claims
    import uuid
    session = service._store.get_session(pair_before.sid)
    claims = Claims(
        sub="alice", sid=session.sid, typ="access", jti=uuid.uuid4().hex,
        iat=revoked_at, exp=revoked_at + 900, pv=0,
    )
    token_at_boundary = service._codec.encode(claims)
    assert service.authenticate(token_at_boundary)[0] == "alice"  # iat == revoked_at 放行
    with pytest.raises(AuthFailure) as exc:
        service.authenticate(pair_before.access_token)           # 早于吊销 => 拒绝
    assert exc.value.code is FailureCode.TOKEN_REVOKED


def test_revocation_order_global_before_subject(service):
    """三类吊销同时命中时原因可解释且确定：全局优先。"""
    pair = service.login("alice", "pw-alice")
    service.revoke_subject("alice")
    service.revoke_global()
    with pytest.raises(AuthFailure) as exc:
        service.authenticate(pair.access_token)
    assert exc.value.code is FailureCode.GLOBAL_REVOKED
