"""刷新令牌轮换：正常轮换、重放分类、过期/篡改可区分。"""
from __future__ import annotations

import logging

import pytest

from auth.errors import FailureCode


def _login(service, username="alice", password="pw-alice"):
    return service.login(username, password)


def test_refresh_rotates_and_old_token_is_revoked(service, clock, caplog):
    pair = _login(service)
    new_pair = service.refresh(pair.refresh_token)
    assert new_pair.sid == pair.sid
    assert new_pair.refresh_token != pair.refresh_token
    assert new_pair.access_token != pair.access_token

    # 超出重放宽限窗口后使用旧令牌 => REPLAYED，且整个会话被吊销
    clock.set_offset(10.0)
    with caplog.at_level(logging.INFO):
        with pytest.raises(Exception) as exc:
            service.refresh(pair.refresh_token)
    assert exc.value.code is FailureCode.REFRESH_REPLAYED
    session = service._store.get_session(pair.sid)
    assert session.revoked_at is not None, "重放必须吊销整个会话"

    # 重放后，刚轮换出的新令牌也无法再使用（会话已吊销）
    with pytest.raises(Exception) as exc2:
        service.refresh(new_pair.refresh_token)
    assert exc2.value.code is FailureCode.SESSION_REVOKED

    logs = [r.getMessage() for r in caplog.records]
    assert any("refresh ok" in m and "old_jti" in m for m in logs), logs
    assert any("refresh rejected" in m or "重放" in m for m in logs), logs


def test_refresh_with_expired_token_is_token_expired(service, clock):
    pair = _login(service)
    clock.set_offset(86400.0 + 1.0)  # refresh_ttl 已过
    with pytest.raises(Exception) as exc:
        service.refresh(pair.refresh_token)
    assert exc.value.code is FailureCode.TOKEN_EXPIRED


def test_refresh_with_tampered_signature_is_bad_signature(service):
    pair = _login(service)
    tampered = pair.refresh_token[:-3] + ("AAA" if pair.refresh_token[-3:] != "AAA" else "BBB")
    with pytest.raises(Exception) as exc:
        service.refresh(tampered)
    assert exc.value.code is FailureCode.BAD_SIGNATURE


def test_refresh_with_malformed_token(service):
    with pytest.raises(Exception) as exc:
        service.refresh("not-a-token")
    assert exc.value.code is FailureCode.MALFORMED_TOKEN


def test_rotated_token_can_be_used_for_access(service):
    pair = _login(service)
    new_pair = service.refresh(pair.refresh_token)
    # 新 access 令牌通过认证，旧 access 令牌在自然过期前仍受吊销规则约束（见吊销测试）
    sub, sid = service.authenticate(new_pair.access_token)
    assert sub == "alice" and sid == pair.sid


def test_login_rejects_bad_credentials(service):
    with pytest.raises(Exception) as exc:
        service.login("alice", "wrong")
    assert exc.value.code is FailureCode.INVALID_CREDENTIALS


def test_token_type_must_match_endpoint(service):
    pair = _login(service)
    # 拿 refresh 令牌去访问资源 => 类型不符（而非过期/签名错误）
    with pytest.raises(Exception) as exc:
        service.authenticate(pair.refresh_token)
    assert exc.value.code is FailureCode.MALFORMED_TOKEN
    assert "access" in exc.value.reason
    # 拿 access 令牌去刷新 => 类型不符
    with pytest.raises(Exception) as exc2:
        service.refresh(pair.access_token)
    assert exc2.value.code is FailureCode.MALFORMED_TOKEN
    assert "refresh" in exc2.value.reason
