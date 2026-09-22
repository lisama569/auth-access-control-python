"""时钟偏移与过期边界：严格比较 + leeway 容忍，临界结论确定且可解释。"""
from __future__ import annotations

import pytest

from auth.clock import OffsetClock
from auth.errors import AuthFailure, FailureCode
from auth.service import AuthService
from auth.tokens import TokenCodec


def _skewed_service(service, clock, leeway: float) -> AuthService:
    """与主服务共享存储/密钥、但校验时钟可偏移的第二个校验端。"""
    return AuthService(
        service._store, TokenCodec(b"test-secret"), clock,
        access_ttl=900.0, refresh_ttl=86400.0, leeway=leeway, replay_grace=5.0,
    )


def test_expiry_boundary_is_strict_and_deterministic(service, clock):
    pair = service.login("alice", "pw-alice")
    claims = service._codec.decode(pair.access_token, at=clock.now())
    # 恰好 exp 时刻：有效（严格大于才过期）
    assert service._codec.decode(pair.access_token, at=claims.exp).sub == "alice"
    # 越过 exp 任意小量：过期
    with pytest.raises(AuthFailure) as exc:
        service._codec.decode(pair.access_token, at=claims.exp + 0.001)
    assert exc.value.code is FailureCode.TOKEN_EXPIRED
    assert "exp=" in exc.value.reason  # 判定依据包含关键时间量


def test_expired_token_rejected_with_reason(service, clock):
    pair = service.login("bob", "pw-bob")
    clock.set_offset(900.0 + 1.0)  # 越过 access_ttl
    with pytest.raises(AuthFailure) as exc:
        service.authenticate(pair.access_token)
    assert exc.value.code is FailureCode.TOKEN_EXPIRED


def test_validator_clock_behind_within_leeway(service, clock):
    """校验端时钟慢 20s：新令牌的 iat 看似在未来，leeway=30 时仍被接受。"""
    pair = service.login("alice", "pw-alice")
    skewed_clock = OffsetClock(offset_seconds=-20.0)
    skewed = _skewed_service(service, skewed_clock, leeway=30.0)
    assert skewed.authenticate(pair.access_token)[0] == "alice"

    # 无 leeway 时同样的偏移必须给出确定拒绝：TOKEN_FUTURE
    strict = _skewed_service(service, skewed_clock, leeway=0.0)
    with pytest.raises(AuthFailure) as exc:
        strict.authenticate(pair.access_token)
    assert exc.value.code is FailureCode.TOKEN_FUTURE


def test_validator_clock_ahead_expires_early(service, clock):
    """校验端时钟快 20s：令牌提前过期；leeway 可容纳该偏移。"""
    pair = service.login("alice", "pw-alice")
    # 主时钟推进到距过期仅 10s（令牌签发于 offset=0）
    clock.set_offset(890.0)
    # 比签发端快 20s 的校验端：wall + 910，已越过 exp
    ahead_clock = OffsetClock(offset_seconds=910.0)
    strict = _skewed_service(service, ahead_clock, leeway=0.0)
    with pytest.raises(AuthFailure) as exc:
        strict.authenticate(pair.access_token)
    assert exc.value.code is FailureCode.TOKEN_EXPIRED
    # leeway=30 的校验端接受同一令牌：结论确定且由 leeway 配置解释
    tolerant = _skewed_service(service, ahead_clock, leeway=30.0)
    assert tolerant.authenticate(pair.access_token)[0] == "alice"


def test_validator_clock_behind_expired_token(service, clock):
    """校验端时钟慢于签发端：令牌实际已过期，但慢时钟下仍在有效期内——
    结论由该校验端时钟确定，leeway 不反向延长。"""
    pair = service.login("alice", "pw-alice")
    clock.set_offset(901.0)  # 签发端视角已过期
    behind_clock = OffsetClock(offset_seconds=0.0)  # 慢 901s 的校验端
    behind = _skewed_service(service, behind_clock, leeway=0.0)
    # 慢时钟端认为仍有效：结论确定（这就是该时钟下的正确判定）
    assert behind.authenticate(pair.access_token)[0] == "alice"
    # 主服务（时钟已推进）判定过期：两端结论不同但各自确定、可解释
    with pytest.raises(AuthFailure) as exc:
        service.authenticate(pair.access_token)
    assert exc.value.code is FailureCode.TOKEN_EXPIRED


def test_leeway_boundary_exact(service, clock):
    """leeway 边界同样严格：at == exp + leeway 有效，越过即过期。"""
    pair = service.login("alice", "pw-alice")
    claims = service._codec.decode(pair.access_token, at=clock.now())
    codec = service._codec
    assert codec.decode(pair.access_token, at=claims.exp + 30.0, leeway=30.0).sub == "alice"
    with pytest.raises(AuthFailure) as exc:
        codec.decode(pair.access_token, at=claims.exp + 30.001, leeway=30.0)
    assert exc.value.code is FailureCode.TOKEN_EXPIRED
