"""测试夹具：构造确定性时钟与装配好的服务。"""
from __future__ import annotations

import logging

import pytest

from auth.app import seed
from auth.clock import OffsetClock
from auth.service import AuthService
from auth.storage import Store
from auth.tokens import TokenCodec


@pytest.fixture
def store() -> Store:
    s = Store()
    seed(s)
    return s


@pytest.fixture
def clock() -> OffsetClock:
    # 以固定基准时钟运行（time.time 本身单调推进，但偏移可控、可复现）
    return OffsetClock(offset_seconds=0.0)


@pytest.fixture
def service(store, clock) -> AuthService:
    return AuthService(
        store, TokenCodec(b"test-secret"), clock,
        access_ttl=900.0, refresh_ttl=86400.0, leeway=0.0, replay_grace=5.0,
    )


@pytest.fixture(autouse=True)
def _show_auth_logs(caplog):
    """让 auth.service 的判定日志在测试记录中可见（失败时可查看判定依据）。"""
    caplog.set_level(logging.INFO, logger="auth.service")
    yield
