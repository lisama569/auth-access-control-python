"""应用装配：构建 Store/Codec/Service，挂载路由，注册统一异常映射。"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .clock import OffsetClock, SystemClock
from .errors import AuthFailure, FailureCode
from .service import AuthService
from .storage import Resource, Store, User
from .tokens import TokenCodec

# 失败码 -> HTTP 状态码。各入口共用，保证结论一致。
HTTP_STATUS: dict[FailureCode, int] = {
    FailureCode.MISSING_TOKEN: 401,
    FailureCode.MALFORMED_TOKEN: 401,
    FailureCode.BAD_SIGNATURE: 401,
    FailureCode.TOKEN_EXPIRED: 401,
    FailureCode.TOKEN_FUTURE: 401,
    FailureCode.TOKEN_REVOKED: 401,
    FailureCode.SESSION_REVOKED: 401,
    FailureCode.GLOBAL_REVOKED: 401,
    FailureCode.REFRESH_REPLAYED: 401,
    FailureCode.REFRESH_CONFLICT: 409,
    FailureCode.INVALID_CREDENTIALS: 401,
    FailureCode.FORBIDDEN: 403,
    FailureCode.NOT_FOUND: 404,
}


def seed(store: Store) -> None:
    """写入演示用户/角色/资源。

    alice=admin(read+admin)；bob=viewer(read)；carol=auditor(audit)。
    """
    store.users["alice"] = User("alice", "pw-alice", ["admin"])
    store.users["bob"] = User("bob", "pw-bob", ["viewer"])
    store.users["carol"] = User("carol", "pw-carol", ["auditor"])
    store.role_permissions["admin"] = {"resource:read"}
    store.role_permissions["viewer"] = {"resource:read"}
    store.role_permissions["auditor"] = {"audit:read"}
    store.resources["doc-1"] = Resource("doc-1", owner="alice", required_permission="resource:read")
    store.resources["doc-2"] = Resource("doc-2", owner="alice", required_permission="audit:read")


def create_app(
    secret: bytes = b"local-dev-secret",
    clock: OffsetClock | SystemClock | None = None,
    service: AuthService | None = None,
) -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    app = FastAPI(title="Local Auth & Access Control")
    store = Store()
    seed(store)
    if service is None:
        service = AuthService(store, TokenCodec(secret), clock or SystemClock())
    app.state.auth_service = service
    app.state.store = store

    from .api import build_router
    app.include_router(build_router())

    @app.exception_handler(AuthFailure)
    async def _auth_failure_handler(_request: Request, exc: AuthFailure) -> JSONResponse:
        return JSONResponse(
            status_code=HTTP_STATUS[exc.code],
            content={"error": exc.code.value, "reason": exc.reason},
        )

    return app
