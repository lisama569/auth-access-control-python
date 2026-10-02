'''FastAPI 入口：登录/刷新、受保护资源、管理端权限变更与吊销。

所有 AuthError 由统一异常处理器转换为：
    HTTP 状态码 + {error, message, reason}
错误码表见 app/errors.py，调用方据此可区分各类失败。
'''
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .access_control import Guard
from .auth_service import AuthService
from .clock import Clock
from .errors import AuthError, ResourceNotFound
from .storage import Store
from .tokens import decode

log = logging.getLogger("api")


class LoginBody(BaseModel):
    username: str
    password: str


class RefreshBody(BaseModel):
    refresh_token: str


class RolePermissionBody(BaseModel):
    role: str
    permission: str


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer "):].strip()
    return None


def create_app(store: Store, clock: Clock, auth: AuthService, guard: Guard) -> FastAPI:
    app = FastAPI(title="本地认证与访问控制演示", version="0.1.0")

    @app.exception_handler(AuthError)
    async def _on_auth_error(_: Request, exc: AuthError) -> JSONResponse:
        log.warning("请求被拒 code=%s reason=%s message=%s", exc.code, exc.reason, exc.message)
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # ---------- 认证 ----------
    @app.post("/auth/login")
    def login(body: LoginBody) -> dict[str, Any]:
        pair = auth.issue(body.username, body.password)
        return {
            "access_token": pair.access_token,
            "refresh_token": pair.refresh_token,
            "token_type": "Bearer",
            "access_expires_in": pair.access_expires_in,
            "refresh_expires_in": pair.refresh_expires_in,
        }

    @app.post("/auth/refresh")
    def refresh(body: RefreshBody) -> dict[str, Any]:
        pair = auth.refresh(body.refresh_token)
        access_claims = decode(pair.access_token, auth.config.secret)
        return {
            "access_token": pair.access_token,
            "refresh_token": pair.refresh_token,
            "token_type": "Bearer",
            "sid": access_claims.sid,
            "access_expires_in": pair.access_expires_in,
            "refresh_expires_in": pair.refresh_expires_in,
        }

    # ---------- 受保护资源 ----------
    @app.get("/docs/{doc_id}")
    def read_doc(doc_id: str, request: Request) -> dict[str, Any]:
        decision = guard.check(_bearer(request), "doc:read", doc_id)
        resource = decision.resource
        return {
            "id": resource.rid,
            "owner": resource.owner,
            "content": resource.content,
            "viewer": decision.subject,
        }

    @app.put("/docs/{doc_id}")
    def write_doc(doc_id: str, request: Request) -> dict[str, Any]:
        decision = guard.check(_bearer(request), "doc:write", doc_id)
        return {"id": doc_id, "updated_by": decision.subject, "status": "written"}

    @app.delete("/docs/{doc_id}")
    def delete_doc(doc_id: str, request: Request) -> dict[str, Any]:
        decision = guard.check(_bearer(request), "doc:delete", doc_id)
        return {"id": doc_id, "deleted_by": decision.subject, "status": "deleted"}

    # ---------- 管理端 ----------
    @app.post("/admin/roles/permissions")
    def grant_permission(body: RolePermissionBody, request: Request) -> dict[str, Any]:
        guard.check(_bearer(request), "admin:revoke", None)
        added = store.grant(body.role, body.permission)
        return {"role": body.role, "permission": body.permission, "added": added}

    @app.delete("/admin/roles/permissions")
    def remove_permission(body: RolePermissionBody, request: Request) -> dict[str, Any]:
        guard.check(_bearer(request), "admin:revoke", None)
        removed = store.revoke_permission(body.role, body.permission)
        return {"role": body.role, "permission": body.permission, "removed": removed}

    @app.post("/admin/revoke/subject/{username}")
    def revoke_subject(username: str, request: Request) -> dict[str, Any]:
        guard.check(_bearer(request), "admin:revoke", None)
        auth.revoke_subject(username)
        return {"scope": "subject", "subject": username, "revoked": True}

    @app.post("/admin/revoke/all")
    def revoke_all(request: Request) -> dict[str, Any]:
        guard.check(_bearer(request), "admin:revoke", None)
        auth.revoke_all()
        return {"scope": "global", "revoked": True}

    @app.post("/admin/sessions/{sid}/revoke")
    def revoke_session(sid: str, request: Request) -> dict[str, Any]:
        guard.check(_bearer(request), "admin:revoke", None)
        status = auth.revoke_session(sid)
        if status == "not_found":
            raise ResourceNotFound(f"会话 {sid} 不存在")
        body: dict[str, Any] = {"scope": "session", "sid": sid, "status": status}
        session = store.get_session(sid)
        if session is not None:
            body["revoked_reason"] = session.revoked_reason
        return body

    # ---------- 会话治理（按主体） ----------
    @app.get("/admin/subjects/{username}/sessions")
    def list_subject_sessions(username: str, request: Request) -> dict[str, Any]:
        # 顺序固定：认证(401) -> 权限(403) -> 目标存在性(404)
        guard.check(_bearer(request), "admin:sessions", None)
        if store.get_user(username) is None:
            raise ResourceNotFound(f"主体 {username} 不存在")
        sessions = auth.list_sessions(username)
        return {"subject": username, "count": len(sessions), "sessions": sessions}

    @app.post("/admin/subjects/{username}/sessions/revoke")
    def revoke_subject_sessions(username: str, request: Request) -> dict[str, Any]:
        guard.check(_bearer(request), "admin:sessions", None)
        if store.get_user(username) is None:
            raise ResourceNotFound(f"主体 {username} 不存在")
        revoked = auth.revoke_subject_sessions(username)
        return {
            "subject": username,
            "revoked_count": len(revoked),
            "revoked_sids": revoked,
        }

    return app
