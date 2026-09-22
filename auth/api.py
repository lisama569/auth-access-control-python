"""HTTP 入口：把 AuthService 的确定性结论映射为可区分的 HTTP 响应。

错误响应体形如 ``{"error": <code>, "reason": <判定依据>}``。
状态码映射：401 未认证（含令牌问题/重放），403 权限不足，404 资源/会话不存在，
409 并发刷新冲突。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from .errors import AuthFailure, FailureCode
from .service import AuthService


class LoginBody(BaseModel):
    username: str
    password: str


class RefreshBody(BaseModel):
    refresh_token: str


class PermissionBody(BaseModel):
    role: str
    permission: str


def get_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def _bearer(request: Request) -> str:
    """从 Authorization 头取 Bearer 令牌；缺失/格式错误归为 MISSING_TOKEN。"""
    header = request.headers.get("Authorization")
    if not header:
        raise AuthFailure(FailureCode.MISSING_TOKEN, "请求未携带 Authorization 头")
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AuthFailure(FailureCode.MISSING_TOKEN, "Authorization 头不是 'Bearer <token>' 形式")
    return parts[1].strip()


def _pair_payload(pair) -> dict:
    return {"access_token": pair.access_token, "refresh_token": pair.refresh_token, "sid": pair.sid}


def build_router() -> APIRouter:
    router = APIRouter()

    @router.post("/auth/login")
    def login(body: LoginBody, svc: AuthService = Depends(get_service)):
        return _pair_payload(svc.login(body.username, body.password))

    @router.post("/auth/refresh")
    def refresh(body: RefreshBody, svc: AuthService = Depends(get_service)):
        return _pair_payload(svc.refresh(body.refresh_token))

    @router.post("/auth/logout")
    def logout(body: dict, svc: AuthService = Depends(get_service)):
        svc.logout(body["sid"])
        return {"status": "revoked", "sid": body["sid"]}

    @router.get("/resources/{resource_id}")
    def read_resource(resource_id: str, request: Request, svc: AuthService = Depends(get_service)):
        token = _bearer(request)
        decision = svc.access_resource(token, resource_id)
        return {
            "resource_id": resource_id,
            "subject": decision.subject,
            "permission": decision.permission,
            "decision": "allow",
            "reason": decision.reason,
            "perm_version": decision.perm_version,
        }

    # ---- 管理入口：权限演进与吊销（本地模拟，未额外加管理员鉴权）----
    @router.post("/admin/roles/permissions")
    def grant(body: PermissionBody, svc: AuthService = Depends(get_service)):
        return {"perm_version": svc.grant_permission(body.role, body.permission)}

    @router.delete("/admin/roles/permissions")
    def revoke_permission(body: PermissionBody, svc: AuthService = Depends(get_service)):
        return {"perm_version": svc.revoke_permission(body.role, body.permission)}

    @router.post("/admin/revocation/subjects/{sub}")
    def revoke_subject(sub: str, svc: AuthService = Depends(get_service)):
        return {"revoked_at": svc.revoke_subject(sub)}

    @router.post("/admin/revocation/global")
    def revoke_global(svc: AuthService = Depends(get_service)):
        return {"revoked_at": svc.revoke_global()}

    return router
