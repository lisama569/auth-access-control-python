"""可区分的认证/授权错误类型。

每一类失败都映射到稳定的错误码，调用方据此区分：
未认证(401) / 权限不足(403) / 资源不存在(404) / 冲突(409)。
"""
from __future__ import annotations


class AuthError(Exception):
    """所有认证与访问控制错误的基类。"""

    code: str = "auth_error"
    status_code: int = 401

    def __init__(self, message: str, *, reason: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason or self.code

    def to_dict(self) -> dict:
        return {"error": self.code, "message": self.message, "reason": self.reason}


class InvalidCredentials(AuthError):
    code = "invalid_credentials"
    status_code = 401


class TokenExpired(AuthError):
    code = "token_expired"
    status_code = 401


class TokenTampered(AuthError):
    code = "token_tampered"
    status_code = 401


class TokenRevoked(AuthError):
    code = "token_revoked"
    status_code = 401


class TokenReplayed(AuthError):
    """刷新令牌已被轮换，再次使用即重放。"""

    code = "refresh_replayed"
    status_code = 401


class RefreshConflict(AuthError):
    """并发刷新竞争失败：旧刷新令牌已被另一个请求轮换。"""

    code = "refresh_conflict"
    status_code = 409


class Unauthenticated(AuthError):
    code = "unauthenticated"
    status_code = 401


class Forbidden(AuthError):
    code = "forbidden"
    status_code = 403


class ResourceNotFound(AuthError):
    code = "resource_not_found"
    status_code = 404
