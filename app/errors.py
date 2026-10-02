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


class RefreshReuseDetected(AuthError):
    """已被轮换掉的旧刷新令牌在容忍窗口之外再次被使用。

    判定为凭证泄露：该次登录签发的整串令牌（访问+刷新）立即作废，
    此后再拿这一串里的任何刷新令牌来都归入本错误。
    """

    code = "refresh_reuse_detected"
    status_code = 401


class TokenFamilyRevoked(AuthError):
    """访问令牌所属的令牌串已因刷新令牌重复使用被整串作废。

    与普通会话注销（token_revoked）明确区分，便于排查泄露事件。
    """

    code = "token_family_revoked"
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
