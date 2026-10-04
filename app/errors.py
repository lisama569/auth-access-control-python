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
    """刷新令牌已被轮换，再次使用即重放（兼容保留的结论码）。"""

    code = "refresh_replayed"
    status_code = 401


class RefreshChainRevoked(AuthError):
    """已轮换掉的旧刷新令牌在容忍窗口之外（或更早的旧令牌）再次出现，

    判定为凭证泄露：其所属令牌串（自那次登录起签发的全部访问/刷新令牌）
    整体作废。该结论与普通会话注销(token_revoked)、过期、篡改严格可区分。
    """

    code = "refresh_chain_revoked"
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


class SessionNotFound(AuthError):
    """治理目标会话不存在（从未有过），与"存在但已被清掉"严格区分。"""

    code = "session_not_found"
    status_code = 404


class SubjectNotFound(AuthError):
    """治理目标主体不存在（从未注册），与"主体存在但没有会话"严格区分。"""

    code = "subject_not_found"
    status_code = 404
