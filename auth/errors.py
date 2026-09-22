"""认证与访问控制失败原因的统一分类。

所有失败都通过 :class:`AuthFailure` 抛出，``code`` 用于机读归类，
``reason`` 用于人读解释（判定依据），保证不同入口下结论一致且可区分。
"""
from __future__ import annotations

import enum


class FailureCode(str, enum.Enum):
    """失败原因码。HTTP 状态码映射见 ``auth.api``。"""

    MISSING_TOKEN = "missing_token"                 # 未携带令牌
    MALFORMED_TOKEN = "malformed_token"             # 令牌结构无法解析
    BAD_SIGNATURE = "bad_signature"                 # 签名篡改
    TOKEN_EXPIRED = "token_expired"                 # 已过期
    TOKEN_FUTURE = "token_not_yet_valid"            # 签发时间在未来（时钟偏移超界）
    TOKEN_REVOKED = "token_revoked"                 # 主体级吊销命中
    SESSION_REVOKED = "session_revoked"             # 会话级吊销命中
    GLOBAL_REVOKED = "globally_revoked"             # 全局吊销命中
    REFRESH_REPLAYED = "refresh_replayed"           # 旧刷新令牌被重放
    REFRESH_CONFLICT = "concurrent_refresh_conflict"  # 同令牌并发刷新，未中标
    INVALID_CREDENTIALS = "invalid_credentials"     # 用户名/密码错误
    FORBIDDEN = "permission_denied"                 # 已认证但权限不足
    NOT_FOUND = "resource_not_found"                # 目标资源不存在


class AuthFailure(Exception):
    """带分类码与判定依据的认证/授权失败。"""

    code: FailureCode
    reason: str

    def __init__(self, code: FailureCode, reason: str) -> None:
        super().__init__(f"{code.value}: {reason}")
        self.code = code
        self.reason = reason
