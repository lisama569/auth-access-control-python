"""本地令牌签发与验签（HMAC-SHA256，自包含、无第三方依赖）。

令牌形态: ``base64url(payload_json).base64url(hmac_sha256)``；
payload 为 JSON :class:`Claims`。

失败分类（可区分、原因互不重叠）：
- 结构/编码/字段错误 -> ``MALFORMED_TOKEN``
- 签名不符（篡改）   -> ``BAD_SIGNATURE``
- ``at > exp+leeway``（严格大于）-> ``TOKEN_EXPIRED``
- ``iat > at+leeway``（严格大于）-> ``TOKEN_NOT_YET_VALID``
"""
from __future__ import annotations

import base64
import dataclasses
import hmac
import json
from hashlib import sha256
from typing import Any

from .errors import AuthFailure, FailureCode


@dataclasses.dataclass(frozen=True)
class Claims:
    sub: str            # 主体（用户名）
    sid: str            # 会话 id
    typ: str            # "access" | "refresh"
    jti: str            # 令牌唯一 id
    iat: float          # 签发时间
    exp: float          # 过期时间
    pv: int             # 签发时权限模型版本（仅用于审计/解释，判定以实时权限为准）

    @classmethod
    def from_dict(cls, data: Any) -> "Claims":
        required = ("sub", "sid", "typ", "jti", "iat", "exp", "pv")
        if not isinstance(data, dict) or any(k not in data for k in required):
            raise AuthFailure(FailureCode.MALFORMED_TOKEN, "payload 缺少必要字段或不是对象")
        try:
            return cls(
                sub=str(data["sub"]),
                sid=str(data["sid"]),
                typ=str(data["typ"]),
                jti=str(data["jti"]),
                iat=float(data["iat"]),
                exp=float(data["exp"]),
                pv=int(data["pv"]),
            )
        except (TypeError, ValueError) as exc:
            raise AuthFailure(FailureCode.MALFORMED_TOKEN, f"payload 字段类型错误: {exc}") from None


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:
        raise AuthFailure(FailureCode.MALFORMED_TOKEN, f"base64 解码失败: {exc}") from None


class TokenCodec:
    def __init__(self, secret: bytes) -> None:
        self._secret = bytes(secret)

    def _sign(self, payload_b64: str) -> str:
        mac = hmac.new(self._secret, payload_b64.encode("ascii"), sha256).digest()
        return _b64e(mac)

    def encode(self, claims: Claims) -> str:
        """签发令牌。"""
        payload_b64 = _b64e(json.dumps(dataclasses.asdict(claims), separators=(",", ":")).encode("utf-8"))
        return f"{payload_b64}.{self._sign(payload_b64)}"

    def decode(self, token: str, at: float, leeway: float = 0.0) -> Claims:
        """验签并校验时间边界（严格比较，临界确定）。"""
        parts = token.split(".")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise AuthFailure(FailureCode.MALFORMED_TOKEN, "令牌不是 payload.signature 两段结构")
        payload_b64, sig = parts
        expected = self._sign(payload_b64)
        if not hmac.compare_digest(sig, expected):
            raise AuthFailure(FailureCode.BAD_SIGNATURE, "签名不匹配，令牌可能被篡改")
        try:
            data = json.loads(_b64d(payload_b64))
        except AuthFailure:
            raise
        except Exception as exc:
            raise AuthFailure(FailureCode.MALFORMED_TOKEN, f"payload 不是合法 JSON: {exc}") from None
        claims = Claims.from_dict(data)
        # 确定性边界：恰好等于 exp+leeway 仍有效；越过一微秒即过期。
        if at > claims.exp + leeway:
            raise AuthFailure(
                FailureCode.TOKEN_EXPIRED,
                f"令牌已于 exp={claims.exp} 过期（校验时刻 at={at}，leeway={leeway}）",
            )
        if claims.iat > at + leeway:
            raise AuthFailure(
                FailureCode.TOKEN_FUTURE,
                f"令牌尚未生效 iat={claims.iat}（校验时刻 at={at}，leeway={leeway}）",
            )
        return claims
