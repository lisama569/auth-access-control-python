"""本地令牌：数据模型、HMAC 签名编解码、生命周期判定。

不引入第三方 JWT 库，使用标准库 hmac/hashlib 自行实现，
以便对签名篡改、过期临界、签发时间与吊销时间比较给出确定结论。

令牌线格式（与 JWT 相同的三段式，但字段自定义）：
    base64url(header).base64url(payload).base64url(hmac_sha256(header.payload))
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

from .errors import TokenTampered

ACCESS = "access"
REFRESH = "refresh"

_ALG = "HS256"
_TYP = "LAT1"  # local-auth-token v1


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


@dataclass(frozen=True)
class Claims:
    jti: str
    sub: str
    sid: str
    kind: str
    iat: float
    exp: float
    ver: int

    def to_payload(self) -> dict:
        return {
            "jti": self.jti,
            "sub": self.sub,
            "sid": self.sid,
            "kind": self.kind,
            "iat": self.iat,
            "exp": self.exp,
            "ver": self.ver,
        }

    @classmethod
    def from_payload(cls, payload: dict) -> "Claims":
        try:
            return cls(
                jti=str(payload["jti"]),
                sub=str(payload["sub"]),
                sid=str(payload["sid"]),
                kind=str(payload["kind"]),
                iat=float(payload["iat"]),
                exp=float(payload["exp"]),
                ver=int(payload["ver"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TokenTampered(f"令牌字段缺失或格式错误: {exc}") from exc


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_in: int
    refresh_expires_in: int


def sign(signing_input: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return _b64encode(digest)


def encode(claims: Claims, secret: str) -> str:
    header = {"alg": _ALG, "typ": _TYP}
    header_b = _b64encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    payload_b = _b64encode(
        json.dumps(claims.to_payload(), separators=(",", ":"), sort_keys=True).encode()
    )
    signing_input = f"{header_b}.{payload_b}".encode()
    sig_b = sign(signing_input, secret)
    return f"{header_b}.{payload_b}.{sig_b}"


def decode(token: str, secret: str) -> Claims:
    """解码并校验签名与结构；任何异常都归类为 TokenTampered。"""
    try:
        header_b, payload_b, sig_b = token.split(".")
    except (ValueError, AttributeError) as exc:
        raise TokenTampered("令牌结构不是三段式") from exc

    signing_input = f"{header_b}.{payload_b}".encode()
    expected = sign(signing_input, secret)
    # 常量时间比较，防止时序侧信道
    if not hmac.compare_digest(expected, sig_b):
        raise TokenTampered("签名校验失败：令牌可能被篡改或使用了其他密钥")

    try:
        header = json.loads(_b64decode(header_b))
        payload = json.loads(_b64decode(payload_b))
    except (ValueError, UnicodeDecodeError) as exc:
        raise TokenTampered("令牌内容无法解析") from exc

    if header.get("alg") != _ALG or header.get("typ") != _TYP:
        raise TokenTampered("令牌头声明的算法或类型不受支持")

    return Claims.from_payload(payload)


def is_expired(claims: Claims, now: float, leeway: float) -> bool:
    """过期判定：now - leeway >= exp 即过期（边界上确定地算过期）。"""
    return now - leeway >= claims.exp
