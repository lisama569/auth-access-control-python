"""认证服务：登录签发、刷新轮换（含重放/并发判定）、令牌校验、吊销。

刷新轮换的状态机（每个会话只认一个"当前刷新令牌"）：

    登录 -> 会话(current=R0)
    用 R0 刷新成功 -> 会话(current=R1)，R0 记入已使用表
    再次用 R0：
      - 若该请求在 R0 被标记前已读到"未使用"，且 CAS 失败 => 并发冲突 409
      - 否则 => 重放 401(refresh_replayed)

吊销采用时间戳语义：iat <= 吊销时间 的令牌一律失效；
主体级与全局吊销取较晚者。吊销只影响吊销点之前签发的令牌，
吊销之后重新登录签发的新令牌不受影响（类似"全部退出"后重新登录）。
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from .clock import Clock
from .errors import (
    InvalidCredentials,
    RefreshConflict,
    TokenExpired,
    TokenReplayed,
    TokenRevoked,
    TokenTampered,
    Unauthenticated,
)
from .storage import Store
from .tokens import ACCESS, REFRESH, Claims, TokenPair, decode, encode, is_expired

log = logging.getLogger("auth")

ACCESS_TTL = 900  # 访问令牌有效期 15 分钟
REFRESH_TTL = 60 * 60 * 24 * 7  # 刷新令牌有效期 7 天
LEEWAY = 0.0  # 过期容差（秒）；临界测试中显式配置


@dataclass
class AuthConfig:
    secret: str = "local-demo-secret"
    access_ttl: int = ACCESS_TTL
    refresh_ttl: int = REFRESH_TTL
    leeway: float = LEEWAY


def _new_jti() -> str:
    return uuid.uuid4().hex


class AuthService:
    def __init__(self, store: Store, clock: Clock, config: AuthConfig | None = None) -> None:
        self.store = store
        self.clock = clock
        self.config = config or AuthConfig()

    # ---- 签发 ----
    def issue(self, username: str, password: str) -> TokenPair:
        user = self.store.get_user(username)
        if user is None or not user.enabled or user.password != password:
            log.info("登录被拒 user=%s reason=invalid_credentials", username)
            raise InvalidCredentials("用户名或密码错误")
        now = self.clock.now()
        refresh_jti = _new_jti()
        session = self.store.create_session(username, refresh_jti, now)
        pair = self._issue_pair(session.sid, username, refresh_jti, now)
        log.info(
            "签发令牌 user=%s sid=%s access_jti=%s refresh_jti=%s iat=%.3f",
            username, session.sid,
            pair.access_token.split(".")[1][:12], refresh_jti[:8], now,
        )
        return pair

    def _issue_pair(
        self, sid: str, subject: str, refresh_jti: str | None = None, now: float | None = None
    ) -> TokenPair:
        now = self.clock.now() if now is None else now
        refresh_jti = _new_jti() if refresh_jti is None else refresh_jti
        access = Claims(
            jti=_new_jti(), sub=subject, sid=sid, kind=ACCESS,
            iat=now, exp=now + self.config.access_ttl, ver=1,
        )
        refresh = Claims(
            jti=refresh_jti, sub=subject, sid=sid, kind=REFRESH,
            iat=now, exp=now + self.config.refresh_ttl, ver=1,
        )
        return TokenPair(
            access_token=encode(access, self.config.secret),
            refresh_token=encode(refresh, self.config.secret),
            access_expires_in=self.config.access_ttl,
            refresh_expires_in=self.config.refresh_ttl,
        )

    # ---- 刷新 ----
    def refresh(self, refresh_token: str) -> TokenPair:
        claims = self._decode_kind(refresh_token, REFRESH)
        now = self.clock.now()
        if is_expired(claims, now, self.config.leeway):
            log.info(
                "刷新被拒 user=%s jti=%s reason=token_expired exp=%.3f now=%.3f",
                claims.sub, claims.jti[:8], claims.exp, now,
            )
            raise TokenExpired("刷新令牌已过期")

        session = self.store.get_session(claims.sid)
        if session is None:
            log.info("刷新被拒 jti=%s reason=unknown_session sid=%s",
                     claims.jti[:8], claims.sid)
            raise TokenTampered("刷新令牌对应的会话不存在")
        if session.revoked:
            log.info("刷新被拒 user=%s sid=%s reason=session_revoked",
                     claims.sub, session.sid)
            raise TokenRevoked("会话已被吊销")

        self._check_revocation(claims)

        # 先读一次"是否已被使用"快照：用于区分恶意重放与并发竞争
        seen_used = self.store.was_refresh_used(claims.jti)
        if seen_used:
            log.info(
                "刷新被拒 user=%s sid=%s jti=%s reason=refresh_replayed chain_len=%d",
                claims.sub, claims.sid, claims.jti[:8], len(session.refresh_chain),
            )
            raise TokenReplayed("该刷新令牌已被轮换，禁止重放")

        new_jti = _new_jti()
        swapped = self.store.rotate_refresh(claims.sid, claims.jti, new_jti, now)
        if not swapped:
            log.info(
                "刷新竞争失败 user=%s sid=%s jti=%s reason=refresh_conflict current=%s",
                claims.sub, claims.sid, claims.jti[:8],
                session.current_refresh_jti[:8],
            )
            raise RefreshConflict("并发刷新冲突：该刷新令牌已被另一个请求轮换")

        pair = self._issue_pair(claims.sid, claims.sub, new_jti, now)
        log.info(
            "刷新成功 user=%s sid=%s old_jti=%s new_jti=%s chain_len=%d",
            claims.sub, claims.sid, claims.jti[:8], new_jti[:8],
            len(session.refresh_chain),
        )
        return pair

    # ---- 校验 ----
    def authenticate(self, token: str | None) -> Claims:
        """校验访问令牌并返回 Claims；各类失败抛出可区分的 AuthError。"""
        if not token:
            log.info("访问被拒 reason=unauthenticated detail=missing_token")
            raise Unauthenticated("缺少访问令牌")
        claims = self._decode_kind(token, ACCESS)
        now = self.clock.now()
        if is_expired(claims, now, self.config.leeway):
            log.info(
                "访问被拒 user=%s jti=%s reason=token_expired exp=%.3f now=%.3f",
                claims.sub, claims.jti[:8], claims.exp, now,
            )
            raise TokenExpired("访问令牌已过期")

        session = self.store.get_session(claims.sid)
        if session is None:
            log.info("访问被拒 jti=%s reason=unknown_session sid=%s",
                     claims.jti[:8], claims.sid)
            raise TokenRevoked("会话不存在或已终结")
        if session.revoked:
            log.info("访问被拒 user=%s sid=%s reason=session_revoked",
                     claims.sub, claims.sid)
            raise TokenRevoked("会话已被吊销")

        self._check_revocation(claims)

        log.info("访问令牌校验通过 user=%s sid=%s jti=%s",
                 claims.sub, claims.sid, claims.jti[:8])
        return claims

    def _decode_kind(self, token: str, expected_kind: str) -> Claims:
        claims = decode(token, self.config.secret)
        if claims.kind != expected_kind:
            log.info(
                "令牌类型错误 jti=%s expected=%s actual=%s reason=token_tampered",
                claims.jti[:8], expected_kind, claims.kind,
            )
            raise TokenTampered(
                f"令牌类型不匹配：期望 {expected_kind}，实际 {claims.kind}"
            )
        return claims

    def _check_revocation(self, claims: Claims) -> None:
        rev = self.store.revocation_time(claims.sub)
        if rev is None:
            return
        if claims.iat <= rev:
            scope = "global" if self.store.global_revoked_at == rev else "subject"
            log.info(
                "访问/刷新被拒 user=%s jti=%s reason=token_revoked scope=%s iat=%.3f revoked_at=%.3f",
                claims.sub, claims.jti[:8], scope, claims.iat, rev,
            )
            raise TokenRevoked(f"令牌在{scope}级吊销点之前签发，已被吊销")

    # ---- 吊销 ----
    def revoke_session(self, sid: str) -> bool:
        ok = self.store.revoke_session(sid, self.clock.now())
        log.info("吊销会话 sid=%s ok=%s", sid, ok)
        return ok

    def revoke_subject(self, username: str) -> None:
        self.store.revoke_subject(username, self.clock.now())
        log.info("主体级吊销 user=%s", username)

    def revoke_all(self) -> None:
        self.store.revoke_all(self.clock.now())
        log.info("全局吊销 at=%.3f", self.clock.now())
