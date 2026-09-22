"""认证、令牌生命周期与访问控制的核心服务。

判定规则（亦见 README）：
- 刷新轮换：每次刷新作废旧刷新令牌并签发新对；旧令牌重放 => REFRESH_REPLAYED
  并吊销整个会话；同一未消费令牌的并发刷新在宽限窗口内 => REFRESH_CONFLICT，
  不改变任何会话/令牌状态。整个刷新在同一把锁内完成，链路“恰好一次成功”。
- 吊销按签发时间判定：``iat < revoked_at`` 拒绝，相等放行（边界确定）；
  检查顺序固定 全局 -> 主体 -> 会话，三类原因互不掩盖。
- 权限实时判定：每次访问从当前权限模型计算，令牌内 pv 仅作签发时快照用于解释；
  权限新增/收窄立即生效，旧令牌结果随之确定变化。
- 资源访问结论顺序：未认证(401) -> 资源不存在(404) -> 权限不足(403) -> 允许(200)，
  即先确认资源存在再判定权限，避免以 403 掩盖资源是否存在。
"""
from __future__ import annotations

import dataclasses
import logging
import uuid

from .clock import Clock
from .errors import AuthFailure, FailureCode
from .storage import Store
from .tokens import Claims, TokenCodec

logger = logging.getLogger("auth.service")


@dataclasses.dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    sid: str


@dataclasses.dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    subject: str
    resource_id: str
    permission: str
    reason: str          # 判定依据（人读，含关键状态）
    perm_version: int    # 判定时的权限模型版本


class AuthService:
    def __init__(
        self,
        store: Store,
        codec: TokenCodec,
        clock: Clock,
        access_ttl: float = 900.0,
        refresh_ttl: float = 86400.0,
        leeway: float = 0.0,
        replay_grace: float = 5.0,
    ) -> None:
        self._store = store
        self._codec = codec
        self._clock = clock
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._leeway = leeway
        self._replay_grace = replay_grace

    # ---- 令牌签发 ----
    def login(self, username: str, password: str) -> TokenPair:
        """校验凭据并创建会话，签发首对令牌。"""
        user = self._store.users.get(username)
        if user is None or user.password != password:
            logger.info("login denied subject=%s reason=用户名不存在或密码不符", username)
            raise AuthFailure(
                FailureCode.INVALID_CREDENTIALS, f"凭据无效：用户名不存在或密码不符（subject={username}）"
            )
        now = self._clock.now()
        sid = uuid.uuid4().hex
        # 先生成刷新 jti 建会话，再签发令牌，保证会话记录与令牌一致
        seed_jti = uuid.uuid4().hex
        with self._store.lock:
            self._store.create_session(sid, username, now, seed_jti)
            pair = self._issue_pair_with_refresh_jti(username, sid, now, seed_jti)
        logger.info(
            "login ok subject=%s sid=%s at=%.6f access_exp=%.6f refresh_exp=%.6f pv=%d",
            username, sid, now, now + self._access_ttl, now + self._refresh_ttl,
            self._store.perm_version,
        )
        return pair

    def _issue_pair_with_refresh_jti(self, sub: str, sid: str, now: float, refresh_jti: str) -> TokenPair:
        pv = self._store.perm_version
        access = Claims(
            sub=sub, sid=sid, typ="access", jti=uuid.uuid4().hex,
            iat=now, exp=now + self._access_ttl, pv=pv,
        )
        refresh = Claims(
            sub=sub, sid=sid, typ="refresh", jti=refresh_jti,
            iat=now, exp=now + self._refresh_ttl, pv=pv,
        )
        return TokenPair(
            access_token=self._codec.encode(access),
            refresh_token=self._codec.encode(refresh), sid=sid,
        )

    def refresh(self, refresh_token: str) -> TokenPair:
        """刷新轮换：解码校验 -> 吊销检查 -> 原子轮换 -> 签发新对。"""
        now = self._clock.now()
        claims = self._codec.decode(refresh_token, at=now, leeway=self._leeway)
        if claims.typ != "refresh":
            raise AuthFailure(
                FailureCode.MALFORMED_TOKEN, f"令牌类型为 {claims.typ}，不是 refresh 令牌"
            )
        if self._store.get_session(claims.sid) is None:
            raise AuthFailure(
                FailureCode.MALFORMED_TOKEN, f"刷新令牌引用的会话 {claims.sid} 不存在"
            )
        hit = self._store.revocation_reason(claims.sub, claims.sid, claims.iat)
        if hit is not None:
            logger.info("refresh rejected sid=%s jti=%s code=%s", claims.sid, claims.jti, hit[0].value)
            raise AuthFailure(hit[0], hit[1])

        new_refresh_jti = uuid.uuid4().hex
        with self._store.lock:
            # rotate_refresh 内部完成 CONFLICT/REPLAYED 分类与（必要时）会话吊销
            try:
                self._store.rotate_refresh(
                    claims.sid, claims.jti, new_refresh_jti, now, self._replay_grace
                )
            except AuthFailure as exc:
                logger.info(
                    "refresh rejected subject=%s sid=%s jti=%s code=%s reason=%s",
                    claims.sub, claims.sid, claims.jti, exc.code.value, exc.reason,
                )
                raise
            pair = self._issue_pair_with_refresh_jti(claims.sub, claims.sid, now, new_refresh_jti)
        logger.info(
            "refresh ok subject=%s sid=%s old_jti=%s consumed_at=%.6f new_jti=%s pv=%d",
            claims.sub, claims.sid, claims.jti, now, new_refresh_jti,
            self._store.perm_version,
        )
        return pair

    def logout(self, sid: str) -> None:
        """吊销会话。"""
        now = self._clock.now()
        session = self._store.get_session(sid)
        if session is None:
            raise AuthFailure(FailureCode.NOT_FOUND, f"会话 {sid} 不存在")
        self._store.revoke_session(sid, now)
        logger.info("logout ok subject=%s sid=%s revoked_at=%.6f", session.sub, sid, now)

    # ---- 认证与访问控制 ----
    def authenticate(self, access_token: str) -> tuple[str, str]:
        """校验访问令牌，返回 ``(sub, sid)``。所有失败以 FailureCode 精确分类。"""
        now = self._clock.now()
        claims = self._codec.decode(access_token, at=now, leeway=self._leeway)
        if claims.typ != "access":
            raise AuthFailure(
                FailureCode.MALFORMED_TOKEN, f"令牌类型为 {claims.typ}，不是 access 令牌"
            )
        session = self._store.get_session(claims.sid)
        if session is None or session.sub != claims.sub:
            raise AuthFailure(
                FailureCode.MALFORMED_TOKEN,
                f"访问令牌引用的会话 {claims.sid} 不存在或主体不一致",
            )
        hit = self._store.revocation_reason(claims.sub, claims.sid, claims.iat)
        if hit is not None:
            logger.info(
                "authenticate rejected subject=%s sid=%s jti=%s code=%s reason=%s",
                claims.sub, claims.sid, claims.jti, hit[0].value, hit[1],
            )
            raise AuthFailure(hit[0], hit[1])
        logger.info(
            "authenticate ok subject=%s sid=%s jti=%s token_pv=%d model_pv=%d at=%.6f",
            claims.sub, claims.sid, claims.jti, claims.pv,
            self._store.perm_version, now,
        )
        return claims.sub, claims.sid

    def authorize(self, access_token: str, permission: str) -> None:
        """认证 + 实时权限判定。权限不足抛 FORBIDDEN。"""
        sub, sid = self.authenticate(access_token)
        perms = self._store.permissions_of(sub)
        pv = self._store.perm_version
        if permission not in perms:
            reason = (
                f"subject={sub} sid={sid} 需要权限 {permission}，当前权限集 "
                f"{sorted(perms)}（模型版本 pv={pv}）"
            )
            logger.info("authorize denied %s", reason)
            raise AuthFailure(FailureCode.FORBIDDEN, reason)
        logger.info(
            "authorize ok subject=%s sid=%s permission=%s perms=%s pv=%d",
            sub, sid, permission, sorted(perms), pv,
        )

    def access_resource(self, access_token: str, resource_id: str) -> AccessDecision:
        """资源访问：401 未认证 -> 404 不存在 -> 403 权限不足 -> 允许。"""
        sub, sid = self.authenticate(access_token)
        resource = self._store.resources.get(resource_id)
        if resource is None:
            # 已认证者探测不存在的资源得到 404，与 403 严格区分
            reason = f"subject={sub} 请求的资源 {resource_id} 不存在"
            logger.info("access %s", reason)
            raise AuthFailure(FailureCode.NOT_FOUND, reason)
        perms = self._store.permissions_of(sub)
        pv = self._store.perm_version
        if resource.required_permission not in perms:
            reason = (
                f"subject={sub} 访问资源 {resource_id}（owner={resource.owner}）需要 "
                f"{resource.required_permission}，当前权限集 {sorted(perms)}（pv={pv}）"
            )
            logger.info("access denied %s", reason)
            raise AuthFailure(FailureCode.FORBIDDEN, reason)
        reason = (
            f"subject={sub} 持有 {resource.required_permission}，允许访问资源 "
            f"{resource_id}（owner={resource.owner}，pv={pv}）"
        )
        logger.info("access allowed %s", reason)
        return AccessDecision(
            allowed=True, subject=sub, resource_id=resource_id,
            permission=resource.required_permission, reason=reason, perm_version=pv,
        )

    # ---- 管理操作（权限演进与吊销）----
    def grant_permission(self, role: str, permission: str) -> int:
        pv = self._store.grant_permission(role, permission)
        logger.info("permission granted role=%s permission=%s new_pv=%d", role, permission, pv)
        return pv

    def revoke_permission(self, role: str, permission: str) -> int:
        pv = self._store.revoke_permission(role, permission)
        logger.info("permission revoked role=%s permission=%s new_pv=%d", role, permission, pv)
        return pv

    def revoke_subject(self, sub: str) -> float:
        now = self._clock.now()
        self._store.revoke_subject(sub, now)
        logger.info("subject revoked sub=%s revoked_at=%.6f", sub, now)
        return now

    def revoke_global(self) -> float:
        now = self._clock.now()
        self._store.revoke_all(now)
        logger.info("global revoke issued at=%.6f", now)
        return now
