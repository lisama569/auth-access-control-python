"""认证服务：登录签发、刷新轮换（重放容忍/泄露整串作废/并发判定）、
令牌校验、吊销与按主体的会话治理。

刷新轮换的状态机（每个会话只认一个"当前刷新令牌"）：

    登录 -> 会话(current=R0)
    用 R0 刷新成功 -> 会话(current=R1)，R0 记入已使用表与轮换记录
    再次用 R0：
      - 距上次轮换 <= 容忍窗口，且记录仍属于本会话的最近一次轮换
        => 视为同一次刷新的网络重试，原样回放第一次返回的令牌对，
           会话不二次推进、不判泄露；
      - 超出容忍窗口（或拿更早的旧令牌、或记录已不属于本会话）
        => 判定凭证泄露：该令牌串整串作废（该会话历史上发出的所有
           访问/刷新令牌此后一律 401 refresh_chain_revoked）；
      - 若该请求在 R0 被标记前已读到"未使用"，且 CAS 失败
        => 真正同一时刻的并发竞争 409 refresh_conflict。

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
    RefreshChainRevoked,
    RefreshConflict,
    SessionNotFound,
    SubjectNotFound,
    TokenExpired,
    TokenRevoked,
    TokenTampered,
    Unauthenticated,
)
from .storage import RotationRecord, Session, SessionView, Store
from .tokens import ACCESS, REFRESH, Claims, TokenPair, decode, encode, is_expired

log = logging.getLogger("auth")

ACCESS_TTL = 900  # 访问令牌有效期 15 分钟
REFRESH_TTL = 60 * 60 * 24 * 7  # 刷新令牌有效期 7 天
LEEWAY = 0.0  # 过期容差（秒）；临界测试中显式配置
RETRY_WINDOW = 5.0  # 刷新重复提交容忍窗口（秒，含等号边界）


@dataclass
class AuthConfig:
    secret: str = "local-demo-secret"
    access_ttl: int = ACCESS_TTL
    refresh_ttl: int = REFRESH_TTL
    leeway: float = LEEWAY
    retry_window: float = RETRY_WINDOW


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
        # 已因泄露整串作废：结论独立于普通注销
        if session.compromised:
            log.info(
                "刷新被拒 user=%s sid=%s jti=%s reason=refresh_chain_revoked "
                "detail=chain_already_revoked at=%.3f",
                claims.sub, claims.sid, claims.jti[:8], session.compromised_at,
            )
            raise RefreshChainRevoked(
                "该令牌串因旧刷新令牌被重复使用已整体作废"
            )
        if session.revoked:
            log.info("刷新被拒 user=%s sid=%s reason=token_revoked detail=session_revoked",
                     claims.sub, session.sid)
            raise TokenRevoked("会话已被吊销")

        self._check_revocation(claims)

        # 先读一次"是否已被使用"快照：区分真正的并发竞争与事后重放
        seen_used = self.store.was_refresh_used(claims.jti)
        if seen_used:
            return self._handle_reused_refresh(claims, session, now)

        # 新轮换：先签好令牌对，再走 CAS，使轮换记录在存储临界区内一次固化
        new_jti = _new_jti()
        pair = self._issue_pair(claims.sid, claims.sub, new_jti, now)
        record = RotationRecord(
            sid=claims.sid,
            old_jti=claims.jti,
            new_jti=new_jti,
            rotated_at=now,
            seq=0,  # 由存储层在 CAS 临界区内盖戳
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            access_expires_in=pair.access_expires_in,
            refresh_expires_in=pair.refresh_expires_in,
        )
        swapped = self.store.rotate_refresh(claims.sid, claims.jti, record, now)
        if not swapped:
            log.info(
                "刷新竞争失败 user=%s sid=%s jti=%s reason=refresh_conflict current=%s",
                claims.sub, claims.sid, claims.jti[:8],
                session.current_refresh_jti[:8],
            )
            raise RefreshConflict("并发刷新冲突：该刷新令牌已被另一个请求轮换")

        log.info(
            "刷新成功 user=%s sid=%s old_jti=%s new_jti=%s seq=%d chain_len=%d "
            "rotated_at=%.3f retry_window=%.3f",
            claims.sub, claims.sid, claims.jti[:8], new_jti[:8],
            session.rotation_seq, len(session.refresh_chain), now,
            self.config.retry_window,
        )
        return pair

    def _handle_reused_refresh(
        self, claims: Claims, session: Session, now: float
    ) -> TokenPair:
        """旧刷新令牌再次出现的归类：窗口内重试回放，否则整串作废。"""
        record = self.store.lookup_rotation(claims.jti)
        if record is not None and record.sid == session.sid:
            age = now - record.rotated_at
            within_window = age <= self.config.retry_window  # 等号边界确定地算窗口内
            is_latest = record.seq == session.rotation_seq
            if within_window and is_latest:
                log.info(
                    "刷新重试命中 user=%s sid=%s jti=%s reason=refresh_retry_replayed "
                    "seq=%d age=%.3f window=%.3f => 原样回放令牌对，会话不推进",
                    claims.sub, session.sid, claims.jti[:8],
                    record.seq, age, self.config.retry_window,
                )
                return TokenPair(
                    access_token=record.access_token,
                    refresh_token=record.refresh_token,
                    access_expires_in=record.access_expires_in,
                    refresh_expires_in=record.refresh_expires_in,
                )
            why = "outside_window" if not within_window else "older_rotation"
            log.info(
                "检测到旧刷新令牌泄露 user=%s sid=%s jti=%s "
                "reason=refresh_chain_revoked detail=%s age=%.3f window=%.3f "
                "record_seq=%d current_seq=%d => 整串作废",
                claims.sub, session.sid, claims.jti[:8], why, age,
                self.config.retry_window, record.seq, session.rotation_seq,
            )
        else:
            log.info(
                "检测到旧刷新令牌泄露 user=%s sid=%s jti=%s "
                "reason=refresh_chain_revoked detail=rotation_record_missing => 整串作废",
                claims.sub, session.sid, claims.jti[:8],
            )

        self.store.compromise_session(session.sid, now)
        raise RefreshChainRevoked(
            "已轮换的旧刷新令牌在容忍窗口外再次使用，判定凭证泄露，"
            "该会话整串令牌已作废"
        )

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
        if session.compromised:
            log.info(
                "访问被拒 user=%s sid=%s jti=%s reason=refresh_chain_revoked "
                "detail=chain_revoked_at=%.3f",
                claims.sub, claims.sid, claims.jti[:8], session.compromised_at,
            )
            raise RefreshChainRevoked(
                "该令牌串因旧刷新令牌被重复使用已整体作废"
            )
        if session.revoked:
            log.info("访问被拒 user=%s sid=%s reason=token_revoked detail=session_revoked",
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

    # ---- 会话治理 ----
    def _require_subject(self, subject: str, *, operation: str) -> None:
        """治理目标主体存在性判定（在认证、鉴权通过之后才走到这里）。

        主体从未注册 => SubjectNotFound(404)，与"主体存在但没有会话"
        严格区分；已注册（含无会话）主体照常放行。
        """
        if self.store.get_user(subject) is None:
            log.info(
                "会话治理被拒 operation=%s target=%s reason=subject_not_found "
                "detail=subject_never_registered",
                operation, subject,
            )
            raise SubjectNotFound(f"目标主体 {subject} 不存在")
        log.info(
            "会话治理目标存在性通过 operation=%s target=%s reason=subject_exists",
            operation, subject,
        )

    def list_sessions(self, subject: str) -> list[SessionView]:
        """按主体列出会话（标识/创建时间/状态，不含令牌内容）。

        主体不存在时抛出 SubjectNotFound；主体存在但没有会话返回空列表。
        """
        self._require_subject(subject, operation="list_sessions")
        views = self.store.list_sessions_of(subject)
        log.info(
            "列出会话 operator_target=%s count=%d statuses=%s",
            subject, len(views),
            ",".join(f"{v.sid}:{v.status}" for v in views) or "(none)",
        )
        return views

    def revoke_session_detailed(self, sid: str) -> str:
        """注销单个会话，返回可区分的结论：

        - ``revoked``        本来存在且存活，本次刚刚注销；
        - ``already_revoked`` 目标存在，但此前已是注销/泄露终态；
        - ``not_found``      目标会话从不存在。
        """
        now = self.clock.now()
        session = self.store.get_session(sid)
        if session is None:
            log.info("注销会话 sid=%s result=not_found", sid)
            raise SessionNotFound(f"会话 {sid} 不存在")
        if session.compromised:
            log.info(
                "注销会话 sid=%s result=already_revoked detail=compromised at=%.3f",
                sid, session.compromised_at,
            )
            return "already_revoked"
        if session.revoked:
            log.info(
                "注销会话 sid=%s result=already_revoked detail=revoked at=%.3f",
                sid, session.revoked_at,
            )
            return "already_revoked"
        self.store.revoke_session(sid, now)
        log.info("注销会话 sid=%s result=revoked at=%.3f", sid, now)
        return "revoked"

    def revoke_subject_sessions(self, subject: str) -> int:
        """一次性注销主体名下仍存活的会话；返回实际注销数量。

        主体不存在时抛出 SubjectNotFound；主体存在但没有活会话返回 0。
        """
        self._require_subject(subject, operation="revoke_subject_sessions")
        count = self.store.revoke_all_sessions_of(subject, self.clock.now())
        log.info("批量注销会话 subject=%s revoked_count=%d", subject, count)
        return count

    def revoke_subject(self, username: str) -> None:
        self.store.revoke_subject(username, self.clock.now())
        log.info("主体级吊销 user=%s", username)

    def revoke_all(self) -> None:
        self.store.revoke_all(self.clock.now())
        log.info("全局吊销 at=%.3f", self.clock.now())
