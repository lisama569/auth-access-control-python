"""本地内存存储：用户、角色-权限、资源、会话与吊销记录。

所有状态迁移通过一把锁串行化，保证并发刷新等操作的确定性：
无论多少请求同时到达，刷新链上“恰好一次成功”。
"""
from __future__ import annotations

import dataclasses
import threading
from typing import Optional

from .errors import AuthFailure, FailureCode


@dataclasses.dataclass
class User:
    username: str
    password: str
    roles: list[str]


@dataclasses.dataclass
class Resource:
    id: str
    owner: str
    required_permission: str


@dataclasses.dataclass
class RefreshRecord:
    jti: str
    sid: str
    consumed: bool = False
    consumed_at: Optional[float] = None   # 用于并发冲突与重放的确定性区分


@dataclasses.dataclass
class Session:
    sid: str
    sub: str
    created_at: float
    revoked_at: Optional[float] = None
    refresh: Optional[RefreshRecord] = None   # 当前有效刷新令牌记录
    history: list[RefreshRecord] = dataclasses.field(default_factory=list)  # 已轮换的旧记录


class Store:
    """内存存储与吊销/刷新策略。"""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users: dict[str, User] = {}
        self.role_permissions: dict[str, set[str]] = {}
        self.resources: dict[str, Resource] = {}
        self.sessions: dict[str, Session] = {}
        self.subject_revoked_at: dict[str, float] = {}   # sub -> 吊销生效时刻
        self.global_revoked_at: Optional[float] = None   # 全局吊销生效时刻
        self.perm_version: int = 0                        # 权限模型版本

    # ---- 权限模型 ----
    def permissions_of(self, username: str) -> set[str]:
        """主体当前有效权限（其全部角色权限的并集）。判定实时读取，令牌不缓存权限。"""
        with self.lock:
            user = self.users.get(username)
            if user is None:
                return set()
            result: set[str] = set()
            for role in user.roles:
                result |= self.role_permissions.get(role, set())
            return result

    def grant_permission(self, role: str, permission: str) -> int:
        """权限新增：模型版本 +1，返回新版本。"""
        with self.lock:
            perms = self.role_permissions.setdefault(role, set())
            if permission not in perms:
                perms.add(permission)
                self.perm_version += 1
            return self.perm_version

    def revoke_permission(self, role: str, permission: str) -> int:
        """权限收窄：模型版本 +1，返回新版本。不存在的权限不产生版本跳变。"""
        with self.lock:
            perms = self.role_permissions.get(role)
            if perms is not None and permission in perms:
                perms.discard(permission)
                self.perm_version += 1
            return self.perm_version

    # ---- 会话 ----
    def create_session(self, sid: str, sub: str, now: float, refresh_jti: str) -> Session:
        with self.lock:
            session = Session(
                sid=sid, sub=sub, created_at=now,
                refresh=RefreshRecord(jti=refresh_jti, sid=sid),
            )
            self.sessions[sid] = session
            return session

    def get_session(self, sid: str) -> Optional[Session]:
        with self.lock:
            return self.sessions.get(sid)

    # ---- 吊销 ----
    # 确定性边界：iat < revoked_at 的令牌拒绝；恰好相等视为“吊销同时或之后签发”，放行。
    def revoke_subject(self, sub: str, at: float) -> None:
        """主体级吊销（按吊销时刻单调取最大值，防止回退）。"""
        with self.lock:
            prev = self.subject_revoked_at.get(sub)
            self.subject_revoked_at[sub] = at if prev is None else max(prev, at)

    def revoke_session(self, sid: str, at: float) -> None:
        """会话级吊销。"""
        with self.lock:
            session = self.sessions.get(sid)
            if session is not None:
                session.revoked_at = at if session.revoked_at is None else max(session.revoked_at, at)

    def revoke_all(self, at: float) -> None:
        """全局吊销（kill switch）。"""
        with self.lock:
            self.global_revoked_at = at if self.global_revoked_at is None else max(self.global_revoked_at, at)

    def revocation_reason(self, sub: str, sid: str, iat: float) -> Optional[tuple[FailureCode, str]]:
        """返回首个命中的吊销原因；检查顺序固定为 全局 -> 主体 -> 会话，保证结论确定。"""
        with self.lock:
            if self.global_revoked_at is not None and iat < self.global_revoked_at:
                return FailureCode.GLOBAL_REVOKED, (
                    f"全局吊销已于 t={self.global_revoked_at} 生效，令牌签发于 iat={iat}"
                )
            t = self.subject_revoked_at.get(sub)
            if t is not None and iat < t:
                return FailureCode.TOKEN_REVOKED, (
                    f"主体 {sub} 已于 t={t} 被吊销，令牌签发于 iat={iat}"
                )
            session = self.sessions.get(sid)
            if session is not None and session.revoked_at is not None and iat < session.revoked_at:
                return FailureCode.SESSION_REVOKED, (
                    f"会话 {sid} 已于 t={session.revoked_at} 被吊销，令牌签发于 iat={iat}"
                )
            return None

    # ---- 刷新轮换状态机（原子迁移）----
    def rotate_refresh(
        self, sid: str, old_jti: str, new_jti: str, now: float, replay_grace: float
    ) -> None:
        """原子地消费旧刷新令牌并挂上新刷新令牌。

        结果三选一（失败抛 :class:`AuthFailure`）：
        - 成功：旧记录进入 history（标记 consumed_at=now），current 指向新记录；
        - CONFLICT：旧记录在 ``replay_grace`` 秒内刚被消费，判为并发落败，**不改任何状态**；
        - REPLAYED：超过宽限窗口再次出现的旧令牌，或不在刷新链上的令牌 =>
          判定为重放攻击，立即吊销整个会话。
        """
        with self.lock:
            session = self.sessions.get(sid)
            if session is None:
                raise AuthFailure(
                    FailureCode.MALFORMED_TOKEN, f"刷新令牌引用的会话 {sid} 不存在"
                )
            if session.revoked_at is not None:
                raise AuthFailure(
                    FailureCode.SESSION_REVOKED,
                    f"会话 {sid} 已于 t={session.revoked_at} 被吊销",
                )
            current = session.refresh
            if current is not None and current.jti == old_jti and not current.consumed:
                # 唯一中标路径
                current.consumed = True
                current.consumed_at = now
                session.history.append(current)
                session.refresh = RefreshRecord(jti=new_jti, sid=sid)
                return

            # 旧令牌：在历史链中定位消费记录
            prior = next((r for r in session.history if r.jti == old_jti), None)
            if prior is not None and prior.consumed and prior.consumed_at is not None:
                age = now - prior.consumed_at
                if age <= replay_grace:
                    raise AuthFailure(
                        FailureCode.REFRESH_CONFLICT,
                        f"同一刷新令牌在宽限窗口内并发使用（距上次消费 {age:.6f}s <= {replay_grace}s），"
                        "本次请求落败，会话状态不变",
                    )
                session.revoked_at = now
                raise AuthFailure(
                    FailureCode.REFRESH_REPLAYED,
                    f"检测到旧刷新令牌重放（距上次消费 {age:.6f}s > {replay_grace}s），"
                    f"会话 {sid} 已被整体吊销",
                )

            # 合法签名但 jti 不在该会话的当前/历史刷新链上：视为重放/盗用，吊销会话
            session.revoked_at = now
            raise AuthFailure(
                FailureCode.REFRESH_REPLAYED,
                f"刷新令牌 jti={old_jti} 不在会话 {sid} 的刷新链上，会话已被吊销",
            )
