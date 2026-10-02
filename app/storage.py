"""本地内存存储：身份、角色、权限、资源、会话与吊销台账。

所有写操作通过一把可重入锁串行化，保证并发刷新等场景下
会话与令牌状态不会进入不确定状态。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .tokens import TokenPair

# 会话失效原因（revoked_reason 取值）
REASON_ADMIN = "admin"               # 常规注销（管理端/用户主动）
REASON_REUSE_DETECTED = "reuse_detected"  # 旧刷新令牌重复使用，整串作废

# 会话注销结果（可区分）
REVOKE_OK = "revoked"
REVOKE_ALREADY = "already_revoked"
REVOKE_NOT_FOUND = "not_found"


@dataclass
class User:
    username: str
    password: str  # 演示用明文，本地模拟
    roles: list[str]
    enabled: bool = True


@dataclass
class Role:
    name: str
    permissions: set[str] = field(default_factory=set)


@dataclass
class Resource:
    rid: str
    owner: str
    content: str


@dataclass
class RotationRecord:
    """最近一次成功轮换的记录，用于重复提交容忍窗口内的幂等重试。

    pair 为第一次成功时签发的令牌对；窗口内的重试原样返回它，
    会话不推进第二次。
    """

    old_jti: str
    new_jti: str
    rotated_at: float
    pair: TokenPair


@dataclass
class Session:
    sid: str
    subject: str
    current_refresh_jti: str
    refresh_chain: list[str] = field(default_factory=list)
    created_at: float = 0.0
    revoked: bool = False
    revoked_at: float | None = None
    revoked_reason: str | None = None  # REASON_ADMIN / REASON_REUSE_DETECTED
    last_rotation: RotationRecord | None = None


class Store:
    """线程安全的内存数据存储。"""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users: dict[str, User] = {}
        self.roles: dict[str, Role] = {}
        self.resources: dict[str, Resource] = {}
        # jti -> 被轮换（标记已使用）的时间
        self.used_refresh_jti: dict[str, float] = {}
        self.sessions: dict[str, Session] = {}
        # 主体级吊销时间；全局吊销时间
        self.subject_revoked_at: dict[str, float] = {}
        self.global_revoked_at: float | None = None

    # ---- 身份 / 权限 ----
    def get_user(self, username: str) -> User | None:
        with self.lock:
            return self.users.get(username)

    def add_user(self, user: User) -> None:
        with self.lock:
            self.users[user.username] = user

    def permissions_of(self, username: str) -> set[str]:
        """实时聚合角色权限：权限模型演进（新增/收窄）后此处立即反映。"""
        with self.lock:
            user = self.users.get(username)
            if user is None or not user.enabled:
                return set()
            perms: set[str] = set()
            for role_name in user.roles:
                role = self.roles.get(role_name)
                if role is not None:
                    perms |= role.permissions
            return perms

    def has_permission(self, username: str, permission: str) -> bool:
        return permission in self.permissions_of(username)

    def grant(self, role_name: str, permission: str) -> bool:
        """为角色新增权限；返回是否为新增。对已签发令牌即时生效。"""
        with self.lock:
            role = self.roles.get(role_name)
            if role is None:
                return False
            if permission in role.permissions:
                return False
            role.permissions.add(permission)
            return True

    def revoke_permission(self, role_name: str, permission: str) -> bool:
        """从角色收窄权限；返回是否实际移除。对已签发令牌即时生效。"""
        with self.lock:
            role = self.roles.get(role_name)
            if role is None or permission not in role.permissions:
                return False
            role.permissions.discard(permission)
            return True

    # ---- 资源 ----
    def get_resource(self, rid: str) -> Resource | None:
        with self.lock:
            return self.resources.get(rid)

    def add_resource(self, resource: Resource) -> None:
        with self.lock:
            self.resources[resource.rid] = resource

    # ---- 会话 / 刷新轮换 ----
    def create_session(self, subject: str, refresh_jti: str, now: float) -> Session:
        with self.lock:
            session = Session(
                sid=f"sess-{len(self.sessions) + 1}-{refresh_jti[:8]}",
                subject=subject,
                current_refresh_jti=refresh_jti,
                refresh_chain=[refresh_jti],
                created_at=now,
            )
            self.sessions[session.sid] = session
            return session

    def get_session(self, sid: str) -> Session | None:
        with self.lock:
            return self.sessions.get(sid)

    def rotate_refresh(
        self, sid: str, expected_jti: str, new_jti: str, now: float,
        pair: TokenPair | None = None,
    ) -> bool:
        """CAS 轮换刷新令牌。

        仅当会话存在、未被吊销、且当前刷新 jti 恰为 expected_jti 时，
        原子地把当前 jti 切换为 new_jti 并把旧 jti 记入已使用表；
        否则返回 False。并发刷新中至多一个请求成功。
        成功时若携带 pair，则记录为最近一次轮换（供容忍窗口内幂等重试）。
        """
        with self.lock:
            session = self.sessions.get(sid)
            if session is None or session.revoked:
                return False
            if session.current_refresh_jti != expected_jti:
                return False
            session.current_refresh_jti = new_jti
            session.refresh_chain.append(new_jti)
            self.used_refresh_jti[expected_jti] = now
            if pair is not None:
                session.last_rotation = RotationRecord(
                    old_jti=expected_jti, new_jti=new_jti,
                    rotated_at=now, pair=pair,
                )
            return True

    def match_retry(
        self, sid: str, jti: str, now: float, window: float
    ) -> TokenPair | None:
        """重复提交容忍窗口判定（确定性边界）。

        仅当 jti 恰为"上一次刚被轮换掉的那个刷新令牌"、且
        now - rotated_at < window（等号即超出窗口）时，
        返回第一次成功时签发的令牌对；否则返回 None。
        更早之前的旧令牌、或超出窗口，一律返回 None（按泄露处理）。
        """
        with self.lock:
            session = self.sessions.get(sid)
            if session is None or session.revoked:
                return None
            rot = session.last_rotation
            if rot is None or rot.old_jti != jti:
                return None
            if now - rot.rotated_at >= window:
                return None
            return rot.pair

    def mark_refresh_used(self, jti: str, now: float) -> None:
        with self.lock:
            self.used_refresh_jti.setdefault(jti, now)

    def was_refresh_used(self, jti: str) -> bool:
        with self.lock:
            return jti in self.used_refresh_jti

    # ---- 吊销 ----
    def revoke_session(self, sid: str, now: float, reason: str = REASON_ADMIN) -> str:
        """注销单个会话；返回可区分结果：revoked / already_revoked / not_found。"""
        with self.lock:
            session = self.sessions.get(sid)
            if session is None:
                return REVOKE_NOT_FOUND
            if session.revoked:
                return REVOKE_ALREADY
            session.revoked = True
            session.revoked_at = now
            session.revoked_reason = reason
            return REVOKE_OK

    def invalidate_family(self, sid: str, now: float) -> bool:
        """因刷新令牌重复使用，把该次登录签发的整串令牌作废。

        置会话为吊销终态并标记 revoked_reason=reuse_detected，
        使这一串的访问令牌与刷新令牌全部失效，且与常规注销可区分。
        """
        with self.lock:
            session = self.sessions.get(sid)
            if session is None or session.revoked:
                return False
            session.revoked = True
            session.revoked_at = now
            session.revoked_reason = REASON_REUSE_DETECTED
            return True

    # ---- 会话治理（按主体） ----
    def sessions_of(self, subject: str) -> list[Session]:
        """列出主体名下全部会话（含已失效），按创建时间排序。"""
        with self.lock:
            return sorted(
                (s for s in self.sessions.values() if s.subject == subject),
                key=lambda s: (s.created_at, s.sid),
            )

    def revoke_subject_sessions(
        self, subject: str, now: float, reason: str = REASON_ADMIN
    ) -> list[str]:
        """一次性注销主体名下所有仍活着的会话；返回本次实际注销的 sid 列表。"""
        with self.lock:
            revoked: list[str] = []
            for session in self.sessions.values():
                if session.subject == subject and not session.revoked:
                    session.revoked = True
                    session.revoked_at = now
                    session.revoked_reason = reason
                    revoked.append(session.sid)
            return revoked

    def revoke_subject(self, username: str, now: float) -> None:
        with self.lock:
            prev = self.subject_revoked_at.get(username)
            self.subject_revoked_at[username] = now if prev is None else max(prev, now)

    def revoke_all(self, now: float) -> None:
        with self.lock:
            self.global_revoked_at = now if self.global_revoked_at is None else max(
                self.global_revoked_at, now
            )

    def revocation_time(self, subject: str) -> float | None:
        """对该主体生效的吊销时间：主体级与全局取较晚者；无吊销返回 None。"""
        with self.lock:
            candidates = [
                t for t in (self.global_revoked_at, self.subject_revoked_at.get(subject))
                if t is not None
            ]
            return max(candidates) if candidates else None
