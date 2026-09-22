"""本地内存存储：身份、角色、权限、资源、会话与吊销台账。

所有写操作通过一把可重入锁串行化，保证并发刷新等场景下
会话与令牌状态不会进入不确定状态。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field


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
class Session:
    sid: str
    subject: str
    current_refresh_jti: str
    refresh_chain: list[str] = field(default_factory=list)
    created_at: float = 0.0
    revoked: bool = False
    revoked_at: float | None = None


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
        self, sid: str, expected_jti: str, new_jti: str, now: float
    ) -> bool:
        """CAS 轮换刷新令牌。

        仅当会话存在、未被吊销、且当前刷新 jti 恰为 expected_jti 时，
        原子地把当前 jti 切换为 new_jti 并把旧 jti 记入已使用表；
        否则返回 False。并发刷新中至多一个请求成功。
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
            return True

    def mark_refresh_used(self, jti: str, now: float) -> None:
        with self.lock:
            self.used_refresh_jti.setdefault(jti, now)

    def was_refresh_used(self, jti: str) -> bool:
        with self.lock:
            return jti in self.used_refresh_jti

    # ---- 吊销 ----
    def revoke_session(self, sid: str, now: float) -> bool:
        with self.lock:
            session = self.sessions.get(sid)
            if session is None:
                return False
            if not session.revoked:
                session.revoked = True
                session.revoked_at = now
            return True

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
