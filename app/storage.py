"""本地内存存储：身份、角色、权限、资源、会话与吊销台账。

所有写操作通过一把可重入锁串行化，保证并发刷新等场景下
会话与令牌状态不会进入不确定状态。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace


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
    # 凭证泄露终态：因"已轮换掉的旧刷新令牌被再次使用"而整串作废。
    # 与普通注销 revoked 并存但语义独立，排查时可直接区分。
    compromised: bool = False
    compromised_at: float | None = None
    # 已完成的轮换次数（登录时为 0），日志用于定位命中的是第几次刷新。
    rotation_seq: int = 0


@dataclass(frozen=True)
class RotationRecord:
    """一次成功刷新的幂等记录：以"被换掉的旧刷新 jti"为键。

    容忍窗口内用同一个旧刷新令牌重试时，原样回放当时签发的令牌对，
    会话不二次推进。
    """

    sid: str
    old_jti: str
    new_jti: str
    rotated_at: float
    seq: int  # 该记录是会话的第几次轮换（从 1 开始）
    access_token: str
    refresh_token: str
    access_expires_in: int
    refresh_expires_in: int


# 会话在列表中的对外状态
SESSION_ACTIVE = "active"          # 正常
SESSION_REVOKED = "revoked"        # 普通注销 / 会话级吊销
SESSION_COMPROMISED = "compromised"  # 因旧刷新令牌重放被判泄露，整串作废


@dataclass(frozen=True)
class SessionView:
    """会话列表项：只含标识与状态，绝不暴露任何令牌内容。"""

    sid: str
    subject: str
    created_at: float
    status: str
    revoked_at: float | None
    compromised_at: float | None
    rotation_seq: int


class Store:
    """线程安全的内存数据存储。"""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users: dict[str, User] = {}
        self.roles: dict[str, Role] = {}
        self.resources: dict[str, Resource] = {}
        # jti -> 被轮换（标记已使用）的时间
        self.used_refresh_jti: dict[str, float] = {}
        # old_jti -> RotationRecord，用于容忍窗口内的幂等重试回放
        self.rotation_records: dict[str, RotationRecord] = {}
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
        self, sid: str, expected_jti: str, record: RotationRecord, now: float
    ) -> bool:
        """CAS 轮换刷新令牌，并在同一临界区内固化幂等记录。

        仅当会话存在、既未被注销也未被判泄露、且当前刷新 jti 恰为
        expected_jti 时，原子地：切换当前 jti、旧 jti 入"已使用表"、
        写入以旧 jti 为键的 RotationRecord；否则返回 False。
        并发刷新中至多一个请求成功。
        """
        with self.lock:
            session = self.sessions.get(sid)
            if session is None or session.revoked or session.compromised:
                return False
            if session.current_refresh_jti != expected_jti:
                return False
            session.current_refresh_jti = record.new_jti
            session.refresh_chain.append(record.new_jti)
            session.rotation_seq += 1
            self.used_refresh_jti[expected_jti] = now
            # seq 在临界区内盖戳，保证记录与链推进是同一个原子结论
            self.rotation_records[expected_jti] = replace(record, seq=session.rotation_seq)
            return True

    def lookup_rotation(self, old_jti: str) -> RotationRecord | None:
        """返回某次旧刷新令牌对应的成功轮换记录（不存在返回 None）。"""
        with self.lock:
            return self.rotation_records.get(old_jti)

    def mark_refresh_used(self, jti: str, now: float) -> None:
        with self.lock:
            self.used_refresh_jti.setdefault(jti, now)

    def was_refresh_used(self, jti: str) -> bool:
        with self.lock:
            return jti in self.used_refresh_jti

    def compromise_session(self, sid: str, now: float) -> bool:
        """把会话标记为"凭证泄露、整串作废"（幂等，终态）。

        与普通注销相互独立：compromised 优先作为对外结论。
        返回是否本次实际发生了状态变化。
        """
        with self.lock:
            session = self.sessions.get(sid)
            if session is None:
                return False
            if not session.compromised:
                session.compromised = True
                session.compromised_at = now
            return True

    # ---- 会话治理 ----
    def list_sessions_of(self, subject: str) -> list[SessionView]:
        """按主体列出全部会话（含已注销/已作废），按创建时间排序。

        只返回标识、时间与状态，绝不返回令牌内容。
        """
        with self.lock:
            views = [
                self._view(s) for s in self.sessions.values() if s.subject == subject
            ]
        views.sort(key=lambda v: v.created_at)
        return views

    @staticmethod
    def _view(session: Session) -> SessionView:
        if session.compromised:
            status = SESSION_COMPROMISED
        elif session.revoked:
            status = SESSION_REVOKED
        else:
            status = SESSION_ACTIVE
        return SessionView(
            sid=session.sid,
            subject=session.subject,
            created_at=session.created_at,
            status=status,
            revoked_at=session.revoked_at,
            compromised_at=session.compromised_at,
            rotation_seq=session.rotation_seq,
        )

    def revoke_all_sessions_of(self, subject: str, now: float) -> int:
        """一次性注销该主体名下仍存活的会话；返回实际注销的数量。

        已注销/已判泄露的会话不重复计数；主体不存在或无活会话时返回 0。
        注意：本原语只做计数，"主体是否存在"由 AuthService 在认证、鉴权
        之后统一判定（SubjectNotFound），不要据此把不存在误报给上层。
        """
        with self.lock:
            count = 0
            for session in self.sessions.values():
                if session.subject != subject:
                    continue
                if session.revoked or session.compromised:
                    continue
                session.revoked = True
                session.revoked_at = now
                count += 1
            return count

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
