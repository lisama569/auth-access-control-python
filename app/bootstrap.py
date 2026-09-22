"""组装演示数据与服务：角色、权限、用户、资源。

种子数据：
- 角色 admin：  doc:read, doc:write, doc:delete, admin:revoke
- 角色 editor： doc:read, doc:write
- 角色 viewer： doc:read
- 用户 alice(admin) / bob(editor) / carol(viewer)
- 资源 doc-1(owner=alice) / doc-2(owner=bob)
"""
from __future__ import annotations

from dataclasses import dataclass

from .access_control import Guard
from .auth_service import AuthConfig, AuthService
from .clock import Clock
from .storage import Resource, Role, Store, User

ADMIN_PERMS = {"doc:read", "doc:write", "doc:delete", "admin:revoke"}
EDITOR_PERMS = {"doc:read", "doc:write"}
VIEWER_PERMS = {"doc:read"}


@dataclass
class AppContext:
    store: Store
    clock: Clock
    auth: AuthService
    guard: Guard


def _seed(store: Store) -> Store:
    store.roles["admin"] = Role("admin", set(ADMIN_PERMS))
    store.roles["editor"] = Role("editor", set(EDITOR_PERMS))
    store.roles["viewer"] = Role("viewer", set(VIEWER_PERMS))

    store.add_user(User("alice", "alice-pw", ["admin"]))
    store.add_user(User("bob", "bob-pw", ["editor"]))
    store.add_user(User("carol", "carol-pw", ["viewer"]))

    store.add_resource(Resource("doc-1", "alice", "季度规划（机密）"))
    store.add_resource(Resource("doc-2", "bob", "编辑周报"))
    return store


def build_context(
    clock: Clock | None = None,
    config: AuthConfig | None = None,
    *,
    seed: bool = True,
) -> AppContext:
    store = Store()
    if seed:
        _seed(store)
    clock = clock or Clock(instant=1_000_000.0)  # 固定起点，保证测试确定性
    auth = AuthService(store, clock, config)
    guard = Guard(store, auth)
    return AppContext(store=store, clock=clock, auth=auth, guard=guard)
