"""访问控制：认证 -> 鉴权 -> 资源存在性，顺序固定、结论可区分。

关键语义：
- 未携带/非法/过期/已吊销令牌 => 401，绝不继续透露资源是否存在；
- 已认证但权限不足 => 403；
- 权限通过但资源不存在 => 404。
因此"资源存在性"永远在"权限通过"之后才判定，不会用越权掩盖缺失，
也不会把无权访问的资源泄露给无权主体。

权限在每次请求时从存储实时解析，因此角色权限新增/收窄即时生效，
不依赖旧令牌中固化的权限快照。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from .auth_service import AuthService
from .errors import Forbidden, ResourceNotFound
from .storage import Resource, Store
from .tokens import Claims

log = logging.getLogger("access")


@dataclass
class Decision:
    allowed: bool
    reason: str
    subject: str | None = None
    resource: Resource | None = None
    claims: Claims | None = None


class Guard:
    def __init__(self, store: Store, auth: AuthService) -> None:
        self.store = store
        self.auth = auth

    def check(
        self, token: str | None, required_permission: str, resource_id: str | None
    ) -> Decision:
        """返回最终判定；各失败分支以对应 AuthError 抛出并记录依据。"""
        # 1) 认证：失败直接抛出 401 类错误
        claims = self.auth.authenticate(token)

        # 2) 鉴权：权限实时计算，权限模型变更即时生效
        permissions = self.store.permissions_of(claims.sub)
        if required_permission not in permissions:
            log.info(
                "鉴权拒绝 user=%s sid=%s required=%s held=%s reason=forbidden",
                claims.sub, claims.sid, required_permission,
                ",".join(sorted(permissions)) or "(none)",
            )
            raise Forbidden(
                f"权限不足：需要 {required_permission}",
                reason=f"missing_permission:{required_permission}",
            )

        # 3) 资源存在性：仅对已通过鉴权的主体判定，避免资源枚举
        resource: Resource | None = None
        if resource_id is not None:
            resource = self.store.get_resource(resource_id)
            if resource is None:
                log.info(
                    "资源缺失 user=%s permission=%s resource=%s reason=resource_not_found",
                    claims.sub, required_permission, resource_id,
                )
                raise ResourceNotFound(f"资源 {resource_id} 不存在")

        log.info(
            "访问放行 user=%s sid=%s permission=%s resource=%s reason=allowed",
            claims.sub, claims.sid, required_permission, resource_id,
        )
        return Decision(
            allowed=True, reason="allowed", subject=claims.sub,
            resource=resource, claims=claims,
        )
