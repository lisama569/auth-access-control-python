"""手动端到端冒烟：登录/访问/刷新、窗口内重试、窗口外旧刷新整串作废、
越权/404、按主体会话治理、过期。

用法：uv run python scripts/smoke.py
"""
from fastapi.testclient import TestClient

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.api import create_app
from app.bootstrap import build_context


def main() -> None:
    ctx = build_context()
    http = TestClient(create_app(ctx.store, ctx.clock, ctx.auth, ctx.guard))
    H = lambda t: {"Authorization": f"Bearer {t}"}

    def step(title, resp):
        print(f"{title:34} -> {resp.status_code} {resp.json().get('error', 'OK')}")

    alice = http.post("/auth/login", json={"username": "alice", "password": "alice-pw"}).json()
    carol = http.post("/auth/login", json={"username": "carol", "password": "carol-pw"}).json()

    step("正常读文档", http.get("/docs/doc-1", headers=H(alice["access_token"])))
    step("匿名访问(401)", http.get("/docs/doc-1"))
    step("viewer 写文档(403)", http.put("/docs/doc-1", headers=H(carol["access_token"])))
    step("权限通过资源缺失(404)", http.get("/docs/nope", headers=H(alice["access_token"])))

    # 刷新：首次成功、窗口内重试原样回放
    step("首次刷新(200)", http.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]}))
    step("窗口内重试(200 回放)", http.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]}))

    # 超出容忍窗口再用旧刷新令牌 => 判定泄露，整串作废
    ctx.clock.advance(ctx.auth.config.retry_window + 1)
    step("窗口外旧刷新(401 整串作废)",
         http.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]}))
    step("整串里旧访问令牌(401 作废)", http.get("/docs/doc-1", headers=H(alice["access_token"])))

    # 整串作废不阻止重新登录
    alice2 = http.post("/auth/login", json={"username": "alice", "password": "alice-pw"}).json()
    step("作废后重新登录(200)", http.get("/docs/doc-1", headers=H(alice2["access_token"])))

    # 会话治理：viewer 无权；admin 列会话、批量注销、再列会话
    carol2 = http.post("/auth/login", json={"username": "carol", "password": "carol-pw"}).json()
    step("viewer 列会话(403)", http.get("/admin/subjects/carol/sessions", headers=H(carol2["access_token"])))
    step("admin 列 carol 会话(200)", http.get("/admin/subjects/carol/sessions", headers=H(alice2["access_token"])))
    step("批量注销 carol(200)", http.post("/admin/subjects/carol/sessions/revoke", headers=H(alice2["access_token"])))
    step("注销后 carol 旧令牌(401)", http.get("/docs/doc-1", headers=H(carol2["access_token"])))
    step("不存在会话注销(404)", http.post("/admin/sessions/nope/revoke", headers=H(alice2["access_token"])))

    # 按主体治理：不存在的主体必须明确 404，不能伪装成成功的空操作；
    # 已注册主体（carol，其会话此前已被批量注销）列会话仍是 200
    step("不存在主体列会话(404)", http.get("/admin/subjects/ghost/sessions", headers=H(alice2["access_token"])))
    step("不存在主体批量注销(404)", http.post("/admin/subjects/ghost/sessions/revoke", headers=H(alice2["access_token"])))
    step("存在主体列会话(200)", http.get("/admin/subjects/carol/sessions", headers=H(alice2["access_token"])))

    ctx.clock.advance(901)
    step("访问令牌过期(401)", http.get("/docs/doc-1", headers=H(alice2["access_token"])))


if __name__ == "__main__":
    main()
