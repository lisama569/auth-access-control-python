"""手动端到端冒烟：跑通登录/访问/刷新/重放/越权/404/吊销/过期。

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
        print(f"{title:32} -> {resp.status_code} {resp.json().get('error', 'OK')}")

    alice = http.post("/auth/login", json={"username": "alice", "password": "alice-pw"}).json()
    carol = http.post("/auth/login", json={"username": "carol", "password": "carol-pw"}).json()

    step("正常读文档", http.get("/docs/doc-1", headers=H(alice["access_token"])))
    step("匿名访问(401)", http.get("/docs/doc-1"))
    step("viewer 写文档(403)", http.put("/docs/doc-1", headers=H(carol["access_token"])))
    step("权限通过资源缺失(404)", http.get("/docs/nope", headers=H(alice["access_token"])))

    r1 = http.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]})
    step("首次刷新(200)", r1)
    step("重放旧刷新(401)", http.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]}))

    step("吊销 carol(200)", http.post("/admin/revoke/subject/carol", headers=H(alice["access_token"])))
    step("吊销后访问(401)", http.get("/docs/doc-1", headers=H(carol["access_token"])))

    ctx.clock.advance(901)
    step("访问令牌过期(401)", http.get("/docs/doc-1", headers=H(alice["access_token"])))


if __name__ == "__main__":
    main()
