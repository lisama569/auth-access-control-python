"""手动端到端冒烟：登录/访问/刷新/重试窗口/泄露检测/越权/404/吊销/过期/会话治理。

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
    retry = http.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]})
    step("窗口内重试(200 同一对)", retry)
    assert retry.json()["refresh_token"] == r1.json()["refresh_token"]

    ctx.clock.advance(ctx.auth.config.refresh_retry_window + 0.1)
    step("窗口外重用旧刷新(401)", http.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]}))
    step("整串作废后访问(401)", http.get("/docs/doc-1", headers=H(r1.json()["access_token"])))

    alice = http.post("/auth/login", json={"username": "alice", "password": "alice-pw"}).json()
    step("泄露后重新登录(200)", http.get("/docs/doc-1", headers=H(alice["access_token"])))

    step("列出 carol 会话(200)", http.get("/admin/subjects/carol/sessions", headers=H(alice["access_token"])))
    step("carol 无权列会话(403)", http.get("/admin/subjects/alice/sessions", headers=H(carol["access_token"])))
    step("批量注销 carol 会话(200)", http.post("/admin/subjects/carol/sessions/revoke", headers=H(alice["access_token"])))
    step("批量注销后访问(401)", http.get("/docs/doc-1", headers=H(carol["access_token"])))

    ctx.clock.advance(901)
    step("访问令牌过期(401)", http.get("/docs/doc-1", headers=H(alice["access_token"])))


if __name__ == "__main__":
    main()
