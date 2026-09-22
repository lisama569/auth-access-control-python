"""令牌生命周期：过期、签名篡改、类型误用与时钟偏移临界判定。

边界规则（确定性）：
    is_expired 定义为 now - leeway >= exp；等号成立即"过期"。
"""
from __future__ import annotations

import logging

from app.tokens import ACCESS, REFRESH, Claims, decode, encode, is_expired

from .conftest import FIXED_NOW, auth_header, login

log = logging.getLogger("tests")


def test_login_success_and_token_decodable(client):
    data = login(client, "alice", "alice-pw")
    assert data["token_type"] == "Bearer"
    claims = decode(data["access_token"], "local-demo-secret")
    assert claims.sub == "alice"
    assert claims.kind == ACCESS
    log.info("判定依据: 登录成功 sid=%s jti=%s", claims.sid, claims.jti[:8])


def test_login_bad_password_is_401_invalid_credentials(client):
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credentials"


def test_expired_access_token_is_rejected_as_token_expired(client, ctx):
    data = login(client, "alice", "alice-pw")
    ctx.clock.advance(901)  # TTL=900
    resp = client.get("/docs/doc-1", headers=auth_header(data))
    body = resp.json()
    assert resp.status_code == 401
    assert body["error"] == "token_expired"
    log.info("判定依据: 过期访问被拒 reason=%s", body["reason"])


def test_tampered_signature_is_rejected_as_token_tampered(client):
    data = login(client, "alice", "alice-pw")
    head, payload, _sig = data["access_token"].split(".")
    tampered = f"{head}.{payload}.{'A' * len(_sig)}"
    resp = client.get("/docs/doc-1", headers={"Authorization": f"Bearer {tampered}"})
    body = resp.json()
    assert resp.status_code == 401
    assert body["error"] == "token_tampered"
    log.info("判定依据: 签名篡改被拒 reason=%s", body["reason"])


def test_tampered_payload_is_rejected_as_token_tampered(client, ctx):
    data = login(client, "bob", "bob-pw")
    head, _payload, sig = data["access_token"].split(".")
    # 构造一个 sub=alice 的伪造负载，沿用原签名 -> HMAC 不匹配
    forged = Claims(
        jti="deadbeef", sub="alice", sid="x", kind=ACCESS,
        iat=FIXED_NOW, exp=FIXED_NOW + 900, ver=1,
    )
    forged_token = encode(forged, ctx.auth.config.secret)
    _h, forged_payload, _s = forged_token.split(".")
    resp = client.get(
        "/docs/doc-1", headers={"Authorization": f"Bearer {head}.{forged_payload}.{sig}"}
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_tampered"


def test_missing_authorization_header_is_unauthenticated(client):
    resp = client.get("/docs/doc-1")
    body = resp.json()
    assert resp.status_code == 401
    assert body["error"] == "unauthenticated"


def test_refresh_token_used_as_access_is_token_tampered(client):
    data = login(client, "alice", "alice-pw")
    resp = client.get(
        "/docs/doc-1", headers={"Authorization": f"Bearer {data['refresh_token']}"}
    )
    body = resp.json()
    assert resp.status_code == 401
    assert body["error"] == "token_tampered"
    assert "令牌类型不匹配" in body["message"]


def test_access_token_used_at_refresh_endpoint_is_token_tampered(client):
    data = login(client, "alice", "alice-pw")
    resp = client.post("/auth/refresh", json={"refresh_token": data["access_token"]})
    body = resp.json()
    assert resp.status_code == 401
    assert body["error"] == "token_tampered"


def test_expiry_boundary_is_deterministic_equality_expired():
    """now - leeway == exp 的临界瞬间必须确定地算过期。"""
    claims = Claims(
        jti="j", sub="u", sid="s", kind=ACCESS,
        iat=100.0, exp=200.0, ver=1,
    )
    assert is_expired(claims, now=199.999, leeway=0.0) is False
    assert is_expired(claims, now=200.0, leeway=0.0) is True
    assert is_expired(claims, now=200.001, leeway=0.0) is True
    log.info("判定依据: 过期边界 exp=200.0 now=200.0 => expired(True)")


def test_clock_skew_within_leeway_still_accepted(client, ctx):
    """校验方时钟快于权威时钟：在 leeway 内的临界请求仍放行。"""
    ctx.auth.config.leeway = 5.0
    data = login(client, "alice", "alice-pw")
    # 令牌 exp=FIXED_NOW+900；校验时钟拨快 3 秒，仍在 5 秒容差内
    ctx.clock.set_offset(3.0)
    ctx.clock.instant = FIXED_NOW + 900.0  # 权威时间恰为 exp
    resp = client.get("/docs/doc-1", headers=auth_header(data))
    assert resp.status_code == 200, resp.text
    log.info("判定依据: 时钟偏移+3s<=leeway=5s 放行")


def test_clock_skew_beyond_leeway_expired(client, ctx):
    """偏移超出容差必须稳定地判过期，重复结论一致。"""
    ctx.auth.config.leeway = 5.0
    data = login(client, "alice", "alice-pw")
    ctx.clock.set_offset(6.0)
    ctx.clock.instant = FIXED_NOW + 900.0  # now=exp+6 => now-leeway=exp+1 > exp
    results = []
    for _ in range(3):
        resp = client.get("/docs/doc-1", headers=auth_header(data))
        results.append((resp.status_code, resp.json()["error"]))
    assert all(r == (401, "token_expired") for r in results)
    log.info("判定依据: 时钟偏移+6s>leeway=5s 三次重复结论均为 %s", results)


def test_negative_clock_skew_never_causes_early_expiry(client, ctx):
    """校验方时钟慢：令牌不会提前过期。"""
    data = login(client, "alice", "alice-pw")
    ctx.clock.set_offset(-3600.0)
    ctx.clock.instant = FIXED_NOW + 1000.0
    resp = client.get("/docs/doc-1", headers=auth_header(data))
    assert resp.status_code == 200
