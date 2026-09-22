# 本地 API 认证与访问控制（Python / FastAPI）

一套**本地签发、本地存储**的认证与访问控制流程：用 HMAC 自签名令牌 + 内存存储模拟
身份、会话、权限与吊销数据，目标是让令牌生命周期、权限变更和吊销在每一个入口
（服务层 / HTTP 层 / 并发请求 / 时钟偏移）下都给出**一致、确定、可解释**的结论。

无外部数据库或认证服务依赖，仅需 FastAPI（令牌编解码只用标准库 `hmac/hashlib/json`）。

## 快速开始

```bash
uv sync                                   # 安装依赖
uv run uvicorn main:app --reload          # 启动服务（默认 http://127.0.0.1:8000）
uv run python -m pytest                   # 运行全部测试（含判定依据日志）
```

内置演示数据：

| 用户  | 密码      | 角色    | 权限             |
|-------|-----------|---------|------------------|
| alice | pw-alice  | admin   | resource:read    |
| bob   | pw-bob    | viewer  | resource:read    |
| carol | pw-carol  | auditor | audit:read       |

资源：`doc-1`（需 `resource:read`）、`doc-2`（需 `audit:read`）。

```bash
# 登录
curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"pw-alice"}'
# 用返回的 access_token 访问资源
curl -s localhost:8000/resources/doc-1 -H "Authorization: Bearer <access_token>"
```

## HTTP 接口

| 方法   | 路径 | 说明 |
|--------|------|------|
| POST | `/auth/login` | 凭据换令牌对（access + refresh + sid） |
| POST | `/auth/refresh` | 刷新轮换（旧 refresh 作废旧链） |
| POST | `/auth/logout` | 会话级吊销（body: `{"sid": "..."}`） |
| GET  | `/resources/{id}` | 带 Bearer 令牌访问资源 |
| POST | `/admin/roles/permissions` | 权限新增（body: role/permission） |
| DELETE | `/admin/roles/permissions` | 权限收窄 |
| POST | `/admin/revocation/subjects/{sub}` | 主体级吊销 |
| POST | `/admin/revocation/global` | 全局吊销（kill switch） |

所有失败响应统一形如：

```json
{"error": "<machine_readable_code>", "reason": "<人读判定依据，含关键状态>"}
```

## 失败分类（原因互不重叠，可机读区分）

| error 码 | HTTP | 含义 |
|----------|------|------|
| `missing_token` | 401 | 未携带/格式错误的 Authorization 头 |
| `malformed_token` | 401 | 令牌结构、编码、字段或引用会话有问题 |
| `bad_signature` | 401 | 签名不匹配（篡改），与过期严格区分 |
| `token_expired` | 401 | `at > exp + leeway` |
| `token_not_yet_valid` | 401 | `iat > at + leeway`（签发时间在未来，时钟偏移超界） |
| `token_revoked` | 401 | 主体级吊销命中 |
| `session_revoked` | 401 | 会话级吊销命中（含刷新重放后的整会话吊销） |
| `globally_revoked` | 401 | 全局吊销命中 |
| `refresh_replayed` | 401 | 宽限窗口外旧刷新令牌重放，会话已被整会话吊销 |
| `concurrent_refresh_conflict` | 409 | 同一刷新令牌并发使用，本请求落败，状态不变 |
| `invalid_credentials` | 401 | 用户名/密码错误 |
| `permission_denied` | 403 | 已认证但权限不足 |
| `resource_not_found` | 404 | 目标资源不存在 |

## 令牌生命周期

令牌形态：`base64url(JSON Claims).base64url(HMAC_SHA256)`，自包含、无状态可验签。

```jsonc
// Claims
{"sub": "alice", "sid": "<会话id>", "typ": "access|refresh",
 "jti": "<令牌唯一id>", "iat": 签发时刻, "exp": 过期时刻, "pv": 签发时权限模型版本}
```

- 默认 TTL：access 900 秒、refresh 86400 秒（`AuthService` 构造参数可调）。
- **登录**：校验凭据 → 创建会话 → 签发首对令牌；会话记录持有当前 refresh 的 jti。
- **刷新轮换（rotation）**：每次刷新原子地消费旧 refresh（标记 `consumed_at` 并入历史链）、
  挂上新 refresh、签发新令牌对。
- **刷新失败的确定性分类**：
  - 旧 refresh 在 `replay_grace`（默认 5 秒）窗口内再次出现 →
    `concurrent_refresh_conflict`（409），**不改动任何会话/令牌状态**。这表示
    “同一令牌的并发刷新只有一次中标”，落败方应使用中标方返回的新令牌，而不是重试旧令牌。
  - 窗口外再次出现，或合法签名但 jti 不在该会话刷新链上 →
    `refresh_replayed`（401），判定为重放/盗用，**立即吊销整个会话**，
    其后任何该会话的令牌（包括刚轮换出的新对）都以 `session_revoked` 拒绝。
  - 过期、篡改、被吊销的 refresh 在进入轮换逻辑前即以各自的码拒绝，原因不混淆。
- 整个轮换在存储层同一把锁内完成（解码/签发放到锁外，锁内只做状态迁移），
  32 个线程同时刷新同一令牌时：恰好 1 个成功，其余全部 CONFLICT，状态唯一确定。

## 权限模型与访问控制

- 权限模型为 `用户 → 角色[] → 权限集合`，访问时取角色权限的并集。
- **权限实时判定**：每次请求都从当前模型计算权限集，令牌内的 `pv` 只记录签发时的
  模型版本快照，用于日志解释（`token_pv` vs `model_pv`），**不参与放行判定**。
  因此：
  - 权限**新增**后，此前签发、尚未过期的旧令牌立即获得访问权；
  - 权限**收窄**后，同一旧令牌立即失去访问权（返回 403，认证本身仍然通过，
    会话也不被吊销——权限变更与安全吊销是两条独立语义）。
- 模型版本 `perm_version` 单调递增；重复授予/删除不存在的权限是幂等的，
  不制造无意义的版本跳变。
- **资源访问的结论顺序固定**：未认证 (401) → 资源不存在 (404) → 权限不足 (403) → 允许 (200)。
  即先确认资源存在再判权限，**不会用 403 掩盖资源是否存在**；对已认证用户，
  “存在但无权”与“根本不存在”是两个可区分的结论。

## 吊销语义

三种粒度，全部以**令牌签发时刻 `iat` 与吊销生效时刻比较**来判定：

- 主体级：`POST /admin/revocation/subjects/{sub}`，吊销该用户此前的全部会话令牌；
- 会话级：`POST /auth/logout`（或刷新重放触发的自动吊销）；
- 全局：`POST /admin/revocation/global`，kill switch，影响所有用户。

确定性规则：

1. **边界严格**：`iat < revoked_at` 拒绝；`iat == revoked_at` 视为吊销生效同时或之后
   签发，放行。不存在随机或自相矛盾的临界结果。
2. **检查顺序固定**：全局 → 主体 → 会话，同时命中时返回排在最前者，原因始终可解释。
3. **立即生效**：吊销不依赖令牌过期——吊销前签发且未过期的 access/refresh 令牌
   在下一次校验时即以对应码拒绝。
4. 吊销时刻取单调最大值（重复/并发吊销不会让生效时间回退）。

## 时钟偏移与时间语义

- 所有时间判断只依赖 `Clock` 抽象（`SystemClock` / 可注入的 `OffsetClock`），
  测试中时钟完全可控，结论可复现。
- 两条边界均为**严格比较**：
  - `at > exp + leeway` → `token_expired`；恰好 `at == exp + leeway` 仍有效；
  - `iat > at + leeway` → `token_not_yet_valid`（校验端时钟明显落后时）。
- `leeway`（默认 0）同时向“过期”和“未来签发”两个方向施加容差，
  用于吸收校验端与签发端的固定时钟偏移；偏移超界时拒绝原因明确区分两个方向。
- 不同校验端时钟不同导致结论不同是预期行为：每个结论都相对该校验端的时钟确定，
  且 `reason` 中打印 `iat / exp / at / leeway` 等关键量，可直接核对。

## 兼容规则

- **令牌载荷**：新增 Claims 字段时，旧令牌缺少新字段应由消费方按默认值处理，
  验签只认签名与既有字段，不因加字段而误判为篡改（当前必要字段：
  `sub,sid,typ,jti,iat,exp,pv`）。
- **权限模型演进**：旧令牌不携带权限列表，模型新增/收窄权限对旧令牌立即、确定地生效；
  `pv` 仅用于审计与日志解释，不会因版本不同而拒绝令牌。
- **密钥**：令牌使用对称密钥本地签发（`create_app(secret=...)`）；轮换密钥意味着
  旧令牌以 `bad_signature` 被拒，需要重新登录（本地模拟，不支持多密钥并存）。
- **失败码即契约**：新增失败原因必须新增 code，不得复用既有 code 表达新语义。

## 代码结构

```
auth/
  errors.py    # FailureCode 分类与 AuthFailure（code + 判定依据 reason）
  clock.py     # Clock / SystemClock / OffsetClock（确定性时间）
  tokens.py    # Claims + HMAC 令牌签发/验签/时间边界
  storage.py   # 内存存储、权限模型、三类吊销、刷新轮换原子状态机
  service.py   # 登录/刷新/认证/授权/资源访问/管理操作 + 判定日志
  api.py       # FastAPI 路由与 Bearer 提取
  app.py       # 装配、演示数据、code→HTTP 状态码映射、异常处理
main.py        # uvicorn 入口
tests/         # 六组覆盖用例（见下）
```

## 测试覆盖与验证方法

```bash
uv run python -m pytest          # 实时打印每个判定的依据与令牌状态变化
uv run python -m pytest -q       # 安静模式
```

| 测试文件 | 覆盖点 |
|----------|--------|
| `test_refresh_rotation.py` | 正常轮换、旧令牌窗口外重放（REPLAYED + 整会话吊销）、过期、签名篡改、结构损坏、坏凭据——失败各自归类 |
| `test_concurrent_refresh.py` | 32 线程并发刷新恰好一次成功、其余 CONFLICT 且状态不变；窗口外重放不被误判为冲突 |
| `test_revocation.py` | 主体/会话/全局三粒度吊销后令牌立即失效；`iat == revoked_at` 边界放行；命中顺序 |
| `test_access_control.py` | 401/403/404 三类结论可区分（含不存在资源不被越权掩盖）；HTTP 状态码与响应体；HTTP 入口并发刷新 1×200 + N×409 |
| `test_permission_change.py` | 权限新增/收窄对既有旧令牌的确定影响；认证与授权解耦；版本单调与幂等 |
| `test_clock_skew.py` | exp 严格边界、leeway 容差边界、校验端时钟超前/落后两个方向的确定性结论 |

日志中可观察到的关键证据示例：

```
refresh ok ... old_jti=... consumed_at=... new_jti=... pv=0
refresh rejected ... code=concurrent_refresh_conflict reason=...本次请求落败，会话状态不变
authenticate rejected ... code=token_revoked reason=主体 alice 已于 t=... 被吊销，令牌签发于 iat=...
authenticate ok ... token_pv=0 model_pv=1 at=...     # 旧令牌在新版本模型下判定
access denied ... 需要 audit:read，当前权限集 ['resource:read']（pv=0）
```
