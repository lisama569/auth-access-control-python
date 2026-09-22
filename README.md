# 本地 API 认证与访问控制（Python / FastAPI）

一个**完全本地运行、无外部依赖服务**的认证与访问控制演示：令牌在本地用 HMAC 签发，
身份、角色、权限、会话与吊销台账全部保存在进程内存中。重点是把以下三件事做到
**结论可区分、状态确定、判定依据可在日志中解释**：

1. 访问令牌 / 刷新令牌的签发、刷新轮换（过期、篡改、重放、并发竞争）；
2. 基于角色与权限范围的访问控制（未认证 / 越权 / 资源不存在严格可区分）+ 三种粒度吊销；
3. 权限模型演进的即时语义与时钟偏移下的确定性临界判定。

## 运行

```bash
uv sync                       # 安装依赖（含 pytest/httpx）
uv run uvicorn main:app --reload
# 或：uv run python -c "import uvicorn; uvicorn.run('main:app', port=8000)"
```

打开 http://127.0.0.1:8000/docs 可交互调试。健康检查：`GET /health`。

## 验证（测试）

```bash
uv run pytest -s -o log_cli=true -o log_cli_level=INFO
# 或安静模式：uv run pytest -q
```

39 个用例，分布：

| 文件 | 覆盖内容 |
| --- | --- |
| `tests/test_token_lifecycle.py` | 登录、过期、签名/负载篡改、令牌类型误用、缺失令牌、过期等号边界、正负时钟偏移与容差 |
| `tests/test_refresh_rotation.py` | 正常轮换、旧令牌重放、重放不影响最新令牌、8 线程并发恰好一次成功、刷新过期 |
| `tests/test_concurrent_service.py` | 服务层真实锁内交错，覆盖 `refresh_conflict`（409）竞争分支与串行轮换链 |
| `tests/test_access_control.py` | 401/403/404 可区分、会话/主体/全局三种吊销、吊销后重新登录、非管理员不能吊销 |
| `tests/test_permission_evolution.py` | 角色权限新增/收窄对**既有令牌**即时生效、逐条独立、轮换令牌同样跟随 |
| `tests/test_decision_ordering.py` | 多重失败叠加时的固定归类优先级、`now == exp` 临界确定性 |

`auth` / `access` logger 在每次判定时打印**判定依据**（user/sid/jti/required/held）
与**关键令牌状态变化**（签发、轮换 old_jti→new_jti、chain_len、吊销点、冲突）。

## HTTP 接口

### 认证
- `POST /auth/login` `{username,password}` → `{access_token, refresh_token, ...}`
- `POST /auth/refresh` `{refresh_token}` → 全新令牌对（旧刷新令牌立即失效）

### 受保护资源（Bearer Token）
- `GET /docs/{id}` 需要 `doc:read`
- `PUT /docs/{id}` 需要 `doc:write`
- `DELETE /docs/{id}` 需要 `doc:delete`

### 管理端（需要 `admin:revoke`）
- `POST /admin/roles/permissions` `{role,permission}` 角色新增权限
- `DELETE /admin/roles/permissions` `{role,permission}` 角色收窄权限
- `POST /admin/sessions/{sid}/revoke` —— 会话级吊销（`sid` 可从令牌 `sid` 字段得到）
- `POST /admin/revoke/subject/{username}` —— 主体级吊销
- `POST /admin/revoke/all` —— 全局吊销

种子账号：`alice/alice-pw`（admin）、`bob/bob-pw`（editor）、`carol/carol-pw`（viewer）；
种子资源：`doc-1`、`doc-2`。

### 错误码（结论可区分）

所有失败统一返回 `{error, message, reason}`：

| HTTP | error | 含义 |
| --- | --- | --- |
| 401 | `unauthenticated` | 缺少令牌 |
| 401 | `invalid_credentials` | 用户名/密码错误 |
| 401 | `token_tampered` | 结构非法、签名不匹配、算法/类型不支持、访问/刷新令牌混用 |
| 401 | `token_expired` | 已过期（临界规则见下） |
| 401 | `token_revoked` | 会话/主体/全局吊销，或会话已不存在 |
| 401 | `refresh_replayed` | 刷新令牌已被轮换过，再次使用即重放 |
| 409 | `refresh_conflict` | 并发刷新竞争失败（另一个请求已完成轮换） |
| 403 | `forbidden` | 已认证但缺少所需权限（`reason=missing_permission:<p>`） |
| 404 | `resource_not_found` | **权限通过后**才判定的资源缺失 |

## 令牌生命周期

线格式为三段式（类 JWT，标准库 `hmac/hashlib/base64/json` 自实现）：

```
base64url(header).base64url(payload).base64url(HMAC_SHA256(header.payload, secret))
header  = {"alg":"HS256","typ":"LAT1"}
payload = {jti, sub, sid, kind, iat, exp, ver}   # kind ∈ access|refresh
```

- **访问令牌** TTL 15 分钟；**刷新令牌** TTL 7 天（`AuthConfig` 可调）。
- 登录为每个会话签发一对令牌；刷新**轮换**两者，刷新令牌沿单链推进
  `R0 → R1 → R2 …`，会话在任一时刻只记录一个 `current_refresh_jti`。
- 轮换由存储层 CAS 原语 `rotate_refresh(sid, expected, new)` 在全局锁内原子完成：
  仅当 `current == expected` 才切换，旧 jti 入"已使用表"。
- 旧刷新令牌再使用的归类：
  - 若已在已使用表中 → `401 refresh_replayed`（恶意/迟到重放）；
  - 若请求读到"未使用"快照但 CAS 失败 → `409 refresh_conflict`（并发竞争）。
    并发场景下**至多一个请求成功**，失败不回滚、状态不前进两次，会话永远确定。
- 访问令牌不随刷新失效（二者各自独立过期/吊销）；刷新只保证刷新令牌链的唯一性。

### 固定判定顺序（多重失败叠加时无歧义）

```
结构/签名 → 令牌类型 → 过期 → 会话存在性/会话吊销 → 主体|全局吊销 → 重放/冲突(仅刷新)
```
例如"又过期又被吊销"归类为 `token_expired`；"签名非法且主体已吊销"归类为
`token_tampered`——令牌本身先站得住，才讨论吊销/重放。

## 权限与吊销语义

### 访问控制三段式（顺序固定，不可调换）

```
① 认证 authenticate(token)   失败 → 401（到此为止，不泄露资源是否存在）
② 鉴权 required ∈ 实时权限   失败 → 403（资源是否存在都返回 403，防枚举）
③ 资源 store.get_resource    缺失 → 404（仅对有权主体暴露存在性）
```

### 权限模型演进（兼容规则）

- 令牌**不携带权限快照**，只携带身份（`sub`）与会话（`sid`）。
- 每次请求由 `Store.permissions_of(sub)` **实时聚合**角色权限。
  - 角色新增权限：已签发的旧令牌**下一次请求立即获得**；
  - 角色收窄权限：已签发的旧令牌**下一次请求立即失去**，无需重新登录；
  - 判定结果只取决于"当前权限表"，与令牌签发时间无关，可预期、可解释。
- 演进版本字段 `ver` 预留在令牌中；当前策略为实时权限（版本无关）。
  未来若改为快照式权限，可用 `ver` 做平滑兼容。

### 吊销：时间戳语义，三种粒度

| 粒度 | 做法 | 效果 |
| --- | --- | --- |
| 会话 | `revoke_session(sid)` 置会话 `revoked_at` | 该会话全部访问/刷新令牌立即失效 |
| 主体 | 记录 `subject_revoked_at[sub]` | 该主体 `iat ≤ 吊销时间` 的令牌失效 |
| 全局 | 记录 `global_revoked_at` | 所有主体 `iat ≤ 吊销时间` 的令牌失效 |

- 主体级与全局吊销时间取**较晚者**生效。
- 吊销**不阻止重新登录**：吊销点之后签发的新令牌（`iat > revoked_at`）照常可用，
  对应"全部退出登录"后再次登录的直觉。
- 会话吊销是布尔终态：该 sid 下任何令牌（含刷新轮换得到的新令牌）都不可用。

## 时钟与过期的确定性语义

所有时间取自可注入的 `Clock`（测试起点固定为 `1000000.0`），不直接读墙钟：

- 过期判定为 **`now - leeway >= exp` ⇒ 过期**，等号成立即过期，
  因此 `now == exp` 是确定的"已过期"，重复判定结论一致，无随机。
- `leeway`（默认 0）表示可接受的校验方时钟偏移：
  - 校验时钟**快**于权威时钟、偏差在容差内（如快 3s、leeway=5s）：临界请求仍放行；
  - 偏差超出容差：稳定判过期（测试中连续 3 次结论一致）；
  - 校验时钟**慢**：令牌不会提前过期。
- 测试用 `clock.advance(seconds)` 推进权威时间、`clock.set_offset(seconds)`
  模拟校验时钟偏移，精确构造 exp 边界。

## 代码结构

```
app/
  errors.py          # 错误类型 → error 码 / HTTP 状态码
  clock.py           # 可控时钟（推进 / 偏移）
  tokens.py          # Claims、HMAC 签发/验签、过期临界判定
  storage.py         # 线程安全内存存储 + CAS 轮换原语 + 吊销台账 + 实时权限聚合
  auth_service.py    # 登录签发 / 刷新轮换状态机 / authenticate / 吊销
  access_control.py  # 认证→鉴权→资源 三段式 Guard
  api.py             # FastAPI 路由与统一 AuthError 处理
  bootstrap.py       # 种子数据与组装
tests/               # 39 个用例（见上表）
main.py              # ASGI 入口
```
