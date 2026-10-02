# 本地 API 认证与访问控制（Python / FastAPI）

一个**完全本地运行、无外部依赖服务**的认证与访问控制演示：令牌在本地用 HMAC 签发，
身份、角色、权限、会话与吊销台账全部保存在进程内存中。重点是把以下三件事做到
**结论可区分、状态确定、判定依据可在日志中解释**：

1. 访问令牌 / 刷新令牌的签发、刷新轮换（过期、篡改、重试窗口、泄露检测、并发竞争）；
2. 基于角色与权限范围的访问控制（未认证 / 越权 / 资源不存在严格可区分）+ 三种粒度吊销；
3. 权限模型演进的即时语义与时钟偏移下的确定性临界判定。

在此之上，本版本新增**刷新令牌泄露治理**与**会话治理**两块能力：

- **重复使用旧刷新令牌 = 凭证泄露**：已被轮换掉的旧刷新令牌在容忍窗口之外再次出现时，
  从那次登录签发的**整串令牌**（访问 + 刷新）立即作废，结论（`refresh_reuse_detected` /
  `token_family_revoked`）与普通注销、过期、篡改明确区分；
- **重复提交容忍窗口**：客户端网络重试在短窗口内拿回与首次完全相同的一对令牌，
  会话不推进两次，也不误判为泄露；
- **按主体的会话治理**：列出某主体名下会话（不暴露令牌内容）、一次性注销其全部
  存活会话，注销后重新登录即恢复正常。

## 运行

```bash
uv sync                       # 安装依赖（含 pytest/httpx）
uv run uvicorn main:app --reload
# 或：uv run python -c "import uvicorn; uvicorn.run('main:app', port=8000)"
```

打开 http://127.0.0.1:8000/docs 可交互调试。健康检查：`GET /health`。
端到端冒烟：`uv run python scripts/smoke.py`。

## 验证（测试）

```bash
uv run pytest -s -o log_cli=true -o log_cli_level=INFO
# 或安静模式：uv run pytest -q
```

61 个用例，分布：

| 文件 | 覆盖内容 |
| --- | --- |
| `tests/test_token_lifecycle.py` | 登录、过期、签名/负载篡改、令牌类型误用、缺失令牌、过期等号边界、正负时钟偏移与容差 |
| `tests/test_refresh_rotation.py` | 正常轮换、窗口外重用整串作废、作废后全串不可用、8 线程并发只推进一次、刷新过期 |
| `tests/test_refresh_retry_window.py` | 窗口内重试返回同一对令牌、会话不推进、窗口等号边界确定性、窗口不顺延、更早旧令牌不受窗口保护、窗口=0 严格模式 |
| `tests/test_refresh_reuse_detection.py` | 整串作废与常规注销/过期/篡改可区分、只作废出事的一串、重新登录恢复、终态稳定 |
| `tests/test_session_governance.py` | 按主体列会话（无令牌内容）、批量注销与重新登录链路、单会话注销三种结论、401/403/404 判定顺序 |
| `tests/test_concurrent_service.py` | 服务层真实锁内交错，覆盖 `refresh_conflict`（409）竞争分支、串行轮换链的重试与泄露 |
| `tests/test_access_control.py` | 401/403/404 可区分、会话/主体/全局三种吊销、吊销后重新登录、非管理员不能吊销 |
| `tests/test_permission_evolution.py` | 角色权限新增/收窄对**既有令牌**即时生效、逐条独立、轮换令牌同样跟随 |
| `tests/test_decision_ordering.py` | 多重失败叠加时的固定归类优先级、`now == exp` 临界确定性 |

`auth` / `access` logger 在每次判定时打印**判定依据**（user/sid/jti/required/held）
与**关键状态变化**：签发、轮换 old_jti→new_jti、chain_len、重试命中（rotated_at/now/window）、
泄露整串作废时刻、批量注销的 sid 清单、吊销点、冲突。

## HTTP 接口

### 认证
- `POST /auth/login` `{username,password}` → `{access_token, refresh_token, ...}`
- `POST /auth/refresh` `{refresh_token}` → 令牌对（轮换语义见下）

### 受保护资源（Bearer Token）
- `GET /docs/{id}` 需要 `doc:read`
- `PUT /docs/{id}` 需要 `doc:write`
- `DELETE /docs/{id}` 需要 `doc:delete`

### 管理端（需要 `admin:revoke`）
- `POST /admin/roles/permissions` `{role,permission}` 角色新增权限
- `DELETE /admin/roles/permissions` `{role,permission}` 角色收窄权限
- `POST /admin/sessions/{sid}/revoke` —— 会话级注销；响应 `status` 可区分：
  `revoked`（本来活着、刚被注销）/ `already_revoked`（此前已被清掉，附 `revoked_reason`）；
  会话不存在 => 404 `resource_not_found`
- `POST /admin/revoke/subject/{username}` —— 主体级吊销（时间戳语义）
- `POST /admin/revoke/all` —— 全局吊销

### 会话治理（需要 `admin:sessions`）
- `GET /admin/subjects/{username}/sessions` —— 列出该主体全部会话：
  `{sid, subject, created_at, status(active|revoked), revoked_reason, rotations}`，
  **不含任何令牌内容**；主体不存在 => 404
- `POST /admin/subjects/{username}/sessions/revoke` —— 一次性注销该主体名下
  所有仍活着的会话，返回 `{revoked_count, revoked_sids}`；主体不存在 => 404

两个入口都遵循固定判定顺序：未认证 401 → 无权限 403 → 主体不存在 404，
无权主体无法借响应差异探测目标是否存在。

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
| 401 | `token_revoked` | 常规注销（会话/主体/全局吊销），或会话已不存在 |
| 401 | `refresh_reuse_detected` | 旧刷新令牌在容忍窗口外被重复使用：判定泄露，整串令牌已作废 |
| 401 | `token_family_revoked` | 访问令牌所属串已因刷新令牌重复使用被整串作废 |
| 409 | `refresh_conflict` | 并发刷新竞争失败（另一个请求已完成轮换） |
| 403 | `forbidden` | 已认证但缺少所需权限（`reason=missing_permission:<p>`） |
| 404 | `resource_not_found` | **权限通过后**才判定的资源/会话/主体缺失 |

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
  仅当 `current == expected` 才切换，旧 jti 入"已使用表"，并记录最近一次轮换
  （old_jti、签发的那对令牌、rotated_at）供重试窗口判定。
- 访问令牌不随刷新失效（二者各自独立过期/吊销）；刷新只保证刷新令牌链的唯一性。

### 旧刷新令牌再次使用的三种结论（互不混淆）

| 场景 | 结论 | 副作用 |
| --- | --- | --- |
| 容忍窗口内用"上一次刚被换掉的"旧令牌 | 200，**原样返回首次轮换签发的那对令牌** | 无：会话不推进第二次，已使用表不增长 |
| 与轮换并发、读到"未使用"快照后 CAS 失败 | 409 `refresh_conflict` | 无：状态由胜者推进一次 |
| 超出窗口，或使用更早之前的旧令牌 | 401 `refresh_reuse_detected` | **整串作废**：该次登录签发的访问+刷新令牌全部失效 |

### 重复提交容忍窗口（确定性边界）

- 窗口长度 `AuthConfig.refresh_retry_window`（默认 2.0 秒，可配；置 0 即回到严格语义）。
- 判定规则：**`now - rotated_at < window` ⇒ 幂等重试**；**等号即超出窗口**，
  与过期判定"等号即过期"同风格，同一时刻反复判定结论一致。
- 窗口只锚定**首次轮换时刻** `rotated_at`，不因重试而顺延。
- 窗口只覆盖"上一次刚被换掉的"那一任令牌；更早的旧令牌任何时候都按泄露处理。
- 重试返回的是首次成功时签发的**同一对**令牌，客户端可安全继续用它推进轮换。

### 整串令牌失效（泄露语义）与重新登录

- 一旦判定泄露，会话进入吊销终态并标记 `revoked_reason=reuse_detected`：
  - 该串的**访问令牌** => 401 `token_family_revoked`；
  - 该串的**刷新令牌**（含最新一任）=> 401 `refresh_reuse_detected`；
  - 与常规注销（`token_revoked`）、过期（`token_expired`）、篡改（`token_tampered`）
    在错误码层面两两可区分，会话列表中也能看到 `revoked_reason`。
- 只作废**出事的那一串**：同一主体的其他会话、其他主体的会话不受影响。
- 不阻止**重新登录**：新登录签发全新的一串（新 sid），正常使用。

### 固定判定顺序（多重失败叠加时无歧义）

```
结构/签名 → 令牌类型 → 过期 → 会话存在性/会话吊销(含整串作废) → 主体|全局吊销 → 重试/泄露/冲突(仅刷新)
```
例如"又过期又被吊销"归类为 `token_expired`；"签名非法且主体已吊销"归类为
`token_tampered`——令牌本身先站得住，才讨论吊销/泄露。

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

### 吊销：时间戳语义，三种粒度 + 会话级两种原因

| 粒度 | 做法 | 效果 |
| --- | --- | --- |
| 会话 | `revoke_session(sid)` 置会话 `revoked_at` + `revoked_reason` | 该会话全部访问/刷新令牌立即失效 |
| 主体 | 记录 `subject_revoked_at[sub]` | 该主体 `iat ≤ 吊销时间` 的令牌失效 |
| 全局 | 记录 `global_revoked_at` | 所有主体 `iat ≤ 吊销时间` 的令牌失效 |

- 主体级与全局吊销时间取**较晚者**生效。
- 吊销**不阻止重新登录**：吊销点之后签发的新令牌（`iat > revoked_at`）照常可用，
  对应"全部退出登录"后再次登录的直觉。
- 会话吊销是布尔终态：该 sid 下任何令牌（含刷新轮换得到的新令牌）都不可用。
- 会话级失效原因可区分：`admin`（常规注销/批量注销）与
  `reuse_detected`（旧刷新令牌重复使用导致整串作废），
  前者报 `token_revoked`，后者报 `token_family_revoked` / `refresh_reuse_detected`。

## 会话治理用法

```bash
# 列出 bob 的会话（需要 admin:sessions 权限）
curl -H "Authorization: Bearer $ADMIN" http://127.0.0.1:8000/admin/subjects/bob/sessions
# => {"subject":"bob","count":2,"sessions":[{"sid":"sess-1-…","status":"active", …}]}

# 一次性注销 bob 名下所有存活会话
curl -X POST -H "Authorization: Bearer $ADMIN" \
     http://127.0.0.1:8000/admin/subjects/bob/sessions/revoke
# => {"subject":"bob","revoked_count":2,"revoked_sids":["sess-1-…","sess-2-…"]}
# 之后 bob 重新登录即可正常使用，新会话会出现在列表中
```

- 列表只含安全字段（sid、创建时间、状态、失效原因、轮换次数），不暴露令牌内容。
- 批量注销只影响"仍活着"的会话；重复调用返回 `revoked_count=0`，
  与"本次实际注销了 N 个"可区分。
- 判定顺序与资源接口一致：401（未认证）→ 403（无 `admin:sessions` 权限，
  此时目标是否存在都返回 403）→ 404（主体不存在）。

## 与现有能力的兼容范围

- **完全兼容**：登录、访问令牌校验、过期/篡改判定、三种粒度吊销、权限实时聚合、
  并发冲突（409 `refresh_conflict`）、时钟偏移与 leeway 语义，行为与上一版一致。
- **语义变更（有意为之）**：旧刷新令牌再次使用不再一律报 `refresh_replayed`
  （该错误码已移除）——窗口内变为 200 幂等重试，窗口外变为
  401 `refresh_reuse_detected` 并整串作废。需要旧的严格行为时，
  将 `AuthConfig.refresh_retry_window` 置 0，任何重用立即判泄露。
- **响应结构微调**：`POST /admin/sessions/{sid}/revoke` 的响应由
  `{"revoked": bool}` 改为 `{"status": "revoked"|"already_revoked"}`，
  会话不存在时由 200/`false` 改为 404。

## 时钟与过期的确定性语义

所有时间取自可注入的 `Clock`（测试起点固定为 `1000000.0`），不直接读墙钟：

- 过期判定为 **`now - leeway >= exp` ⇒ 过期**，等号成立即过期，
  因此 `now == exp` 是确定的"已过期"，重复判定结论一致，无随机。
- 重试窗口判定为 **`now - rotated_at < window` ⇒ 重试**，等号即超出窗口，
  与过期判定同风格，边界确定。
- `leeway`（默认 0）表示可接受的校验方时钟偏移：
  - 校验时钟**快**于权威时钟、偏差在容差内（如快 3s、leeway=5s）：临界请求仍放行；
  - 偏差超出容差：稳定判过期（测试中连续 3 次结论一致）；
  - 校验时钟**慢**：令牌不会提前过期。
- 测试用 `clock.advance(seconds)` 推进权威时间、`clock.set_offset(seconds)`
  模拟校验时钟偏移，精确构造 exp 边界与重试窗口边界。

## 代码结构

```
app/
  errors.py          # 错误类型 → error 码 / HTTP 状态码
  clock.py           # 可控时钟（推进 / 偏移）
  tokens.py          # Claims、HMAC 签发/验签、过期临界判定
  storage.py         # 线程安全内存存储 + CAS 轮换原语 + 重试窗口判定 + 吊销台账 + 实时权限聚合
  auth_service.py    # 登录签发 / 刷新轮换状态机 / authenticate / 吊销 / 会话治理
  access_control.py  # 认证→鉴权→资源 三段式 Guard
  api.py             # FastAPI 路由与统一 AuthError 处理
  bootstrap.py       # 种子数据与组装
tests/               # 61 个用例（见上表）
main.py              # ASGI 入口
scripts/smoke.py     # 端到端冒烟
```

