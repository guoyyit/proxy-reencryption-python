# 本地代理重加密服务 (Local Proxy Re-Encryption Service)

一套可在本地完整运行、验证的**代理重加密 (Proxy Re-Encryption, PRE)** 服务。数据属主
(Alice) 可以把“面向自己密文的解密能力”委托给被委托人 (Bob)，由一个**半可信代理服务器**
完成密文转换；代理全程接触不到明文，也接触不到任何一方的私钥。支持单向、不可转移、
抗合谋的委托，按单条密文与按时间窗口两种粒度的撤销，重加密密钥的原子轮换，崩溃恢复，
权限控制与全流程审计。

所有能力通过 HTTP 接口暴露，仅依赖本地环境。

---

## 1. 快速开始

```bash
uv sync                      # 安装依赖 (FastAPI / py-ecc / cryptography / httpx / pytest)
uv run pytest                # 运行全部自动化测试 (34 个)
uv run python scripts/demo.py  # 启动真实 HTTP 服务并跑通端到端演示
uv run uvicorn main:app --port 8000   # 手动启动服务
# 交互式 API 文档: http://127.0.0.1:8000/docs
```

数据库位置由环境变量 `PRE_DB_PATH` 控制，默认 `./data/pre_service.db` (SQLite + WAL)。

---

## 2. 安全模型

### 2.1 密码学方案

核心实现位于 `app/crypto.py`，采用经典的 **AFGH06** 代理重加密方案
(Ateniese–Fu–Green–Hohenberg, 2006)，实例化在 **BLS12-381 配对友好曲线**上
(Type-3 双线性配对 `e: G1 × G2 → GT`，使用 `py-ecc` 的 optimized 实现)，DEM 部分使用
**ChaCha20-Poly1305** AEAD，密钥派生使用 HKDF-SHA256。

每个用户持有两个标量私钥分量与对应公钥：

```
sk = (x1, x2)
pk = (g1^x1, Z^x1, g2^x2)          # Z = e(g2, g1)
```

- 属主方向的二级密文（随机数 `r`）：`c1 = g1^r`，DEM 密钥 `K = KDF(Z^(r·x1))`。
- 属主本地生成的**版本化**重加密密钥（`k_v` 是每次轮换生成的盲因子标量）：

```
rk_v   = g2^((x1_a + k_v) · x2_b)   ∈ G2
blind  = g2^k_v                      ∈ G2
blind1 = g1^k_v                      ∈ G1 (仅用于公开校验)
```

- 代理转换（不需要任何私钥，也得不到明文）：

```
c1'   = e(rk_v, c1)   = Z^(r·(x1_a+k_v)·x2_b)
corr  = e(blind, c1)  = Z^(r·k_v)
```

- 被委托人解密时去掉自己的 `x2_b` 指数与公开盲因子：

```
(c1')^(1/x2_b) / corr = Z^(r·x1_a)  => K => 明文
```

### 2.2 安全性质（对应需求条目）

- **非交互、单向**：重加密密钥只由属主用自己的 `x1_a` 和被委托人的*公钥*生成，被委托人
  无需参与、无需出示私钥；只能从 A 转到 B，不能反向。
- **代理不可见明文**：代理只持有 G1/G2 上的群元素与配对运算，重加密密钥是一个群元素而非
  标量私钥；代理无法计算 `Z^(r·x1_a)`，因而无法解密。
- **不可转移 / 抗合谋**：被委托人即使拿到重加密密钥并与代理合谋，也只能得到群元素
  `g2^((x1_a+k_v)·x2_b)`，无法还原属主标量 `x1_a`（基于 G2 上离散对数困难），也无法据此
  伪造面向第三方 C 的重加密密钥。面向 C 的重加密密钥需要 `g2^((x1_a+k')·x2_c)`，合谋方无法
  在不知道 `x1_a` 的情况下构造，且会被公开校验拒绝（见下）。
- **单跳**：转换后的一级密文只含 GT 元素，不能再次作为 `ReEncrypt` 输入，从结构上禁止二次
  转换与链式扩散。
- **重加密密钥公开可校验**：任何人可用两个公钥验证重加密密钥确实是“属主 A → 被委托人 B”的
  良钥（两条配对等式），防止伪造或调包重定向：

```
e(rk.point, g1) == e(pk_B.pk2, pk_A.pk0 + rk.blind1)
e(rk.blind, g1) == e(g2, rk.blind1)
```

> 说明：这里采用的是 AFGH06（配对型 PRE），而不是基于 BBS98 的 Umbral。原因是 Umbral 在
> 单代理场景下，被委托人与代理合谋可以还原属主的标量私钥，不满足本任务第 2 条的抗合谋要求。

### 2.3 错误可区分（对应需求 7）

对格式非法、参数不匹配、被篡改密文一律**显式拒绝**，绝不静默产出无法解密的密文：

| HTTP | error.code | 触发场景 |
| --- | --- | --- |
| 400 | `malformed_ciphertext` | JSON/Base64/字段长度非法，曲线点不在曲线上或不在素数阶子群 |
| 400 | `validation_error` | 参数缺失、版本号不支持、重加密密钥公开校验失败 |
| 400 | `ciphertext_tampered` | AEAD 标签校验失败（密文被改 / 用错密钥 / AAD 不匹配） |
| 401 | `unauthorized` | 缺签名头、签名错误、时间戳偏移、nonce 重放 |
| 403 | `forbidden` | 非属主尝试撤销他人密文等越权 |
| 403 | `ciphertext_revoked` | 命中单条密文撤销 |
| 403 | `revocation_window_active` | 命中生效中的时间窗口撤销 |
| 403 | `delegation_revoked` | 委托被永久撤销 |
| 404 | `not_found` | 用户/委托/密文不存在 |
| 409 | `conflict` | 重复创建委托、密文 id 内容冲突等 |
| 409 | `stale_reencryption_key_version` | 保留：旧密钥转换新密文（由版本门控触发） |

所有曲线点反序列化时都会校验曲线方程与素数阶子群成员关系（G1/G2 子群检查，GT 指数阶检查），
AEAD 以规范化的 AAD（含长度前缀）绑定上下文，防止密文搬移/拼接攻击。

---

## 3. 密钥管理约定

- **服务端永不持有私钥**。PRE 私钥（`x1,x2`）与 Ed25519 签名私钥只存在于客户端
  （见 `app/client.py`）。服务端只存：
  - 用户的 PRE **公钥**（用于公开加密与重加密密钥校验）；
  - 用户的 Ed25519 **验证公钥**（用于验签）。
- **重加密密钥只由数据属主生成**：`PREClient.make_re_encryption_key()` 在本地用属主私钥计算，
  然后把群元素形式的重加密密钥通过已签名请求提交给代理。
- **请求签名**：所有写操作（以及审计查询）用 HTTP 头携带 Ed25519 签名，签名串为

  ```
  METHOD \n PATH \n TIMESTAMP \n NONCE \n SHA256_HEX(BODY)
  ```

  头：`X-User-Id`、`X-Timestamp`（unix 秒，允许 300 秒偏移）、`X-Nonce`、`X-Signature`(hex)。
  nonce 持久化用于防重放；`/crypto/encrypt` 是公开操作（任何人都可用公钥加密）。
- **密钥材料落盘由调用方负责**。`scripts/demo.py` 只在内存中持有；真实使用时应把
  `KeyMaterial` 存到受控的密钥库/加密文件，切勿提交到仓库。

---

## 4. 撤销语义（对应需求 3）

- **按单条密文**：`POST /revocations/ciphertext`。撤销后该密文不能再被转换；已经完成的转换
  结果不受影响、不会被召回。
- **按时间窗口**：`POST /revocations/window`，`target` 可为被委托人 id（对该委托下所有密文
  生效）或某个密文 id；`not_before` / `not_after` 为 UTC ISO8601，端点可为空表示开放。窗口
  生效期间拒绝转换，窗口过后**自动恢复**，无需额外操作。
- **永久撤销委托**：`POST /delegations/revoke`，优先于一切窗口。
- 撤销状态持久化在 SQLite，服务重启后保持（见崩溃恢复）。

---

## 5. 重加密密钥轮换与并发一致性（对应需求 4）

- 每次轮换由属主用新的随机盲因子 `k_v` 生成新版本重加密密钥，版本号单调递增，旧版本全部保留。
- 转换在一个 `BEGIN IMMEDIATE` 事务内**重新锁定读取**委托当前版本并选用对应密钥，轮换同样在
  事务内“插入新版本 + 翻转 current_version 指针”原子完成。因此轮换与转换并发时：
  - 每个转换请求都基于某个**确定版本**的密钥完成；
  - 不会出现旧密钥转换新密文，也不会出现“半应用新密钥”的中间状态；
  - 并发轮换得到互不冲突、单调连续的版本号（唯一约束 + 锁内重读兜底）。
- 自动化覆盖见 `tests/test_concurrency.py`（24 条密文转换与多次轮换并发交错，逐条校验结果可在
  对应版本下解密、版本连续无缺失）。

---

## 6. 持久化与崩溃恢复（对应需求 5）

- SQLite 开启 **WAL + synchronous=NORMAL + foreign_keys**；每个业务变更（含审计写入）都在
  单个事务内提交，保证原子性，不会出现部分写入。
- 写接口支持 `X-Idempotency-Key`：首次成功后的响应被持久化；客户端重试或进程重启后重发同一
  请求会返回**同一结果且不重复应用变更**（nonce 重放与幂等键协同，见 `app/api.py`）。
- 密钥材料（公钥/重加密密钥版本）、委托关系、撤销状态、nonce、审计记录均落盘，重启后继续可用。
- 覆盖见 `tests/test_crash.py`：状态/撤销/审计跨重启保持、幂等重放不产生新版本。

> 注：用户 PRE/签名私钥按设计从不在服务端，因此“在途请求不丢”主要体现在服务端状态与幂等响应上。

---

## 7. 权限控制与审计（对应需求 6）

- 只有数据属主能创建/轮换/撤销自己的委托、撤销自己的密文、为自己的委托加时间窗口（服务端用
  验签后的 `X-User-Id` 与资源 owner 比对，越权返回 `forbidden` 并写拒绝审计）。
- 代理执行的每次转换都写审计（成功/拒绝均记录），与状态变更同事务提交：时间、行为方、动作、
  结果、request-id、详情（密文 id、使用的密钥版本、拒绝原因）。
- `GET /audit?action=&limit=` 返回调用方自己的审计轨迹（代理行为方为 `proxy`）。

---

## 8. HTTP 接口语义

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET  | `/health` | 无 | 健康检查 |
| POST | `/users` | 自证签名 | 注册 `user_id` + Ed25519 验证公钥 + PRE 公钥 |
| POST | `/crypto/encrypt` | 无 | 用已注册属主公钥加密，返回二级密文 JSON |
| POST | `/ciphertexts` | 属主签名 | 登记密文（用于按条撤销/版本门控），支持幂等键 |
| POST | `/delegations` | 属主签名 | 创建委托，body 含 `delegatee_id` 与本地生成的 `re_encryption_key`，服务端公开校验 |
| POST | `/delegations/rotate` | 属主签名 | 提交新版本重加密密钥，返回新版本号 |
| POST | `/delegations/revoke` | 属主签名 | 永久撤销委托 |
| POST | `/revocations/ciphertext` | 属主签名 | 撤销单条密文 |
| POST | `/revocations/window` | 属主签名 | 新增时间窗口撤销 |
| POST | `/reencrypt` | 可选签名 | 代理转换：`owner_id/delegatee_id/ciphertext_id`，返回一级密文与所用版本 |
| GET  | `/audit` | 签名 | 查询审计轨迹 |

密文/公钥/重加密密钥均为自描述 JSON：`{"v":1,"lvl":1|2,...}`，曲线点与 GT 元素采用定长
大端字节 + Base64。

---

## 9. 代码结构

```
app/
  crypto.py       AFGH06/BLS12-381 + AEAD：密钥、加密、重加密密钥、转换、两级解密、公开校验
  errors.py       稳定可区分的错误码
  auth.py         Ed25519 请求签名/验签、时间戳与 nonce
  storage.py      SQLite(WAL)：schema、事务、幂等、nonce、审计
  revocation.py   单条/时间窗口撤销判定
  service.py      业务编排：委托、轮换、转换门控、撤销、审计（事务原子性）
  api.py          FastAPI HTTP 层与统一错误
  client.py       本地客户端：密钥材料、本地生成重加密密钥、签名、加解密
  audit.py        审计动作/结果常量
scripts/demo.py   真实 HTTP 服务端到端演示
tests/            34 个自动化测试（密码学、服务、HTTP、并发轮换、崩溃恢复）
```

## 10. 局限与适用范围

- 本实现面向**本地教学/演示与功能验证**：使用纯 Python 优化配对实现（单次配对约数百毫秒），
  未对侧信道做恒定时间工程化，不应直接用于生产高负载或对抗性主机环境。
- 未实现门限代理（本需求为单代理）；时间以服务器 UTC 为准。
