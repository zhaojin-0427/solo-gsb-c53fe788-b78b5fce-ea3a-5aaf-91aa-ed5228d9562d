# 差分隐私查询预算编排 API

基于 **Python + FastAPI + PostgreSQL** 的差分隐私预算编排服务：客户端上传带
`subject_id` 的版本化记录，在策略（总 epsilon / delta、单主体贡献上限、可用维度）
约束下提交 count / sum 分组查询；服务按主体裁剪贡献、按 delta 选择 Laplace /
Gaussian 机制加噪，并通过**不可变账本**在同一事务内完成预算预占、披露、取消与
重试的记账。内置**策略版本发布与切换**：管理员为策略提交包含 epsilon、delta、
单主体上限和维度的**不可变草案**，凭 `expected_policy_version`
原子发布并切换生效版本；发布 / 撤回未生效草案 / 重复提交均幂等，版本摘要全程
保留；查询提交明确绑定生效版本，旧查询继续按原版本记账与审计重放，新版本预算
**独立核算**，禁止跨版本并发覆盖或原地修改。内置**数据主体擦除**：按 `subject_id` + 截止数据版本登记不可变
墓碑，在同一事务的锁屏障下先确定实际包含该主体的**受影响版本集合**，再统一
按该集合清除原始记录、脱敏查询快照、失效未披露查询并仅退款一次——截止范围
内不含该主体的版本，其查询状态、预算与账本保持不变。审计 API
支持按策略版本重放全部裁剪、噪声与预算明细，并返回可校验的擦除证明。

内置**数据版本封存与内容证明**：幂等 `seal` API 在版本锁内拒绝空版本、冻结
后续上传，把版本内记录按 `record_key` 稳定排序、规范化生成不可变清单并提交
Merkle 根；查询可绑定 `seal_id`，绑定后快照、噪声种子与审计结果锚定同一根；
任意 `record_key` 可出具包含 / 不存在证明及离线校验材料。主体擦除不改写旧
清单，而是向封存版本追加"连接原根、脱敏新根与墓碑证明"的修订链：后续绑定
查询只用最新修订，旧查询仍可核验当时依据且不泄露主体标识。

内置**不可变版本差异证明**：幂等 `POST /seals/compare` 只接受重算校验通过的
修订，把两端清单按 `record_key` 对齐，输出稳定排序的新增 / 删除 /
`subject_hash` 或 `attributes` 变化清单（只含主体哈希，绝不泄露主体标识），
并把两端 seal / revision 哈希、根与差异清单规范化生成 `diff_hash`；
`GET /seals/comparisons/{id}` 返回同一材料，纯标准库脚本
`scripts/verify_diff.py` 可离线重算并拒绝改键、改叶、漏项或跨根材料。

## 一键启动

```bash
docker compose up --build
```

- API: http://localhost:8000 （交互式文档 http://localhost:8000/docs）
- PostgreSQL: `localhost:5432`（用户/密码/库：`dp` / `dp` / `dpdb`）

`docker-compose.yml` 会做两件事保证 schema 就绪：把 `sql/001_schema.sql` 挂入
postgres 的 `docker-entrypoint-initdb.d`（首次启动执行），API 启动时也会幂等地
执行同一脚本。健康检查：`GET /health`。

## 运行测试

```bash
docker compose exec api pytest tests/ -q
```

其中 `tests/test_privacy.py` 为纯逻辑单测（裁剪、敏感度、噪声种子、Merkle
树 / 证明路径与擦除证明哈希的可复现性、策略草案 / 版本摘要哈希），
`tests/test_api.py` /
`tests/test_erasure.py` / `tests/test_seals.py` / `tests/test_compare.py` /
`tests/test_policy_versions.py`
为针对真实 Postgres 的端到端集成测试（分别覆盖预算编排生命周期；擦除范围
判定、幂等与并发；封存、包含 / 不存在证明、绑定查询、擦除修订链与离线校验
脚本；版本差异证明的对齐、幂等、并发与离线差异校验；策略版本草案 / 发布 /
撤回的幂等性、原子切换、版本预算独立核算、旧查询按原版本记账、跨版本并发
与存储层不可变触发器、按版本审计重放）。

## 核心概念

### 策略（Policy）

```json
POST /policies
{
  "name": "analytics",
  "epsilon_total": 10.0,        // 总 epsilon 预算
  "delta_total": 0.001,         // 总 delta 预算（0 = 仅允许纯 DP）
  "per_subject_cap": 2,         // 单主体每次查询最多贡献的记录数
  "dimensions": ["region", "age_band"]   // 允许 group_by / filter 的维度
}
```

策略上的 `version` 是 CAS 令牌：所有预算变更都以
`UPDATE ... SET version = version + 1 ... WHERE id = ? AND version = ?`
形式比较并交换；客户端可携带 `expected_policy_version`，过期即返回
`409 VERSION_CONFLICT`。创建策略时即自动生成一个已发布、不可变的**参数版本 #1**
及其独立预算池（见下节）。

### 策略版本发布与切换（Policy Versions）

管理员可以在不改动任何历史版本的前提下发布新的策略参数版本：

```json
// 1) 提交不可变草案（epsilon / delta / 单主体上限 / 维度）
POST /policies/{policy_id}/versions/drafts
{
  "idempotency_key": "draft-2026-09-27-looser",
  "epsilon_total": 20.0,
  "delta_total": 0.001,
  "per_subject_cap": 3,
  "dimensions": ["region", "age_band", "plan"]
}

// 2) 原子发布并切换为生效版本（可携带两个乐观锁令牌）
POST /policies/versions/drafts/{draft_id}/publish
{
  "expected_policy_version": 7,       // 可选：全局 CAS 令牌 policies.version
  "expected_effective_version": 1     // 可选：发布前应当生效的版本序号
}

// 3) 撤回一个从未生效的草案（幂等）
POST /policies/versions/drafts/{draft_id}/withdraw
```

- **不可变草案**：`policy_versions` 为仅追加表（数据库触发器禁止 UPDATE 内容列
  与 DELETE）；草案一旦提交，其 epsilon / delta / 单主体上限 / 维度永不改变。
  每个草案带内容摘要 `draft_hash`（域分离 SHA-256，对参数规范化，维度排序、
  十进制定点化后再哈希）。
- **原子发布**：在策略行锁内的**同一事务**中为草案分配下一个**连续无洞**的
  `version_seq`、把 `policies.effective_version_seq` 指针切到新版本、全局 CAS 令牌
  `policies.version + 1`，并为新版本建立**全新的独立预算池**
  （`policy_version_budgets`，余额从 0 开始）。已发布版本带版本摘要
  `summary_hash = H("dp-policy-version-v1" ‖ {policy_id, version_seq, spec,
  draft_hash})`，把版本身份与参数绑定成可重算的摘要。
- **幂等**：
  - 同一 `idempotency_key` + 同一草案体重放 → `200` 返回原草案；同键不同体 →
    `409 IDEMPOTENCY_CONFLICT`。
  - **相同参数内容**（相同 `draft_hash`，即使换了幂等键）重复提交 → `200` 返回
    既有草案 / 已发布版本（内容寻址去重）。
  - 已发布草案重复发布 → `200` 返回同一版本；撤回未生效草案可重复调用 → `200`。
  - 已发布版本不可撤回（`409 DRAFT_ALREADY_PUBLISHED`），已撤回草案不可发布
    （`409 DRAFT_WITHDRAWN`），但其参数可以作为**新草案**重新提交。
  - 发布时的 `expected_policy_version` 过期 → `409 VERSION_CONFLICT`；
    `expected_effective_version` 与当前生效版本不符（被并发发布抢先）→
    `409 EFFECTIVE_VERSION_CONFLICT`。

```json
// 发布响应（节选）
{
  "id": "…", "version_seq": 2, "status": "PUBLISHED",
  "epsilon_total": 20.0, "delta_total": 0.001,
  "per_subject_cap": 3, "dimensions": ["region", "age_band", "plan"],
  "draft_hash": "64be…", "summary_hash": "1f9a…",
  "published_at": "2026-09-27T…",
  "budget": {"epsilon_total": 20.0, "epsilon_reserved": 0.0, "epsilon_spent": 0.0,
             "epsilon_available": 20.0, "delta_total": 0.001, …}
}
```

查询接口：

```
GET /policies/{policy_id}/versions                # 全部已发布版本（含各版本预算）+ 开放草案 + 已撤回草案
GET /policies/{policy_id}/versions/{version_seq}  # 单个版本（含 effective 标记与摘要）
```

- **查询明确绑定生效版本**：`POST /queries` 新增可选 `policy_version_seq`
  （缺省 = 提交时刻的生效版本）。新提交只允许绑定**当前生效**版本，显式绑定旧
  版本 → `409 POLICY_VERSION_NOT_EFFECTIVE`。请求摘要包含 `policy_version_seq`，
  因此同一幂等键不能跨版本复用（`409 IDEMPOTENCY_CONFLICT`）。查询的裁剪上限、
  允许维度、delta 合法性、噪声敏感度全部取自绑定版本的参数。
- **旧查询按原版本继续记账**：版本切换后，对旧查询的披露 / 取消 / 擦除失效退款
  仍然计入它所绑定版本的独立预算池；新版本的查询计入新池。旧版本池在切换后
  **冻结为仅由旧查询驱动**，新预算永远从新版本池扣减——新版本预算独立核算。
- **禁止跨版本并发覆盖 / 原地修改**：所有预算变更与发布都先取策略行锁（全局唯一
  串行点），再取版本池行锁；全局锁顺序为
  **策略行 → 擦除屏障 → 数据版本锁 → 查询行**，因此跨版本并发提交 / 披露 /
  擦除不会互相覆盖，也不会死锁。预算只在 `policy_version_budgets` 上更新，
  `policies` 表的余额列在 v1 之后保持为版本 #1 的冻结镜像；策略版本行只追加、
  触发器禁止任何原地修改。
- **审计按版本重放**：`GET /audit/policies/{policy_id}/replay` 新增
  `version_seq` 参数（缺省 = 生效版本）。账本仍是**每条策略一条全局哈希链**，
  每条记录带 `policy_version_seq`；重放时先校验到 `to_version` 为止的整条全局链，
  再只用该版本自己的账目独立重建该版本余额（跨版本条目跳过但仍参与链校验），
  并给出 `scope_consistent` 与每版本 `reconstruction_consistent`。旧版本可随时
  重放，旧查询的裁剪、噪声、预算与版本摘要均按原版本复现。

### 版本化记录上传

```json
POST /records
{
  "dataset_version": 1,
  "records": [
    {"record_key": "r1", "subject_id": "alice", "attributes": {"region": "us", "value": 5}},
    {"record_key": "r2", "subject_id": "bob",   "attributes": {"region": "eu", "value": 11}}
  ]
}
```

`(dataset_version, record_key)` 唯一，重复上传幂等（返回 `inserted` /
`duplicates` 计数）。若主体已在墓碑范围内被擦除（见下文「数据主体擦除」），
上传整体拒绝并返回 `409 SUBJECT_ERASED`；若版本已被封存（见下文「数据版本
封存」），上传整体拒绝并返回 `409 VERSION_SEALED`。

### 数据版本封存与内容证明（Seal）

```json
POST /seals
{
  "idempotency_key": "seal-2026-09-22-ds1",
  "dataset_version": 1
}
```

一次封存在**同一事务、同一版本锁**内完成：拒绝空版本（`409 VERSION_EMPTY`），
读取版本内全部记录，按 `record_key` 稳定排序并规范化为清单叶子，提交 Merkle
根（修订 #0），并**冻结该版本的后续上传**（`409 VERSION_SEALED`）。

- **幂等**：同 `idempotency_key` + 同版本重放返回 `200` 与原封存；同键不同
  版本 → `409 IDEMPOTENCY_CONFLICT`；不同键封存同版本 → `409 VERSION_SEALED`
  （`details.seal_id` 指向既有封存）。
- **清单叶子**：`{"record_key", "subject_hash", "attributes"}`——只提交主体
  的域分离哈希（与擦除墓碑同一哈希域），**绝不提交原始主体标识**，因此旧
  清单在擦除后仍可公开核验而不泄露主体。
- **哈希规约**（`hash_version = "v1"`，域分离 SHA-256）：

  ```
  leaf     = sha256("dp-seal-leaf-v1|"     + canonical_json(leaf))
  node     = sha256("dp-seal-node-v1|"     + left_hex + "|" + right_hex)
  root     = 自叶向上折叠，奇数层复制最后一个节点；空清单 = sha256("dp-seal-empty-root-v1")
  revision = sha256("dp-seal-revision-v1|" + canonical_json(revision))
  canonical_json = JSON 键排序、紧凑分隔符、UTF-8
  ```

- `version_seals` / `seal_revisions` 均为仅追加表（数据库触发器禁止
  UPDATE/DELETE），清单与根不可变。

```json
// 201 响应（节选）
{
  "seal_id": "…",
  "dataset_version": 1,
  "revision_seq": 0,
  "root": "2d81…",            // 修订 #0 的 Merkle 根
  "record_count": 5,
  "revision_hash": "9c04…",
  "hash_version": "v1"
}
```

查询接口：

```
GET /seals                                   # 全部封存 + 最新修订 + 校验结论
GET /seals/{seal_id}                         # 完整修订链，逐修订重算根/哈希/链式链接
GET /seals/{seal_id}/manifest?revision=N     # 某修订的完整清单（默认最新）
GET /seals/{seal_id}/records/{record_key}/proof?revision=N
```

证明接口对**存在的** `record_key` 返回包含证明（叶子、叶索引、Merkle 兄弟
路径），对**不存在的**返回不存在证明；两者都自带按 `record_key` 稳定排序的
**完整规范叶子 `leaves`**、并行的 `record_keys` / `leaf_hashes`、根、修订哈希
与 `hash_version`，是完整的**离线校验材料**。

- **键名与承诺叶逐项绑定**：每个叶哈希都由包含 `record_key` 的规范叶子算出
  （`leaf = H("dp-seal-leaf-v1|" + canonical_json({record_key, subject_hash,
  attributes}))`）。校验方只信任 `leaves`——逐叶重算叶哈希、再折叠出
  Merkle 根，并要求并行的 `record_keys` / `leaf_hashes` 与重算结果**逐项相等**，
  最后重算修订哈希把根锚入修订链。独立的键名表本身不被单独采信，因此**在根不变
  的前提下，仅从 `record_keys` 删键、调换顺序、改名或替换叶哈希，都无法把一个
  实际已封存的键伪造成不存在**（叶哈希与其键名绑定，任何篡改都会使重算根或
  逐项校验失败）。
- 不存在证明的判定即「该 `record_key` 不在由 `leaves` 推出的键名集合中」；
  包含证明额外校验叶子、`leaf_index` 与 Merkle 兄弟路径折叠到根。
- 旧版（绑定修复前）的包含证明因自带完整叶子与兄弟路径仍可离线核验；旧版
  不存在证明只有与叶哈希相互独立的键名表、不可绑定，校验器会拒绝并要求重新
  拉取当前接口的材料。**已封存修订与擦除修订的根、修订哈希均未重写**，旧修订
  仍可通过 `manifest` / `chain` 模式及当前 `proof` 接口逐项核验。

**离线校验**（纯标准库，无需服务与依赖）：

```bash
curl -s localhost:8000/seals/$SEAL/manifest            > manifest.json
curl -s localhost:8000/seals/$SEAL/records/r1/proof    > proof.json
curl -s localhost:8000/seals/$SEAL                     > chain.json
python3 scripts/verify_proof.py manifest manifest.json   # 重算叶子→根→修订哈希
python3 scripts/verify_proof.py proof    proof.json      # 校验键↔叶绑定，折叠路径/验证不存在
python3 scripts/verify_proof.py chain    chain.json      # 校验整条修订链链接
```

退出码 `0` = 校验通过，`1` = 校验失败（含材料被篡改或为不可绑定的旧版不存在
证明），`2` = 用法 / 输入错误。`proof` 模式会逐叶重算并核对键名、顺序与叶哈希，
因此对一份真实存在的键，任何「保留真根与真叶哈希、只改键名表」的篡改都会以
退出码 `1` 失败。

### 版本差异证明（Seal Compare）

```json
POST /seals/compare
{
  "idempotency_key": "cmp-2026-09-26-ds1-r0-r1",
  "left":  {"seal_id": "…", "revision_seq": 0},
  "right": {"seal_id": "…", "revision_seq": 1}
}
```

一次比较在**同一事务**内完成：先逐端重算校验两个修订（从存储清单重算
Merkle 根、重算修订哈希、核对链式链接），**只有全部通过的已验证修订才允许
比较**（任一端不可验证 → `409 SEAL_REVISION_UNVERIFIED`）；随后把两端清单
按 `record_key` 对齐，生成稳定排序（按 `record_key` 升序）的规范差异：

- `added`：仅右端存在的键（附右端叶子）；
- `removed`：仅左端存在的键（附左端叶子）；
- `changed`：两端都有但 `subject_hash` 或 `attributes` 不同的键（附
  `changes` 字段清单与完整 `from` / `to` 叶子）；
- `counts`：新增 / 删除 / 变化 / 未变（`unchanged`）计数。

差异只携带主体的域分离哈希，**绝不泄露 `subject_id`**。两端 seal /
revision 哈希、根与差异清单规范化后生成不可变差异证明哈希：

```
diff_hash = sha256("dp-seal-diff-v1|" + canonical_json({
  "left":  {"seal_id", "revision_seq", "revision_hash", "root"},
  "right": {"seal_id", "revision_seq", "revision_hash", "root"},
  "diff":  {"added", "removed", "changed", "counts"}}))
```

- **幂等**：同 `idempotency_key` + 同请求重放返回 `200` 与原比较；同键
  不同请求（含左右互换）→ `409 IDEMPOTENCY_CONFLICT`；并发重复提交由唯一
  幂等键串行化，只有一个 `201`，其余重放同一结果。比较只读不可变修订，
  因此幂等键是唯一串行点。
- **不可变**：`seal_comparisons` 为仅追加表（数据库触发器禁止
  UPDATE/DELETE），差异证明落库后不可改写。
- **同一材料**：`GET /seals/comparisons/{comparison_id}` 返回与 POST 响应
  完全相同的材料（两端修订字段 + 完整承诺叶子、规范差异、`diff_hash`），
  并在每次读取时重新校验（`verification = VERIFIED / UNVERIFIABLE`）；
  未知 id → `404 COMPARISON_NOT_FOUND`。

```json
// 201 响应（节选）
{
  "comparison_id": "…",
  "hash_version": "v1",
  "left":  {"seal_id": "…", "revision_seq": 0, "root": "2d81…",
            "revision_hash": "9c04…", "leaves": [ … ]},
  "right": {"seal_id": "…", "revision_seq": 1, "root": "b77e…",
            "revision_hash": "e2a1…", "leaves": [ … ]},
  "diff": {
    "added":   [{"record_key": "r5", "leaf": { … }}],
    "removed": [{"record_key": "r1", "leaf": { … }}],
    "changed": [{"record_key": "r3", "changes": ["attributes"],
                 "from": { … }, "to": { … }}],
    "counts":  {"added": 1, "removed": 1, "changed": 1, "unchanged": 2}
  },
  "diff_hash": "6e93…",
  "verification": "VERIFIED"
}
```

**离线差异校验**（纯标准库，无需服务与依赖）：

```bash
curl -s -X POST localhost:8000/seals/compare -H 'content-type: application/json' \
  -d '{"idempotency_key":"cmp-1","left":{"seal_id":"'$S1'","revision_seq":0},
       "right":{"seal_id":"'$S2'","revision_seq":0}}'      > comparison.json
curl -s localhost:8000/seals/comparisons/$CID              > fetched.json
python3 scripts/verify_diff.py comparison.json   # 或 ... fetched.json / 管道 "-"
```

校验器只信任两端承诺的 `leaves`：逐叶重算叶哈希并折叠出两个 Merkle 根
（**跨根材料**——从别的根搬来的叶子——在此失败），重算两个修订哈希把材料
锚入不可变修订链，再从叶子**独立重推**规范差异并要求与材料中的 `diff`
逐项相等（**改键**、**改叶**、**漏项**都会破坏该等式），最后重算
`diff_hash`。退出码 `0` = 校验通过，`1` = 校验失败，`2` = 用法 / 输入错误。

### 绑定封存的查询

`POST /queries` 增加可选字段 `seal_id`（缺省即未绑定，语义与原来完全一致）：

```json
{
  "idempotency_key": "report-2026-09-22-us-count",
  "policy_name": "analytics",
  "dataset_version": 1,
  "seal_id": "…",                  // 必须覆盖 dataset_version，否则 422 SEAL_VERSION_MISMATCH
  "query_type": "count",
  "group_by": ["region"],
  "epsilon": 1.0,
  "delta": 0.0
}
```

绑定查询在提交时刻**锚定该封存的最新修订**，快照、噪声种子与审计结果全部
绑定同一 Merkle 根：

- **快照**：从该修订的不可变清单计算（而非活表），裁剪明细中的主体以
  伪名哈希出现，原始标识从不进入绑定快照；响应与审计视图带
  `seal: {seal_id, revision_seq, root}`。
- **噪声种子**：`SHA256("dp-noise-seal-v1" ‖ idempotency_key ‖ request_digest ‖ root)`，
  根不同则种子不同，重试 / 重启仍逐位可复现。
- **审计**：重放视图逐查询重算清单根、修订哈希与噪声种子并给出
  `seal.verification = VERIFIED / UNVERIFIABLE`。
- 请求摘要包含 `seal_id`：同一幂等键不能一会儿绑定一会儿不绑定
  （`409 IDEMPOTENCY_CONFLICT`）。
- 封存 + 绑定查询与上传 / 擦除在同一版本锁屏障下串行化，并发下**绝不
  产生跨根快照**：绑定查询永远精确锚定某一个修订的根。

### 查询生命周期

```
            submit                disclose                 cancel
  (key)  ──────────►  RESERVED  ──────────►  DISCLOSED
                         │                                       
                         ├──────────────►  CANCELLED（仅披露前，仅退款一次）
                         │                                       
                         └──────────────►  INVALIDATED（主体擦除，仅退款一次）
```

1. **提交（预占）** `POST /queries`

```json
{
  "idempotency_key": "report-2026-09-21-us-count",
  "policy_name": "analytics",
  "expected_policy_version": 3,        // 可选 CAS 令牌（全局 policies.version）
  "policy_version_seq": 2,             // 可选：绑定的策略参数版本，须为当前生效版本
  "dataset_version": 1,
  "query_type": "count",               // 或 "sum"（需 measure + value_min/value_max）
  "group_by": ["region"],
  "filters": {"age_band": "30-39"},
  "epsilon": 1.0,
  "delta": 0.0                          // 0 → Laplace；>0 → Gaussian
}
```

   - 按主体裁剪：每个 subject 按记录 id 升序最多保留 `per_subject_cap` 条
     （确定性、可重放）；sum 查询再把每条值裁剪到 `[value_min, value_max]`。
   - 敏感度：count = `cap`；sum = `cap × max(|min|, |max|)`。
   - 噪声：`delta = 0` → Laplace(`sens/ε`)；`delta > 0` →
     Gaussian(`sens·√(2 ln 1.25/δ)/ε`)。
   - 噪声种子 = `SHA256(idempotency_key ‖ request_digest)`，每组再派生子种子，
     重试 / 重启后噪声逐位可复现。
   - 同事务完成：CAS 扣减可用预算（`reserved += ε,δ`）+ 写入账本 `RESERVE`，
     预占计入查询所绑定参数版本的独立预算池。
   - 冲突语义：预算不足 → `409 BUDGET_EXCEEDED`；同幂等键不同摘要 →
     `409 IDEMPOTENCY_CONFLICT`；版本过期 → `409 VERSION_CONFLICT`；显式绑定
     非生效参数版本 → `409 POLICY_VERSION_NOT_EFFECTIVE`；
     同键同摘要 → `200` 返回原查询并记一条 `RETRY` 账本（不重复占预算）。

2. **披露** `POST /queries/{id}/disclose`

   同事务把 `reserved` 转为 `spent`（累计消耗 epsilon/delta），账本写
   `DISCLOSE`，返回噪声结果（仅 noisy 值）。重复披露幂等返回相同结果。

3. **取消** `POST /queries/{id}/cancel`

   仅限披露前；同事务退还预占并写 `CANCEL`（负 delta）。已披露 →
   `409 CANCEL_WINDOW_CLOSED`；重复取消 → `409 REFUND_ALREADY_ISSUED`
   （只能返还一次）。

### 数据主体擦除（Tombstone Erasure）

```json
POST /erasures
{
  "idempotency_key": "gdpr-req-2026-09-21-alice",
  "subject_id": "alice",
  "until_dataset_version": 5        // 截止数据版本（含）
}
```

一次擦除在**同一事务**内完成：先在擦除锁屏障下确定**受影响版本集合**
`affected_dataset_versions` —— 截止范围内该主体实际拥有记录的版本，与
存储快照确实引用该主体的版本的并集；随后所有副作用统一只作用于该集合。
**截止范围内但不含该主体的版本，其查询状态、预算与账本保持完全不变。**

1. **登记墓碑**：写入仅追加的 `erasure_tombstones`（数据库触发器禁止
   UPDATE/DELETE）。墓碑只存主体的域分离 SHA-256 哈希
   （`subject_hash`）与受影响版本集合，**不存原始主体标识**。
2. **清除原始记录**：删除该主体在受影响版本上的全部记录。
3. **清洗查询快照**：把受影响版本上引用该主体的查询快照
   （`clipping.subjects`）中的主体标识替换为 `[erased]`；已披露的噪声
   结果与既有账本条目**保持不变**。
4. **失效未披露查询**：受影响版本上仍为 `RESERVED` 的查询转为
   `INVALIDATED`，同事务内**仅返还一次**预占预算（`reserved -= ε,δ`）
   并向对应策略的哈希账本追加 `INVALIDATE` 条目（负 delta）。已披露 /
   已取消的查询，以及无主体版本上的查询，均不受影响。
5. **追加封存修订链**：受影响版本若已封存，**不改写旧清单**，而是向该
   封存的修订链追加一条 `erasure` 修订——连接前一修订哈希（原根所在
   链）、移除该主体叶子后的脱敏新清单与新 Merkle 根，并引用本墓碑。
   之后的绑定查询只锚定最新修订；锚定旧修订的查询仍可核验当时依据
   （旧清单本就只含主体哈希，不泄露主体标识）。若最新清单中已无该主体
   （此前擦除已处理），该封存跳过、不产生空转修订。

```json
// 201 响应（节选）：回执即擦除证明，绝不返回原始主体标识
{
  "tombstone_id": 7,
  "subject_hash": "9f2c…",
  "until_dataset_version": 5,
  "affected_dataset_versions": [2, 5],   // 实际含该主体的版本集合
  "records_deleted": 4,
  "queries_invalidated": 1,
  "snapshots_scrubbed": 2,
  "affected_queries": [{"query_id": "…", "ledger_seq": 11, "refunded": {"epsilon": 1.0, "delta": 0.0}}],
  "seal_revisions": [{"seal_id": "…", "dataset_version": 5, "revision_seq": 1,
                      "prev_revision_hash": "9c04…", "root": "b77e…",
                      "record_count": 3, "revision_hash": "e2a1…"}],
  "proof_hash": "c41a…"
}
```

语义要点：

- **范围判定**：失效、脱敏、退款与证明哈希按"实际包含该主体的版本
  集合"执行，而不是简单的 `dataset_version <= 截止值`。某版本只要
  在截止范围内存有该主体的记录（或其快照引用了该主体）即属受影响；
  反之，即使版本号在截止范围内，只要不含该主体，其 `RESERVED` 查询
  不会被失效、预算不会被退款、账本不会新增条目。
- **幂等**：同 `idempotency_key` + 同请求体重放返回 `200` 与原墓碑
  （含相同的 `affected_dataset_versions`，不重复删除、不重复退款）；
  同键不同请求体 → `409 IDEMPOTENCY_CONFLICT`。
- **禁止再上传**：墓碑范围内（同主体、`dataset_version <= 截止版本`）的
  上传整体拒绝 → `409 SUBJECT_ERASED`；超出截止版本的上传不受影响。
- **按数据版本串行化**：擦除、上传与查询提交通过事务级咨询锁串行化
  （上传/提交持共享擦除锁 + 独占版本锁，擦除持独占擦除锁）。受影响
  版本集合在同一锁屏障下确定，擦除不会与在途的上传/提交交错，因此
  失效扫描不会遗漏新查询，删除不会遗漏新记录；并发擦除互斥，
  `RESERVED → INVALIDATED` 单向迁移保证并发重试绝不重复退款。擦除
  提交后新提交的查询基于已擦除数据计算，保持有效。
- **失效后**：`INVALIDATED` 查询不可披露（`409 QUERY_INVALIDATED`）、不可
  再取消（`409 REFUND_ALREADY_ISSUED`）；同幂等键重试提交返回原查询
  （`200`，状态 `INVALIDATED`，不再占预算）。客户端可换新幂等键重新提交，
  在擦除后的数据上计算。
- **擦除证明**：墓碑的 `proof_hash` 绑定了墓碑 id、主体哈希、截止版本、
  **受影响版本集合**、各项计数、被失效查询清单（含账本序号）以及追加的
  **封存修订链接**（原修订哈希、新根、修订哈希），审计时可重算校验；
  `GET /audit/erasures` 同时逐条重算封存修订的根、修订哈希、链式链接与
  墓碑引用（`VERIFIED` / `UNVERIFIABLE`）。

### 不可变账本

`budget_ledger` 仅允许追加（数据库触发器禁止 UPDATE/DELETE）。每条记录：
操作类型、ε/δ 有符号增量、**所属策略参数版本** `policy_version_seq`、操作后四项
余额、前序哈希与条目哈希（SHA-256 链，创世哈希为 64 个 `0`）。一条策略只有一条
全局哈希链，跨参数版本的账目交错链接、不可分叉；各版本的余额则按
`policy_version_seq` 独立重建。RESERVE / DISCLOSE / CANCEL / RETRY /
INVALIDATE 五类事件与对应余额变更在**同一事务**内落库。

### 审计重放

```
GET /audit/policies/{policy_id}/replay?to_version=5&version_seq=2
```

- `version_seq`（缺省 = 当前生效版本）选择要重放哪个参数版本的独立预算池。
- `entries`：按账本序号稳定排序，逐条给出 ε/δ 增量、操作后余额、`policy_version_seq`
  与哈希校验结果；校验失败或余额重建不一致的条目标记 `UNVERIFIABLE`。重放先
  校验到 `to_version` 为止的整条全局链（`chain.verified`），再确认作用域内条目
  都正确锚定全局链（`chain.scope_consistent`）。
- `budget`：仅由该版本自己的条目重建的版本池余额及 `reconstruction_consistent`；
  `live_budget` 给出该版本池的当前权威余额与可用量。
- `policy_version`：被重放版本的不可变参数、`draft_hash` / `summary_hash` 与
  `effective` 标记。
- `queries`：只包含绑定到该版本的查询，裁剪明细（按 subject 稳定排序，已擦除
  主体显示为 `[erased]`）、噪声参数（机制 / 敏感度 / scale / 种子）、预算明细；截至
  重放版本尚无 DISCLOSE/CANCEL/INVALIDATE 事件的查询标记
  `outcome = INDETERMINATE`（`determinate = false`），并给出 `reason`
  （无法判定原因）与 `later_events_beyond_replay` 提示；被擦除失效的查询
  标记 `INVALIDATED` 并附 `erasure` 引用（墓碑 id、主体哈希、擦除证明）；
  绑定封存的查询附 `seal` 块（锚定的修订序号与 Merkle 根、重算清单根 /
  修订哈希 / 噪声种子的逐项校验与 `VERIFIED` / `UNVERIFIABLE` 结论）。
- `chain`：整条哈希链的校验结论。

### 擦除审计

```
GET /audit/erasures
```

返回全部墓碑：主体哈希（**绝不返回已擦除主体标识**）、截止版本、
**受影响版本集合**、删除 / 失效 / 清洗计数、受影响查询清单（含各自
账本序号与退款金额）、追加的**封存修订链接**（逐条重算根、修订哈希、
链式链接与墓碑引用）、`proof_hash` 及重算校验结论（`VERIFIED` /
`UNVERIFIABLE`）。

## 错误码一览

| HTTP | code | 含义 |
| --- | --- | --- |
| 404 | `POLICY_NOT_FOUND` / `QUERY_NOT_FOUND` / `DRAFT_NOT_FOUND` / `POLICY_VERSION_NOT_FOUND` / `SEAL_NOT_FOUND` / `SEAL_REVISION_NOT_FOUND` / `COMPARISON_NOT_FOUND` | 资源不存在 |
| 409 | `POLICY_EXISTS` | 策略名重复 |
| 409 | `IDEMPOTENCY_CONFLICT` | 幂等键被不同摘要复用 |
| 409 | `BUDGET_EXCEEDED` | 绑定版本的预算（ε 或 δ）不足 |
| 409 | `VERSION_CONFLICT` | 策略全局 CAS 令牌冲突 |
| 409 | `EFFECTIVE_VERSION_CONFLICT` | 发布时生效版本与 `expected_effective_version` 不符（被并发发布抢先） |
| 409 | `POLICY_VERSION_NOT_EFFECTIVE` | 新查询显式绑定了非当前生效的参数版本 |
| 409 | `DRAFT_WITHDRAWN` | 草案已撤回，不能发布（同参数可重新提交为新草案） |
| 409 | `DRAFT_ALREADY_PUBLISHED` | 已发布版本不可撤回 |
| 409 | `CANCEL_WINDOW_CLOSED` | 披露后不可取消 |
| 409 | `REFUND_ALREADY_ISSUED` | 重复退款（含擦除已退款） |
| 409 | `QUERY_CANCELLED` | 已取消的查询不可披露 |
| 409 | `QUERY_INVALIDATED` | 已被擦除失效的查询不可披露 |
| 409 | `SUBJECT_ERASED` | 主体已擦除，墓碑范围内禁止再上传 |
| 409 | `VERSION_EMPTY` | 空数据版本拒绝封存 |
| 409 | `VERSION_SEALED` | 版本已封存：上传被冻结 / 版本已被其他键封存 |
| 409 | `SEAL_REVISION_UNVERIFIED` | 修订重算校验未通过，拒绝参与差异比较 |
| 422 | `SEAL_VERSION_MISMATCH` | `seal_id` 覆盖的数据版本与请求不符 |
| 422 | `DIMENSION_NOT_ALLOWED` / `MEASURE_REQUIRED` / `VALUE_BOUNDS_REQUIRED` / `DELTA_NOT_ALLOWED` … | 请求不合法 |

错误统一为 `{"error": {"code", "message", "details"}}`。

## 项目结构

```
├── docker-compose.yml      # db (postgres:16) + api (uvicorn)
├── Dockerfile
├── requirements.txt
├── sql/001_schema.sql      # 手写 DDL：表、约束、不可变账本/墓碑/封存/差异/策略版本触发器
├── scripts/
│   ├── verify_proof.py     # 离线校验：清单根 / 键↔叶绑定的包含·不存在证明 / 修订链（纯标准库）
│   └── verify_diff.py      # 离线差异校验：重算两端根、修订哈希、规范差异与 diff_hash（纯标准库）
├── app/
│   ├── main.py             # 应用工厂、启动时幂等建表、错误封装
│   ├── config.py / db.py   # 环境配置、引擎与会话
│   ├── models.py           # SQLAlchemy ORM（含 PolicyVersion / PolicyVersionBudget）
│   ├── schemas.py          # Pydantic 请求模型（含草案 / 发布 / 查询版本绑定）
│   ├── privacy.py          # 裁剪、敏感度、Laplace/Gaussian、种子、Merkle 树、证明、差异与策略版本哈希（纯函数）
│   ├── services.py         # 事务核心：CAS、版本草案/发布/撤回、按版本池记账、披露/取消、封存、差异、擦除、审计重放
│   ├── presenters.py       # 响应塑形
│   └── routers/            # policies（含版本草案/发布/撤回）/ records / seals / queries / erasures / audit
└── tests/                  # 纯逻辑单测 + 端到端集成测试（含策略版本、擦除、封存、差异比较与并发）
```
