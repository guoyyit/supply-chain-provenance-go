# supply-chain-provenance-go

本地软件构建产物来源证明与验证服务。为每个制品（artifact）登记一条或多条来源声明（statement），
声明之间通过内容摘要链接成链，并支持按策略判定制品是否满足发布时间要求。

服务回答四个问题：制品**由谁构建**、**使用哪些材料**、**经过哪些步骤**（均由声明内容承载），
以及声明是否**被篡改、缺失或顺序错误**（由链校验保证）。

## 构建与运行

```bash
go build ./...
go test ./...            # 运行全部测试（含 -race 建议：go test -race ./...）

# 启动本地 HTTP 服务
go run ./cmd/provenanced -addr 127.0.0.1:8080 -dir ./data
```

### HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/v1/artifacts/{id}/statements` | 登记来源声明，body：`{"type":"build","content":{"builder":"ci"}}` |
| GET | `/v1/artifacts/{id}/statements` | 查询声明链 |
| GET | `/v1/artifacts/{id}/verify` | 校验链完整性（409 返回损坏位置与原因） |
| PUT | `/v1/artifacts/{id}/policy` | 设置发布策略 |
| POST | `/v1/artifacts/{id}/evaluate` | 基于当前一致链快照执行策略判定 |

## 声明与摘要算法

每条声明包含：制品标识 `artifact_id`、链内序号 `seq`、声明类型 `type`、
内容 `content`（字符串键值对）、前驱摘要 `prev_hash`、内容摘要 `hash`。

摘要算法（`provenance.ComputeHash`）：

```
hash = SHA-256( canonical(statement) )，输出小写十六进制（64 字符）

canonical(statement) =
    "SCP1\n"                                  -- 域分隔与编码版本前缀
  || uvarint(len(artifact_id)) || artifact_id
  || uvarint(len(type))        || type
  || uvarint(len(prev_hash))   || prev_hash
  || uvarint(len(content 键数))
  || 按键字典序排列的 (uvarint(len(k))||k||uvarint(len(v))||v) 序列
```

设计要点：

- **稳定性**：相同内容必得相同摘要。content 按键字典序编码，与 map 迭代顺序无关。
- **无歧义**：所有字段带 uvarint 长度前缀，`("ab","c")` 与 `("a","bc")` 编码不同，
  杜绝字段拼接造成的碰撞。
- **链式绑定**：`prev_hash` 参与摘要计算，因此摘要同时承诺了声明内容与其在链中的前驱。
- `hash` 与 `seq` 不参与摘要计算（`seq` 由链中位置决定，校验时单独核对）。

## 链结构与校验语义

同一制品的声明按追加顺序链接：第 `i` 条的 `prev_hash` 必须等于第 `i-1` 条的 `hash`，
首条 `prev_hash` 为空（创世）。校验（`Chain.Verify` / `VerifyStatements`）逐条检查：

1. **内容完整性**：`hash == ComputeHash(statement)`，不符则 `tampered`；
2. **链接衔接**：`prev_hash` 等于前一条的 `hash`，不符时区分两种原因（见下）；
3. **序号连续**：`seq` 等于链中位置，不符则 `tampered`。

失败原因（`FailureKind`）可区分，且报错携带出错声明的 `seq`：

| 原因 | 含义 | 触发条件 |
| --- | --- | --- |
| `tampered` | 声明内容被篡改 | 摘要与内容不符，或序号与位置不符 |
| `missing` | 缺少已登记的声明 | `prev_hash` 指向**已登记但不在链中**的声明（如链中被删除一条） |
| `broken_link` | 摘要无法衔接 | `prev_hash` 指向未知摘要，或前驱在链中但位置不相邻（如顺序被打乱） |

### 增量追加与校验缓存

- 追加为 O(1)：只计算新声明自身的摘要，不重算历史。
- `Chain` 记录已校验前缀长度，重复校验只检查新增后缀，开销不随链长度线性增长
  （测试用校验计数器确定性断言，见 `TestLongChainVerificationIsIncremental`）。
- `Chain.VerifyFull` 可忽略缓存做全量校验。

## 策略语义

策略（`Policy`）由有序规则（`Rule`）组成：

```json
{
  "rules": [
    {"name": "built-by-ci", "type": "build", "match": {"builder": "ci"}},
    {"name": "tests-pass",  "type": "test",  "match": {"result": "pass"}},
    {"name": "two-signs",   "type": "sign",  "min_count": 2}
  ]
}
```

判定语义（`Evaluate`，确定性）：

- 规则匹配：声明 `type` 等于规则 `type`，且规则 `match` 中**每个**键都存在于声明
  `content` 且值相等（子集匹配，声明可含额外键）。
- 规则满足：链中匹配声明条数 ≥ `min_count`（缺省/`<=0` 视为 1）。
- 策略满足：**全部**规则满足。判定结果按策略中规则的声明顺序列出每条未满足规则，
  并给出实际匹配条数（`found`）与要求条数（`required`）。
- 空策略（或无策略）无条件通过；空链上任何带规则的策略都不通过。
- 判定结果携带 `statements`（链长度）与 `head_hash`（链头摘要），
  唯一标识判定所基于的链状态；同一策略 + 同一链状态必得同一结论。

## 并发与一致性

- 服务级 `sync.RWMutex`：登记（写）与查询/校验/判定（读）互斥。
- 判定基于**一致快照**：在读锁内拷贝声明切片后立即释放，判定期间并发追加
  不会混入本次结论，也读不到半写入状态（声明先落盘、再在写锁内进入内存）。
- 校验缓存由链级互斥锁保护，支持并发 `Verify`。

## 持久化与崩溃恢复

数据目录包含两个文件：

- `statements.log`：仅追加日志。记录格式为
  `[4 字节大端长度][JSON payload][4 字节 CRC32(payload)]`。
  打开时顺序扫描，遇到不完整或 CRC 不匹配的记录即视为崩溃造成的撕裂尾部并**截断**，
  已提交前缀不受影响；新记录紧接完好前缀追加。
- `policies.json`：策略配置，写临时文件后 `rename` 原子替换，崩溃不留半写文件。

恢复保证：已提交声明不丢失；未完成的追加不留部分写入；策略配置与链状态一致，
因此重启后同一策略对同一链状态的判定结论与崩溃前一致。

## 测试覆盖

```bash
go test -race ./provenance/
```

- 摘要稳定性与字段敏感性（`statement_test.go`）
- 篡改检测与损坏位置、乱序、缺失、断链及其可区分性（`chain_test.go`）
- 策略满足/未满足报告、确定性、匹配语义（`policy_test.go`）
- 撕裂尾部截断、CRC 损坏恢复、跨"进程"状态与结论一致性（`store_test.go`）
- 并发登记+判定的一致性快照、多制品并发、长链增量校验（`service_test.go`）

## 目录结构

```
provenance/           核心库
  statement.go        声明类型与摘要算法
  chain.go            声明链、校验与缓存、失败分类
  store.go            仅追加日志、CRC、崩溃恢复、策略原子持久化
  policy.go           策略模型与确定性判定
  service.go          并发安全的服务门面（快照语义）
cmd/provenanced/      本地 HTTP 服务
```
