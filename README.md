# supply-chain-provenance-go

本地软件构建产物来源证明（provenance）与验证服务。为每个制品（artifact）登记一条或多条来源声明（statement），声明通过内容摘要链接成防篡改链，并依据策略（policy）判定制品是否满足发布要求。

服务回答四个问题：制品**由谁构建**（statement 的 `subject`）、**使用哪些材料**（`material` 声明）、**经过哪些步骤**（声明按追加顺序成链）、以及**声明是否被篡改、缺失或顺序错误**（链校验给出可区分的失败原因与位置）。

## 构建与运行

```sh
go build ./...
go test ./...            # 单元与集成测试
go test -race ./...      # 含并发竞争检测
go run ./cmd/provenanced -addr :8080 -dir ./data
```

## 摘要算法

- 算法：**SHA-256**，文本形式为 `sha256:<64 位小写十六进制>`。
- 输入：声明的**规范化 JSON**（canonical JSON）。规范化规则：对象键按字典序输出、无冗余空白、结构体字段按固定声明顺序。因此**相同内容的声明在任何进程、任何时刻计算出完全相同的摘要**（时间戳由登记方传入并归入内容，避免隐式时钟造成不稳定）。
- 覆盖范围：摘要覆盖 `artifact_id`、`type`、`subject`、`content`、`sequence`、`prev_digest`、`timestamp`——即除 `digest` 自身外的全部字段。`sequence` 与 `prev_digest` 参与摘要，使**删除、插入、重排**任何声明都会破坏后续摘要知道链尾。

## 链式链接与校验

每个制品一条只增链。位置 `i`（从 0 计）的声明必须满足：

1. `sequence == i+1`；
2. `prev_digest ==` 前一条声明的 `digest`（首条为空）；
3. `digest ==` 其内容的 SHA-256。

校验从头逐条检查，发现第一处损坏即返回 `VerificationError`，包含**零基位置**与**可区分的原因**：

| 原因 | 含义 |
|---|---|
| `tampered` | 声明内容被改动，存储摘要与重算摘要不一致 |
| `missing_statement` | 序号出现空洞，某条已登记声明缺失 |
| `broken_link` | `prev_digest` 无法衔接前一条声明（重排/断链） |
| `sequence_mismatch` | 序号未从 1 连续递增（保留给外部构造的链） |

**增量校验缓存**：服务记住每条链"已验证长度"。再次校验只检查新增声明，代价与新增数量成正比而非链长；追加新声明也只需计算该声明自身的摘要，不重算历史。缓存仅在内存中，进程重启后自动失效并从头校验，因此重启后对磁盘的篡改必然被发现。

## 策略语义

策略 `Policy` 由有序规则 `Rule` 组成，判定结果确定：

- 每条规则声明一个所需的 `statement_type` 与零个或多个条件 `Condition`（`field`、`op`、`value`）。
- 条件操作符：`exists`（字段存在）、`equals`（精确相等）、`contains`（子串包含）。一条声明须满足规则的**全部**条件（AND）。
- 一条规则被满足，当且仅当链中**至少一条**该类型声明满足全部条件（存在量词）。
- 策略通过，当且仅当**全部**规则被满足；空策略 vacuously 通过。
- 判定按链顺序扫描、按策略声明顺序报告，`PolicyResult.failed_rules` 列出**每一条**未满足的规则及原因；同一链状态重复判定结果完全一致。
- 判定前先执行链校验：链损坏时判定拒绝进行并返回校验错误。每次判定结果（含所基于的 `chain_head` 与链长）持久化到 `results.wal`，重启后历史结论保持一致。

## 并发模型

单一 `sync.RWMutex` 保护链集合、策略与校验缓存。登记声明是"计算摘要 + 追加 + fsync"的原子单元（写锁）；读取与快照使用读锁且返回防御性拷贝。任一策略判定只基于**某一个一致的链状态**，不会读到半写入或跨声明混合状态。

## 持久化与崩溃恢复

数据目录下三个文件：

- `statements.wal`：声明提交日志。记录帧为 `magic(4B) + CRC32(4B) + length(4B) + JSON payload`，**写入并 fsync 后才算提交**。恢复时顺序扫描，在第一条损坏/撕裂记录处截断——崩溃不会留下部分写入，已提交声明不丢失。
- `results.wal`：策略判定结论日志，同样的帧格式与恢复语义。
- `policy.json`：当前策略，通过"写临时文件 + fsync + rename + fsync 目录"原子替换——崩溃后只会看到旧策略或新策略，不会是混合体。

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/v1/artifacts/{id}/statements` | 登记声明（body: `type`/`subject`/`content`） |
| `GET` | `/v1/artifacts/{id}/statements` | 读取链快照 |
| `GET` | `/v1/artifacts/{id}/verify` | 校验链；失败返回 409 与原因/位置 |
| `PUT` / `GET` | `/v1/policy` | 设置 / 读取策略 |
| `POST` | `/v1/artifacts/{id}/evaluate` | 执行策略判定；未通过返回 422 与未满足规则 |
| `GET` | `/v1/results` | 历史判定结论 |
| `GET` | `/v1/artifacts` | 列出制品 |

## 测试覆盖

- `provenance/chain_test.go`：摘要稳定性、篡改检测、重排检测。
- `provenance/store_test.go`：WAL 提交、撕裂尾部截断、策略恢复。
- `provenance/service_test.go`：磁盘篡改/缺失/断链的可区分检测、策略确定性与未满足规则报告、崩溃后状态恢复。
- `provenance/concurrency_test.go`：并发登记 + 并发判定的快照一致性（`-race`）、2000 条长链的增量校验（重校验扫描 0 条、追加后仅扫描 1 条）。
- `cmd/provenanced/main_test.go`：HTTP 端到端与重启持久性。
