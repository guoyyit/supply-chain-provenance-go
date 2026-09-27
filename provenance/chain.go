package provenance

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// verifyOps 统计执行过的单条声明校验次数，用于观测校验缓存效果（测试与监控用）。
var verifyOps atomic.Int64

// VerifyOps 返回累计执行的单条声明校验次数。
func VerifyOps() int64 { return verifyOps.Load() }

// FailureKind 区分链校验失败的原因。
type FailureKind string

const (
	FailureNone       FailureKind = ""            // 校验通过
	FailureTampered   FailureKind = "tampered"    // 声明内容被篡改（摘要与内容不符）
	FailureMissing    FailureKind = "missing"     // 缺少已登记的声明（前驱摘要指向已登记但不在链中的声明）
	FailureBrokenLink FailureKind = "broken_link" // 前驱摘要无法衔接（指向未知摘要）
)

// ChainError 描述链校验失败的位置与原因。
type ChainError struct {
	Kind   FailureKind
	Seq    uint64 // 出错声明的序号
	Detail string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("chain verification failed at seq %d: %s: %s", e.Seq, e.Kind, e.Detail)
}

// Chain 是单个制品的声明链（仅追加，声明追加后不可变）。
type Chain struct {
	artifactID string
	stmts      []Statement
	known      map[string]struct{} // 已登记声明摘要集合，用于缺失检测
	vmu        sync.Mutex          // 保护 verified 缓存，允许并发 Verify
	verified   int                 // 已校验通过的前缀长度（校验缓存）
}

// NewChain 创建空链。
func NewChain(artifactID string) *Chain {
	return &Chain{
		artifactID: artifactID,
		known:      make(map[string]struct{}),
	}
}

// LoadChain 用恢复出的历史声明重建链，并做全量校验。
// 校验通过则整条前缀计入校验缓存；失败返回 *ChainError。
func LoadChain(artifactID string, stmts []Statement) (*Chain, error) {
	c := NewChain(artifactID)
	c.stmts = append(c.stmts, stmts...)
	for _, st := range stmts {
		c.known[st.Hash] = struct{}{}
	}
	if err := c.VerifyFull(); err != nil {
		return nil, err
	}
	return c, nil
}

// Append 追加一条声明，绑定当前链头摘要，返回完整声明。
// 增量计算：只计算新声明自身的摘要，不重算历史。
func (c *Chain) Append(typ string, content map[string]string) Statement {
	prev := GenesisHash
	if n := len(c.stmts); n > 0 {
		prev = c.stmts[n-1].Hash
	}
	st := Statement{
		ArtifactID: c.artifactID,
		Seq:        uint64(len(c.stmts)),
		Type:       typ,
		Content:    content,
		PrevHash:   prev,
	}
	st.Hash = ComputeHash(st)
	c.stmts = append(c.stmts, st)
	c.known[st.Hash] = struct{}{}
	return st
}

// Statements 返回链中声明的快照（拷贝，调用方可安全持有与修改）。
func (c *Chain) Statements() []Statement {
	out := make([]Statement, len(c.stmts))
	copy(out, c.stmts)
	return out
}

// Known 返回已登记声明摘要集合的拷贝。
func (c *Chain) Known() map[string]struct{} {
	out := make(map[string]struct{}, len(c.known))
	for h := range c.known {
		out[h] = struct{}{}
	}
	return out
}

// Head 返回链头摘要与长度。
func (c *Chain) Head() (hash string, n int) {
	if len(c.stmts) == 0 {
		return GenesisHash, 0
	}
	return c.stmts[len(c.stmts)-1].Hash, len(c.stmts)
}

// Verify 校验链完整性。利用已校验前缀缓存，只校验新增后缀，
// 因此重复校验的开销不随链长度线性增长。
func (c *Chain) Verify() *ChainError {
	return c.verifyFrom(-1) // -1 表示从已校验前缀之后开始
}

// VerifyFull 忽略缓存，从头全量校验。
func (c *Chain) VerifyFull() *ChainError {
	return c.verifyFrom(0)
}

func (c *Chain) verifyFrom(from int) *ChainError {
	c.vmu.Lock()
	defer c.vmu.Unlock()
	if from < 0 {
		from = c.verified
	}
	// 活跃链只追加不删除，已登记集合即当前链中存在的摘要集合。
	if err := verifyRange(c.stmts, from, c.known, c.known); err != nil {
		c.verified = from // 保守处理：缓存回退到本次起点
		return err
	}
	c.verified = len(c.stmts)
	return nil
}

// VerifyStatements 静态校验一组声明（不依赖链状态），用于独立校验快照。
// known 为已登记声明摘要集合，可为 nil（此时缺失检测退化为断链检测）。
func VerifyStatements(stmts []Statement, known map[string]struct{}) *ChainError {
	present := make(map[string]struct{}, len(stmts))
	for _, st := range stmts {
		present[st.Hash] = struct{}{}
	}
	return verifyRange(stmts, 0, known, present)
}

// verifyRange 校验 stmts[from:]，假定 stmts[:from] 已校验通过。
// known 为全部已登记摘要；present 为当前链中实际存在的摘要。
// 链接失败时区分两种可区分原因：
//   - 前驱摘要在 known 中但不在 present 中 → FailureMissing（已登记声明缺失）
//   - 其他（未知摘要，或前驱在链中但位置不相邻，即顺序错误）→ FailureBrokenLink
func verifyRange(stmts []Statement, from int, known, present map[string]struct{}) *ChainError {
	for i := from; i < len(stmts); i++ {
		st := stmts[i]
		verifyOps.Add(1)

		// 1. 内容摘要校验：发现内容篡改。
		if st.Hash != ComputeHash(st) {
			return &ChainError{
				Kind:   FailureTampered,
				Seq:    st.Seq,
				Detail: fmt.Sprintf("statement hash %q does not match its content", st.Hash),
			}
		}

		// 2. 链接校验：前驱摘要必须等于前一条声明的摘要。
		expectedPrev := GenesisHash
		if i > 0 {
			expectedPrev = stmts[i-1].Hash
		}
		if st.PrevHash != expectedPrev {
			if _, ok := known[st.PrevHash]; ok {
				if _, inChain := present[st.PrevHash]; !inChain {
					return &ChainError{
						Kind:   FailureMissing,
						Seq:    st.Seq,
						Detail: fmt.Sprintf("predecessor %q is a registered statement but is absent from the chain", st.PrevHash),
					}
				}
			}
			return &ChainError{
				Kind:   FailureBrokenLink,
				Seq:    st.Seq,
				Detail: fmt.Sprintf("predecessor hash %q does not match previous statement hash %q", st.PrevHash, expectedPrev),
			}
		}

		// 3. 序号连续性校验。
		if uint64(i) != st.Seq {
			return &ChainError{
				Kind:   FailureTampered,
				Seq:    st.Seq,
				Detail: fmt.Sprintf("statement seq %d does not match its position %d", st.Seq, i),
			}
		}
	}
	return nil
}
