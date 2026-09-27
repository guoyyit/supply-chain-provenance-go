package provenance

import (
	"fmt"
	"sort"
	"sync"
)

// Service 是并发安全的来源证明服务门面。
// 任一判定只基于某个一致的链状态（快照语义）：
// 在读锁内取得不可变声明的拷贝后释放锁，判定过程中追加的新声明
// 不会混入本次判定，也不会读到半写入状态（声明先落盘、再在写锁内加入内存）。
type Service struct {
	mu       sync.RWMutex
	store    *Store
	chains   map[string]*Chain // artifactID -> 链
	policies map[string]Policy // artifactID -> 策略
}

// Open 打开服务：执行崩溃恢复，重建各制品声明链与策略配置。
func Open(dir string) (*Service, error) {
	store, err := OpenStore(dir)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	stmts, err := store.LoadAll()
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("load statements: %w", err)
	}
	policies, err := store.LoadPolicies()
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("load policies: %w", err)
	}

	// 按日志追加顺序分组（全局日志中各制品的相对顺序天然保持）。
	grouped := map[string][]Statement{}
	for _, st := range stmts {
		grouped[st.ArtifactID] = append(grouped[st.ArtifactID], st)
	}
	chains := make(map[string]*Chain, len(grouped))
	for id, list := range grouped {
		ch, err := LoadChain(id, list)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("rebuild chain for artifact %q: %w", id, err)
		}
		chains[id] = ch
	}

	return &Service{store: store, chains: chains, policies: policies}, nil
}

// Close 关闭服务。
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Close()
}

// RegisterStatement 为制品登记一条来源声明。
// 顺序：先持久化到仅追加日志，成功后再在写锁内追加进内存链，
// 因此并发读方要么看不到本声明，要么看到完整声明。
func (s *Service) RegisterStatement(artifactID, typ string, content map[string]string) (Statement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.chains[artifactID]
	if !ok {
		ch = NewChain(artifactID)
		s.chains[artifactID] = ch
	}
	// 先构造完整声明（含摘要与链接），保证写入日志的就是最终形态。
	st := ch.Append(typ, content)
	if err := s.store.Append(st); err != nil {
		// 日志写入失败：回滚内存追加。回滚前该链不可能被其他读方观察到本声明
		//（全程持写锁），所以不影响一致性。
		s.rollbackLast(ch)
		return Statement{}, fmt.Errorf("persist statement: %w", err)
	}
	return st, nil
}

// rollbackLast 移除链的最后一条声明及其摘要登记（仅在日志写入失败时调用）。
func (s *Service) rollbackLast(ch *Chain) {
	n := len(ch.stmts)
	if n == 0 {
		return
	}
	drop := ch.stmts[n-1]
	delete(ch.known, drop.Hash)
	ch.stmts = ch.stmts[:n-1]
	ch.vmu.Lock()
	if ch.verified > len(ch.stmts) {
		ch.verified = len(ch.stmts)
	}
	ch.vmu.Unlock()
}

// Statements 返回制品的声明链快照（独立拷贝）。
func (s *Service) Statements(artifactID string) []Statement {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ch, ok := s.chains[artifactID]; ok {
		return ch.Statements()
	}
	return nil
}

// ArtifactIDs 返回已登记声明的全部制品标识（排序，便于确定性展示）。
func (s *Service) ArtifactIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.chains))
	for id := range s.chains {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Verify 校验制品的声明链。返回 nil 表示完整。
// 读锁在整个校验期间持有：写方（Append）被排除，
// 校验看到的是一致的链状态；并发 Verify 之间由链级互斥锁保护缓存。
func (s *Service) Verify(artifactID string) *ChainError {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ch, ok := s.chains[artifactID]
	if !ok {
		return nil
	}
	return ch.Verify()
}

// SetPolicy 设置制品的发布策略并原子持久化。
// 先写盘（临时文件 + rename）成功后再更新内存，避免半写策略对外可见。
func (s *Service) SetPolicy(artifactID string, p Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := make(map[string]Policy, len(s.policies)+1)
	for id, pol := range s.policies {
		next[id] = pol
	}
	next[artifactID] = p
	if err := s.store.SavePolicies(next); err != nil {
		return fmt.Errorf("persist policy: %w", err)
	}
	s.policies = next
	return nil
}

// Policy 返回制品当前策略（不存在则返回空策略与 false）。
func (s *Service) Policy(artifactID string) (Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[artifactID]
	return p, ok
}

// Evaluate 基于一致的链快照执行策略判定。
// 快照在读锁内取得，结果中的 Statements 与 HeadHash 标明判定所基于的链状态；
// 判定期间并发追加不影响本次结论。制品未设置策略时按空策略处理（无条件通过）。
func (s *Service) Evaluate(artifactID string) PolicyResult {
	s.mu.RLock()
	var snap []Statement
	if ch, ok := s.chains[artifactID]; ok {
		snap = ch.Statements()
	}
	p := s.policies[artifactID]
	s.mu.RUnlock()

	return Evaluate(p, artifactID, snap)
}
