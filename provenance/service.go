package provenance

import (
	"fmt"
	"sync"
	"time"
)

// Service coordinates per-artifact chains, durable storage, incremental
// verification and policy evaluation.
//
// Concurrency model: a single RWMutex guards the in-memory chain set, policy
// and verification cache. Registrations take the write lock (a registration
// is an atomic "compute digest + append + fsync" unit); readers take the read
// lock and always receive a defensive copy. A policy evaluation therefore
// observes one consistent chain snapshot, never a half-appended statement or
// a mix of two registrations.
type Service struct {
	mu     sync.RWMutex
	store  *Store
	chains map[string]*Chain

	cache       map[string]*verifyCache
	lastScanned map[string]int
	policy      Policy
	results     []PolicyResult
}

// verifyCache remembers how far a chain is known-good, so verification after
// an append only inspects new statements (never the whole history).
type verifyCache struct {
	verifiedLen int
}

// OpenService opens a service rooted at dir, recovering all committed
// statements, the policy and historical conclusions from disk. Chains are
// rebuilt but not trusted until their first verification.
func OpenService(dir string) (*Service, error) {
	store, err := OpenStore(dir)
	if err != nil {
		return nil, err
	}
	records, err := store.Statements()
	if err != nil {
		store.Close()
		return nil, err
	}
	chains := make(map[string]*Chain)
	for _, st := range records {
		c, ok := chains[st.ArtifactID]
		if !ok {
			c = NewChain(st.ArtifactID)
			chains[st.ArtifactID] = c
		}
		// Rebuild via append-free loader to tolerate a damaged log until
		// verification explicitly surfaces the damage.
		st.Content = copyContent(st.Content)
		c.statements = append(c.statements, st)
		c.index[st.Digest] = len(c.statements) - 1
	}
	results, err := store.Results()
	if err != nil {
		store.Close()
		return nil, err
	}
	policy, err := store.LoadPolicy()
	if err != nil {
		store.Close()
		return nil, err
	}
	return &Service{
		store:       store,
		chains:      chains,
		cache:       make(map[string]*verifyCache),
		lastScanned: make(map[string]int),
		policy:      policy,
		results:     results,
	}, nil
}

// RegisterStatement appends a new statement to the artifact's chain. It is
// durable and visible atomically: either both the WAL record and the in-memory
// link exist, or neither does.
func (s *Service) RegisterStatement(artifactID string, typ StatementType, subject string, content map[string]string) (Statement, error) {
	if artifactID == "" {
		return Statement{}, fmt.Errorf("provenance: artifact id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.chains[artifactID]
	if c == nil {
		c = NewChain(artifactID)
		s.chains[artifactID] = c
		s.cache[artifactID] = &verifyCache{}
	}
	prev, seq := c.Head()
	st := NewStatement(artifactID, typ, subject, content, seq+1, prev, time.Now().UTC())

	// Durable first: if the fsync fails the in-memory chain stays untouched.
	if err := s.store.AppendStatement(st); err != nil {
		return Statement{}, err
	}
	if err := c.Append(st); err != nil {
		// Unreachable for a self-constructed statement; keep the invariant
		// explicit rather than corrupting the in-memory view.
		return Statement{}, fmt.Errorf("provenance: internal append failure after commit: %w", err)
	}
	return st, nil
}

// Statements returns a consistent, defensive snapshot of the artifact's chain.
func (s *Service) Statements(artifactID string) []Statement {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.chains[artifactID]
	if c == nil {
		return []Statement{}
	}
	return c.Statements()
}

// Artifacts returns the known artifact IDs.
func (s *Service) Artifacts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.chains))
	for id := range s.chains {
		ids = append(ids, id)
	}
	return ids
}

// VerifyArtifact verifies the artifact chain using the cached verified prefix:
// only statements appended since the last successful verification are
// re-checked, so cost is proportional to the number of new statements, not to
// chain length.
func (s *Service) VerifyArtifact(artifactID string) *VerificationError {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyLocked(artifactID)
}

func (s *Service) verifyLocked(artifactID string) *VerificationError {
	c := s.chains[artifactID]
	if c == nil {
		return nil // empty/unknown chain is trivially valid
	}
	entry := s.cache[artifactID]
	if entry == nil {
		entry = &verifyCache{}
		s.cache[artifactID] = entry
	}
	start := entry.verifiedLen
	verr := c.VerifyFrom(start)
	if verr == nil {
		s.lastScanned[artifactID] = c.Len() - start
		entry.verifiedLen = c.Len()
		return nil
	}
	s.lastScanned[artifactID] = verr.Index - start + 1
	if verr.Index < entry.verifiedLen {
		// The trusted prefix itself is damaged (e.g. on-disk tampering):
		// drop the cache so the next check starts from genesis.
		entry.verifiedLen = 0
	}
	return verr
}

// LastVerifiedCount reports how many statements the most recent VerifyArtifact
// call actually inspected; zero means the result came entirely from cache.
func (s *Service) LastVerifiedCount(artifactID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastScanned[artifactID]
}

// SetPolicy atomically replaces the active policy and persists it.
func (s *Service) SetPolicy(p Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.SavePolicy(p); err != nil {
		return err
	}
	s.policy = p
	return nil
}

// Policy returns a copy of the active policy.
func (s *Service) Policy() Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := Policy{Name: s.policy.Name, Rules: append([]Rule(nil), s.policy.Rules...)}
	return cp
}

// Evaluate verifies the artifact and runs the active policy against the
// resulting consistent snapshot. The conclusion (including the chain head it
// was based on) is durably recorded before returning.
func (s *Service) Evaluate(artifactID string) (PolicyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if verr := s.verifyLocked(artifactID); verr != nil {
		return PolicyResult{}, verr
	}
	c := s.chains[artifactID]
	var snapshot []Statement
	var head Digest
	if c != nil {
		snapshot = c.Statements()
		head, _ = c.Head()
	}
	result := Evaluate(s.policy, artifactID, snapshot, head)
	if err := s.store.AppendResult(result); err != nil {
		return PolicyResult{}, err
	}
	s.results = append(s.results, result)
	return result, nil
}

// Results returns historical policy conclusions in evaluation order.
func (s *Service) Results() []PolicyResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]PolicyResult(nil), s.results...)
}

// Close flushes and closes the service durably.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Close()
}
