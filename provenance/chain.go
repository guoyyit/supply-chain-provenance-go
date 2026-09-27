package provenance

import "fmt"

// Chain is the ordered, hash-linked statement list of one artifact.
//
// Statements are append-only. Statement at position i (zero-based) must:
//   - carry Sequence == i+1,
//   - carry PrevDigest == Digest of statement i-1 (empty when i == 0),
//   - carry Digest == SHA-256 over its canonical body.
type Chain struct {
	artifactID string
	statements []Statement
	index      map[Digest]int
}

// NewChain creates an empty chain for an artifact.
func NewChain(artifactID string) *Chain {
	return &Chain{artifactID: artifactID, index: map[Digest]int{}}
}

// NewChainFrom rebuilds a chain from persisted statements without validating
// them; call Verify afterwards to detect damage after recovery.
func NewChainFrom(artifactID string, statements []Statement) *Chain {
	c := NewChain(artifactID)
	for _, st := range statements {
		st.Content = copyContent(st.Content)
		c.statements = append(c.statements, st)
		c.index[st.Digest] = len(c.statements) - 1
	}
	return c
}

// ArtifactID returns the artifact this chain belongs to.
func (c *Chain) ArtifactID() string { return c.artifactID }

// Len returns the number of statements.
func (c *Chain) Len() int { return len(c.statements) }

// Head returns the digest and sequence of the last statement.
func (c *Chain) Head() (Digest, uint64) {
	if len(c.statements) == 0 {
		return "", 0
	}
	last := c.statements[len(c.statements)-1]
	return last.Digest, last.Sequence
}

// Statements returns a defensive copy of all statements in append order.
func (c *Chain) Statements() []Statement {
	out := make([]Statement, len(c.statements))
	for i, st := range c.statements {
		st.Content = copyContent(st.Content)
		out[i] = st
	}
	return out
}

// Has reports whether a statement with digest d is registered.
func (c *Chain) Has(d Digest) bool {
	_, ok := c.index[d]
	return ok
}

// Append validates a statement and appends it to the chain.
// It rejects foreign statements, bad sequences/predecessor bindings,
// duplicate digests and statements whose stored digest is inconsistent.
func (c *Chain) Append(s Statement) error {
	if s.ArtifactID != c.artifactID {
		return fmt.Errorf("provenance: statement artifact %q does not belong to chain %q", s.ArtifactID, c.artifactID)
	}
	if s.Type == "" {
		return fmt.Errorf("provenance: statement type is required")
	}
	wantSeq := uint64(len(c.statements) + 1)
	if s.Sequence != wantSeq {
		return fmt.Errorf("provenance: sequence mismatch at append: want %d, got %d", wantSeq, s.Sequence)
	}
	var wantPrev Digest
	if len(c.statements) > 0 {
		wantPrev = c.statements[len(c.statements)-1].Digest
	}
	if s.PrevDigest != wantPrev {
		return fmt.Errorf("provenance: predecessor mismatch at append: want %q, got %q", wantPrev, s.PrevDigest)
	}
	if RecomputeDigest(s) != s.Digest {
		return fmt.Errorf("provenance: statement digest is inconsistent with its content")
	}
	if _, dup := c.index[s.Digest]; dup {
		return fmt.Errorf("provenance: duplicate statement digest %s", s.Digest)
	}
	s.Content = copyContent(s.Content)
	c.statements = append(c.statements, s)
	c.index[s.Digest] = len(c.statements) - 1
	return nil
}

// Verify checks the whole chain from genesis and returns the first damage
// found, with a position and a distinguishable reason.
func (c *Chain) Verify() *VerificationError {
	return c.VerifyFrom(0)
}

// VerifyFrom verifies statements starting at index start (zero-based),
// trusting that the prefix [0, start) has already been verified. The
// predecessor link of statement start is still checked against the trusted
// prefix, so a wrong cache start cannot hide a broken boundary.
func (c *Chain) VerifyFrom(start int) *VerificationError {
	if start < 0 || start > len(c.statements) {
		return &VerificationError{
			Reason: ReasonMissingStatement,
			Index:  start,
			Detail: fmt.Sprintf("verification start %d outside chain of length %d", start, len(c.statements)),
		}
	}
	var prev Digest
	if start > 0 {
		prev = c.statements[start-1].Digest
	}
	for i := start; i < len(c.statements); i++ {
		st := c.statements[i]

		// 1. Self-integrity: does the stored digest match the content?
		if got := RecomputeDigest(st); got != st.Digest {
			return &VerificationError{
				Reason: ReasonTampered,
				Index:  i,
				Digest: st.Digest,
				Detail: fmt.Sprintf("stored digest %s does not match recomputed digest %s", st.Digest, got),
			}
		}

		// 2. Sequence continuity: a gap means a registered statement is missing.
		if st.Sequence != uint64(i+1) {
			return &VerificationError{
				Reason: ReasonMissingStatement,
				Index:  i,
				Digest: st.Digest,
				Detail: fmt.Sprintf("expected sequence %d but found %d (a registered statement is missing)", i+1, st.Sequence),
			}
		}

		// 3. Link continuity: PrevDigest must bind the immediate predecessor.
		if st.PrevDigest != prev {
			return &VerificationError{
				Reason: ReasonBrokenLink,
				Index:  i,
				Digest: st.Digest,
				Detail: fmt.Sprintf("prev_digest %q does not link predecessor %q", st.PrevDigest, prev),
			}
		}
		prev = st.Digest
	}
	return nil
}
