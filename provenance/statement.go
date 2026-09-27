package provenance

import "time"

// StatementType classifies a provenance statement.
type StatementType string

const (
	StatementTypeBuild    StatementType = "build"
	StatementTypeMaterial StatementType = "material"
	StatementTypeTest     StatementType = "test"
	StatementTypeReview   StatementType = "review"
	StatementTypeRelease  StatementType = "release"
)

// Statement is a single provenance claim about an artifact.
//
// The chain fields (Sequence, PrevDigest) are part of the hashed content:
// altering the statement body, removing it or reordering the chain therefore
// invalidates at least one Digest.
type Statement struct {
	ArtifactID string            `json:"artifact_id"`
	Type       StatementType     `json:"type"`
	Subject    string            `json:"subject"`
	Content    map[string]string `json:"content,omitempty"`
	Sequence   uint64            `json:"sequence"`
	PrevDigest Digest            `json:"prev_digest"`
	Timestamp  time.Time         `json:"timestamp"`
	Digest     Digest            `json:"digest"`
}

// digestedBody is the exact subset of Statement covered by the digest.
// Digest itself is excluded to avoid self-reference.
type digestedBody struct {
	ArtifactID string            `json:"artifact_id"`
	Type       StatementType     `json:"type"`
	Subject    string            `json:"subject"`
	Content    map[string]string `json:"content,omitempty"`
	Sequence   uint64            `json:"sequence"`
	PrevDigest Digest            `json:"prev_digest"`
	Timestamp  time.Time         `json:"timestamp"`
}

// NewStatement builds a complete statement for an artifact: it assigns the
// sequence and predecessor binding supplied by the chain and computes the
// digest. The timestamp is passed in (rather than read from the clock) so
// identical inputs deterministically yield identical digests.
func NewStatement(artifactID string, typ StatementType, subject string, content map[string]string, seq uint64, prev Digest, ts time.Time) Statement {
	st := Statement{
		ArtifactID: artifactID,
		Type:       typ,
		Subject:    subject,
		Content:    copyContent(content),
		Sequence:   seq,
		PrevDigest: prev,
		Timestamp:  ts.UTC(),
	}
	st.Digest = RecomputeDigest(st)
	return st
}

// RecomputeDigest computes the digest over every content field of s except
// its stored Digest. It is the single primitive used by append and verify.
func RecomputeDigest(s Statement) Digest {
	body := digestedBody{
		ArtifactID: s.ArtifactID,
		Type:       s.Type,
		Subject:    s.Subject,
		Content:    copyContent(s.Content),
		Sequence:   s.Sequence,
		PrevDigest: s.PrevDigest,
		Timestamp:  s.Timestamp,
	}
	return computeDigest(body)
}

// copyContent returns a non-nil copy of content so statement maps never alias
// caller-owned maps (prevents in-place tampering outside the chain).
func copyContent(content map[string]string) map[string]string {
	if len(content) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(content))
	for k, v := range content {
		out[k] = v
	}
	return out
}
