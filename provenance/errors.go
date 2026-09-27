package provenance

import "fmt"

// FailureReason distinguishes verification failure causes so callers can tell
// content tampering, a missing statement and a broken predecessor link apart.
type FailureReason string

const (
	// ReasonTampered means the stored digest of a statement no longer matches
	// its content (the statement body was altered).
	ReasonTampered FailureReason = "tampered"
	// ReasonMissingStatement means a registered statement is absent from the
	// sequence at the expected position (a statement was deleted).
	ReasonMissingStatement FailureReason = "missing_statement"
	// ReasonBrokenLink means a statement's PrevDigest does not point at the
	// preceding statement's digest (reordering / broken hash chain).
	ReasonBrokenLink FailureReason = "broken_link"
	// ReasonSequenceMismatch means sequence numbers are not consecutive from 1.
	ReasonSequenceMismatch FailureReason = "sequence_mismatch"
)

// VerificationError pinpoints where and why chain verification failed.
// Index is the zero-based position of the damaged statement; Digest carries
// that statement's stored digest when one exists.
type VerificationError struct {
	Reason FailureReason
	Index  int
	Digest Digest
	Detail string
}

func (e *VerificationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := fmt.Sprintf("provenance chain verification failed: %s at index %d", e.Reason, e.Index)
	if e.Digest != "" {
		s += " (statement " + string(e.Digest) + ")"
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}
