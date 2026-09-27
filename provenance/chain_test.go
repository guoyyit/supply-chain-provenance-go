package provenance

import (
	"testing"
	"time"
)

func sampleChain(t *testing.T) *Chain {
	t.Helper()
	c := NewChain("artifact-1")
	ts := time.Unix(1700000000, 0).UTC()
	var prev Digest
	for i := 1; i <= 3; i++ {
		st := NewStatement("artifact-1", StatementTypeBuild, "builder",
			map[string]string{"step": string(rune('0' + i))}, uint64(i), prev, ts)
		if err := c.Append(st); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		prev = st.Digest
	}
	return c
}

func TestChainVerifyHappyPath(t *testing.T) {
	c := sampleChain(t)
	if err := c.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestChainTamperDetected(t *testing.T) {
	c := sampleChain(t)
	c.statements[1].Content["step"] = "tampered"
	err := c.Verify()
	if err == nil || err.Reason != ReasonTampered || err.Index != 1 {
		t.Fatalf("want tampered at 1, got %+v", err)
	}
}

func TestChainBrokenLinkDetected(t *testing.T) {
	c := sampleChain(t)
	// swap order of statements 1 and 2: digests still valid individually,
	// but sequence gaps and links break.
	c.statements[1], c.statements[2] = c.statements[2], c.statements[1]
	err := c.Verify()
	if err == nil || err.Reason != ReasonMissingStatement {
		t.Fatalf("want missing_statement on reorder, got %+v", err)
	}
}

func TestChainStableDigest(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	a := NewStatement("x", StatementTypeBuild, "b", map[string]string{"k": "v"}, 1, "", ts)
	b := NewStatement("x", StatementTypeBuild, "b", map[string]string{"k": "v"}, 1, "", ts)
	if a.Digest != b.Digest {
		t.Fatalf("identical content produced different digests: %s vs %s", a.Digest, b.Digest)
	}
}
