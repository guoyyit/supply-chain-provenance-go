package provenance

import "testing"

func buildTestChain(t *testing.T, n int) *Chain {
	t.Helper()
	c := NewChain("artifact-x")
	for i := 0; i < n; i++ {
		c.Append("build", map[string]string{"step": string(rune('a' + i)), "idx": itoa(i)})
	}
	return c
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestChainHappyPathAndLinks(t *testing.T) {
	c := buildTestChain(t, 4)
	if err := c.Verify(); err != nil {
		t.Fatalf("fresh chain must verify: %v", err)
	}
	stmts := c.Statements()
	if stmts[0].PrevHash != GenesisHash {
		t.Fatal("genesis prev hash must be empty")
	}
	for i := 1; i < len(stmts); i++ {
		if stmts[i].PrevHash != stmts[i-1].Hash {
			t.Fatalf("link broken at %d by construction", i)
		}
	}
}

func TestVerifyDetectsTamperedContentWithPosition(t *testing.T) {
	c := buildTestChain(t, 5)
	stmts := c.Statements()
	known := c.Known()

	// 篡改 seq=2 的内容，但保留原 Hash 字段。
	stmts[2].Content["step"] = "tampered"
	err := VerifyStatements(stmts, known)
	if err == nil {
		t.Fatal("expected tamper detection")
	}
	if err.Kind != FailureTampered || err.Seq != 2 {
		t.Fatalf("want tampered@2, got %v", err)
	}
}

func TestVerifyDetectsReorder(t *testing.T) {
	c := buildTestChain(t, 4)
	stmts := c.Statements()
	known := c.Known()

	// 交换 seq=1 与 seq=2：两者内容/Hash 各自完好，但链接顺序被打乱。
	stmts[1], stmts[2] = stmts[2], stmts[1]
	err := VerifyStatements(stmts, known)
	if err == nil {
		t.Fatal("expected reorder detection")
	}
	// 交换后位置 1 上是原 seq=2：其 PrevHash 指向原 seq=1 的摘要，
	// 该摘要已登记且仍在链中（位置 2），只是不相邻 → 断链（顺序错误）。
	if err.Kind != FailureBrokenLink {
		t.Fatalf("want broken_link kind for reorder, got %v", err)
	}
	if err.Seq != 2 {
		t.Fatalf("want failure reported at seq 2, got seq %d", err.Seq)
	}
}

func TestVerifyDetectsMissingStatement(t *testing.T) {
	c := buildTestChain(t, 4)
	stmts := c.Statements()
	known := c.Known()

	// 直接删除 seq=2：stmts[2](原 seq=3) 的 PrevHash 仍指向已登记的 seq=2 摘要。
	missing := append([]Statement{}, stmts[:2]...)
	missing = append(missing, stmts[3])
	err := VerifyStatements(missing, known)
	if err == nil {
		t.Fatal("expected missing detection")
	}
	if err.Kind != FailureMissing {
		t.Fatalf("want FailureMissing, got %v", err)
	}
	if err.Seq != 3 {
		t.Fatalf("want failure reported at seq 3, got seq %d", err.Seq)
	}
}

func TestVerifyDetectsBrokenLink(t *testing.T) {
	c := buildTestChain(t, 4)
	stmts := c.Statements()
	known := c.Known()

	// 伪造一个从未登记过的前驱摘要，并重算 Hash 使内容自身完好，
	// 构造"纯断链"（PrevHash 参与摘要计算，只改它会被判为篡改）。
	stmts[1].PrevHash = "0123456789abcdef"
	stmts[1].Hash = ComputeHash(stmts[1])
	err := VerifyStatements(stmts, known)
	if err == nil {
		t.Fatal("expected broken link detection")
	}
	if err.Kind != FailureBrokenLink || err.Seq != 1 {
		t.Fatalf("want broken_link@1, got %v", err)
	}
}

func TestMissingAndBrokenLinkAreDistinguishable(t *testing.T) {
	c := buildTestChain(t, 3)
	stmts := c.Statements()
	known := c.Known()

	missingCase := append([]Statement{}, stmts[:1]...)
	missingCase = append(missingCase, stmts[2]) // 删除中间声明
	e1 := VerifyStatements(missingCase, known)

	brokenCase := c.Statements()
	brokenCase[1].PrevHash = "ffffffff" // 未知摘要
	brokenCase[1].Hash = ComputeHash(brokenCase[1])
	e2 := VerifyStatements(brokenCase, known)

	if e1.Kind != FailureMissing || e2.Kind != FailureBrokenLink {
		t.Fatalf("want missing vs broken_link, got %s vs %s", e1.Kind, e2.Kind)
	}
}

func TestVerifyCacheOnlyRechecksNewSuffix(t *testing.T) {
	c := buildTestChain(t, 3)
	if err := c.Verify(); err != nil {
		t.Fatal(err)
	}
	c.vmu.Lock()
	if c.verified != 3 {
		// initial verify caches full prefix
		t.Fatalf("verified=%d, want 3", c.verified)
	}
	c.vmu.Unlock()

	c.Append("test", map[string]string{"k": "v"})
	c.vmu.Lock()
	start := c.verified
	c.vmu.Unlock()
	if start != 3 {
		t.Fatalf("append must not invalidate cached prefix, verified=%d", start)
	}
	if err := c.Verify(); err != nil {
		t.Fatalf("incremental verify failed: %v", err)
	}
	c.vmu.Lock()
	if c.verified != 4 {
		t.Fatalf("verified=%d after append, want 4", c.verified)
	}
	c.vmu.Unlock()

	// 再次无新增校验应保持通过且缓存不变。
	if err := c.Verify(); err != nil {
		t.Fatalf("idempotent verify failed: %v", err)
	}
}

func TestLoadChainRejectsCorruptedHistory(t *testing.T) {
	c := buildTestChain(t, 3)
	stmts := c.Statements()
	stmts[1].Hash = "deadbeef"
	if _, err := LoadChain("artifact-x", stmts); err == nil {
		t.Fatal("LoadChain must reject corrupted history")
	}
}
