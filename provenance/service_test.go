package provenance

import (
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentRegisterAndEvaluate 并发登记声明与执行策略判定：
// 任一判定结果必须对应链的某个一致前缀（Statements 与 HeadHash 必须匹配
// 最终链的某个真实前缀），不得读到半写入或跨声明混合状态。
func TestConcurrentRegisterAndEvaluate(t *testing.T) {
	svc, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	const writers = 8
	const perWriter = 50
	pol := Policy{Rules: []Rule{{Name: "has-build", Type: "build"}}}
	if err := svc.SetPolicy("app", pol); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup

	// 读方：并发校验与判定，收集判定结果。
	results := make(chan PolicyResult, 1024)
	done := make(chan struct{})
	var readers sync.WaitGroup
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if err := svc.Verify("app"); err != nil {
					t.Errorf("concurrent verify failed: %v", err)
					return
				}
				select {
				case results <- svc.Evaluate("app"):
				case <-done:
					return
				}
			}
		}()
	}

	// 写方：并发登记。
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				content := map[string]string{"writer": fmt.Sprint(w), "i": fmt.Sprint(i)}
				if _, err := svc.RegisterStatement("app", "build", content); err != nil {
					t.Errorf("register failed: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(done)
	readers.Wait()
	close(results)

	// 最终链必须完整且包含全部声明。
	final := svc.Statements("app")
	if len(final) != writers*perWriter {
		t.Fatalf("want %d statements, got %d", writers*perWriter, len(final))
	}
	if err := svc.Verify("app"); err != nil {
		t.Fatalf("final chain must verify: %v", err)
	}
	// 序号必须恰好覆盖 0..n-1（无丢失、无重复、无错位）。
	seen := make(map[uint64]bool, len(final))
	for _, st := range final {
		if seen[st.Seq] {
			t.Fatalf("duplicate seq %d", st.Seq)
		}
		seen[st.Seq] = true
	}
	for i := range final {
		if !seen[uint64(i)] {
			t.Fatalf("missing seq %d", i)
		}
	}

	// 每个判定结果都必须对应最终链的某个真实前缀（一致性快照）。
	nResults := 0
	for res := range results {
		nResults++
		if res.Statements < 0 || res.Statements > len(final) {
			t.Fatalf("impossible statement count %d", res.Statements)
		}
		wantHead := GenesisHash
		if res.Statements > 0 {
			wantHead = final[res.Statements-1].Hash
		}
		if res.HeadHash != wantHead {
			t.Fatalf("inconsistent snapshot: statements=%d head=%q, want prefix head %q",
				res.Statements, res.HeadHash, wantHead)
		}
		// 链非空时策略（至少一条 build 声明）必须判定通过。
		if res.Statements > 0 && !res.Satisfied {
			t.Fatalf("policy should be satisfied on non-empty chain: %+v", res)
		}
	}
	if nResults == 0 {
		t.Fatal("no evaluation results collected")
	}
	t.Logf("checked %d consistent snapshots", nResults)
}

// TestConcurrentRegisterMultiArtifact 多制品并发登记互不干扰。
func TestConcurrentRegisterMultiArtifact(t *testing.T) {
	svc, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	const artifacts = 4
	const perArtifact = 30
	var wg sync.WaitGroup
	for a := 0; a < artifacts; a++ {
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			id := fmt.Sprintf("artifact-%d", a)
			for i := 0; i < perArtifact; i++ {
				if _, err := svc.RegisterStatement(id, "build", map[string]string{"i": fmt.Sprint(i)}); err != nil {
					t.Errorf("register failed: %v", err)
					return
				}
			}
		}(a)
	}
	wg.Wait()
	for a := 0; a < artifacts; a++ {
		id := fmt.Sprintf("artifact-%d", a)
		if got := len(svc.Statements(id)); got != perArtifact {
			t.Fatalf("%s: want %d statements, got %d", id, perArtifact, got)
		}
		if err := svc.Verify(id); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
}

// TestLongChainVerificationIsIncremental 长链场景：
// 校验缓存使重复校验的开销不随链长度线性增长（用校验计数器确定性断言）。
func TestLongChainVerificationIsIncremental(t *testing.T) {
	svc, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	const n = 5000
	for i := 0; i < n; i++ {
		if _, err := svc.RegisterStatement("app", "build", map[string]string{"i": fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}

	// 首次校验：全量 n 条。
	before := VerifyOps()
	if err := svc.Verify("app"); err != nil {
		t.Fatal(err)
	}
	full := VerifyOps() - before
	if full != n {
		t.Fatalf("first verify should check %d statements, checked %d", n, full)
	}

	// 重复校验 100 次：缓存命中，增量为 0。
	before = VerifyOps()
	for i := 0; i < 100; i++ {
		if err := svc.Verify("app"); err != nil {
			t.Fatal(err)
		}
	}
	if delta := VerifyOps() - before; delta != 0 {
		t.Fatalf("cached verify should check 0 statements, checked %d", delta)
	}

	// 追加 1 条后再校验：只校验新增的 1 条，与链长无关。
	if _, err := svc.RegisterStatement("app", "sign", map[string]string{"key": "release"}); err != nil {
		t.Fatal(err)
	}
	before = VerifyOps()
	if err := svc.Verify("app"); err != nil {
		t.Fatal(err)
	}
	if delta := VerifyOps() - before; delta != 1 {
		t.Fatalf("incremental verify should check 1 statement, checked %d", delta)
	}
}

// TestLongChainPolicyEvaluation 长链上的策略判定结果正确。
func TestLongChainPolicyEvaluation(t *testing.T) {
	svc, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	const n = 2000
	for i := 0; i < n; i++ {
		if _, err := svc.RegisterStatement("app", "build", map[string]string{"i": fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.RegisterStatement("app", "sign", map[string]string{"key": "release"}); err != nil {
		t.Fatal(err)
	}
	pol := Policy{Rules: []Rule{
		{Name: "many-builds", Type: "build", MinCount: n},
		{Name: "signed", Type: "sign", Match: map[string]string{"key": "release"}},
	}}
	if err := svc.SetPolicy("app", pol); err != nil {
		t.Fatal(err)
	}
	res := svc.Evaluate("app")
	if !res.Satisfied {
		t.Fatalf("long chain policy should be satisfied: %+v", res.Unsatisfied)
	}
	if res.Statements != n+1 {
		t.Fatalf("want %d statements in result, got %d", n+1, res.Statements)
	}
}
