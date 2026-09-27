package provenance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := NewChain("a")
	for i := 0; i < 3; i++ {
		st := c.Append("build", map[string]string{"i": itoa(i)})
		if err := s.Append(st); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 statements, got %d", len(got))
	}
	for i, st := range got {
		if st.Hash != c.Statements()[i].Hash {
			t.Fatalf("statement %d hash mismatch after reload", i)
		}
	}
}

func TestCrashRecoveryTornTailTruncated(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := NewChain("a")
	var committed []Statement
	for i := 0; i < 5; i++ {
		st := c.Append("build", map[string]string{"i": itoa(i)})
		if err := s.Append(st); err != nil {
			t.Fatal(err)
		}
		committed = append(committed, st)
	}
	s.Close()

	// 模拟崩溃：向日志尾部写入半条记录（长度前缀 + 半个 payload）。
	logPath := filepath.Join(dir, statementsFile)
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0, 0, 1, 0, '{', '"', 'a'}); err != nil { // 声明 256 字节，只写了 7
		t.Fatal(err)
	}
	f.Close()

	// 恢复：撕裂尾部被截断，已提交记录完好。
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(committed) {
		t.Fatalf("want %d committed statements, got %d", len(committed), len(got))
	}
	for i := range committed {
		if got[i].Hash != committed[i].Hash {
			t.Fatalf("committed statement %d corrupted", i)
		}
	}
	// 截断后新追加的记录必须紧接完好前缀，且恢复后仍可整体读出。
	st := c.Append("sign", map[string]string{"key": "release"})
	if err := s2.Append(st); err != nil {
		t.Fatal(err)
	}
	s3, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	got2, _ := s3.LoadAll()
	if len(got2) != len(committed)+1 || got2[len(got2)-1].Hash != st.Hash {
		t.Fatalf("append after recovery broken: got %d statements", len(got2))
	}
}

func TestCrashRecoveryCorruptCRC(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir)
	c := NewChain("a")
	for i := 0; i < 3; i++ {
		s.Append(c.Append("build", nil))
	}
	s.Close()

	// 翻转最后一条记录 CRC 的一个字节（模拟撕裂/损坏写入）。
	logPath := filepath.Join(dir, statementsFile)
	data, _ := os.ReadFile(logPath)
	data[len(data)-1] ^= 0xff
	os.WriteFile(logPath, data, 0o644)

	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, _ := s2.LoadAll()
	if len(got) != 2 {
		t.Fatalf("corrupt tail record must be dropped, got %d statements", len(got))
	}
}

func TestServiceCrashRecoveryKeepsCommittedState(t *testing.T) {
	dir := t.TempDir()

	// 第一个"进程"：登记声明并设置策略，然后模拟崩溃（不 Close 直接弃用）。
	svc1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc1.RegisterStatement("app", "source", map[string]string{"commit": "abc"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc1.RegisterStatement("app", "build", map[string]string{"builder": "ci"}); err != nil {
		t.Fatal(err)
	}
	pol := Policy{Rules: []Rule{{Name: "built", Type: "build", Match: map[string]string{"builder": "ci"}}}}
	if err := svc1.SetPolicy("app", pol); err != nil {
		t.Fatal(err)
	}
	before := svc1.Evaluate("app")
	if !before.Satisfied {
		t.Fatal("policy should be satisfied before crash")
	}
	// 崩溃：不调用 Close。

	// 第二个"进程"：同一目录恢复。
	svc2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()

	stmts := svc2.Statements("app")
	if len(stmts) != 2 {
		t.Fatalf("committed statements lost after crash: got %d", len(stmts))
	}
	if err := svc2.Verify("app"); err != nil {
		t.Fatalf("recovered chain must verify: %v", err)
	}
	// 策略配置与历史结论一致：同一策略、同一链状态 → 同一结论。
	after := svc2.Evaluate("app")
	if after.Satisfied != before.Satisfied || after.HeadHash != before.HeadHash || after.Statements != before.Statements {
		t.Fatalf("conclusion changed across crash: before=%+v after=%+v", before, after)
	}
	p, ok := svc2.Policy("app")
	if !ok || len(p.Rules) != 1 || p.Rules[0].Name != "built" {
		t.Fatalf("policy not recovered: %+v", p)
	}
}

func TestServiceRecoveryMultiArtifact(t *testing.T) {
	dir := t.TempDir()
	svc1, _ := Open(dir)
	svc1.RegisterStatement("a", "build", map[string]string{"n": "1"})
	svc1.RegisterStatement("b", "build", map[string]string{"n": "1"})
	svc1.RegisterStatement("a", "test", map[string]string{"n": "2"})
	// 崩溃。

	svc2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	if got := len(svc2.Statements("a")); got != 2 {
		t.Fatalf("artifact a: want 2 statements, got %d", got)
	}
	if got := len(svc2.Statements("b")); got != 1 {
		t.Fatalf("artifact b: want 1 statement, got %d", got)
	}
	// 每个制品各自成链，恢复后链接必须正确。
	for _, id := range []string{"a", "b"} {
		if err := svc2.Verify(id); err != nil {
			t.Fatalf("artifact %s chain broken after recovery: %v", id, err)
		}
	}
}
