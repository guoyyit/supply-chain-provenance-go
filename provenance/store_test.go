package provenance

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreCommitAndRecover(t *testing.T) {
	dir := t.TempDir()

	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(1700000000, 0).UTC()
	var prev Digest
	for i := 1; i <= 3; i++ {
		s := NewStatement("a1", StatementTypeBuild, "ci",
			map[string]string{"step": string(rune('0' + i))}, uint64(i), prev, ts)
		if err := st.AppendStatement(s); err != nil {
			t.Fatal(err)
		}
		prev = s.Digest
	}
	pol := Policy{Name: "p", Rules: []Rule{{Name: "r1", StatementType: StatementTypeBuild}}}
	if err := st.SavePolicy(pol); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash mid-append: a torn partial record at the tail.
	f, err := os.OpenFile(filepath.Join(dir, statementsWAL), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x50, 0x52, 0x4f, 0x56, 0x00, 0x00}); err != nil { // magic + partial
		t.Fatal(err)
	}
	f.Sync()
	f.Close()

	st2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st2.Statements()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 recovered statements, got %d", len(got))
	}
	pol2, err := st2.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if pol2.Name != "p" || len(pol2.Rules) != 1 {
		t.Fatalf("policy not recovered: %+v", pol2)
	}
	// torn tail must have been physically removed
	info, _ := os.Stat(filepath.Join(dir, statementsWAL))
	if info.Size() == 0 {
		t.Fatal("wal unexpectedly empty")
	}
	st2.Close()

	// Another reopen: still exactly 3, truncated size is stable.
	st3, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got3, _ := st3.Statements()
	if len(got3) != 3 {
		t.Fatalf("want 3 after second recover, got %d", len(got3))
	}
	info3, _ := os.Stat(filepath.Join(dir, statementsWAL))
	if info3.Size() != info.Size() {
		t.Fatalf("wal size changed after reopen: %d -> %d", info.Size(), info3.Size())
	}
	st3.Close()
}
