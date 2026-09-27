package provenance

import (
	"testing"
)

func sampleChain(t *testing.T) []Statement {
	t.Helper()
	c := NewChain("app")
	c.Append("source", map[string]string{"repo": "git@example.com/app", "commit": "abc123"})
	c.Append("build", map[string]string{"builder": "ci", "image": "go:1.25"})
	c.Append("test", map[string]string{"suite": "unit", "result": "pass"})
	return c.Statements()
}

func TestEvaluateSatisfied(t *testing.T) {
	p := Policy{Rules: []Rule{
		{Name: "has-source", Type: "source", Match: map[string]string{"repo": "git@example.com/app"}},
		{Name: "built-by-ci", Type: "build", Match: map[string]string{"builder": "ci"}},
		{Name: "tests-pass", Type: "test", Match: map[string]string{"result": "pass"}},
	}}
	res := Evaluate(p, "app", sampleChain(t))
	if !res.Satisfied {
		t.Fatalf("expected satisfied, got unsatisfied: %+v", res.Unsatisfied)
	}
	if res.Statements != 3 || res.HeadHash == "" {
		t.Fatalf("result must identify the chain state: %+v", res)
	}
}

func TestEvaluateReportsUnsatisfiedRules(t *testing.T) {
	p := Policy{Rules: []Rule{
		{Name: "built-by-ci", Type: "build", Match: map[string]string{"builder": "ci"}},
		{Name: "signed", Type: "sign", Match: map[string]string{"key": "release"}},
		{Name: "tests-pass", Type: "test", Match: map[string]string{"result": "pass"}},
		{Name: "two-builds", Type: "build", MinCount: 2},
	}}
	res := Evaluate(p, "app", sampleChain(t))
	if res.Satisfied {
		t.Fatal("expected unsatisfied")
	}
	if len(res.Unsatisfied) != 2 {
		t.Fatalf("want 2 unsatisfied rules, got %d: %+v", len(res.Unsatisfied), res.Unsatisfied)
	}
	// 未满足规则必须按策略中声明的顺序输出（确定性）。
	if res.Unsatisfied[0].Rule.Name != "signed" || res.Unsatisfied[1].Rule.Name != "two-builds" {
		t.Fatalf("unsatisfied rules out of order: %+v", res.Unsatisfied)
	}
	if res.Unsatisfied[0].Found != 0 || res.Unsatisfied[0].Required != 1 {
		t.Fatalf("signed rule: want found=0 required=1, got %+v", res.Unsatisfied[0])
	}
	if res.Unsatisfied[1].Found != 1 || res.Unsatisfied[1].Required != 2 {
		t.Fatalf("two-builds rule: want found=1 required=2, got %+v", res.Unsatisfied[1])
	}
}

func TestEvaluateDeterministic(t *testing.T) {
	p := Policy{Rules: []Rule{
		{Name: "r1", Type: "build", Match: map[string]string{"builder": "other"}},
		{Name: "r2", Type: "sign"},
		{Name: "r3", Type: "test", Match: map[string]string{"result": "fail"}},
	}}
	stmts := sampleChain(t)
	first := Evaluate(p, "app", stmts)
	for i := 0; i < 20; i++ {
		got := Evaluate(p, "app", stmts)
		if got.Satisfied != first.Satisfied || len(got.Unsatisfied) != len(first.Unsatisfied) {
			t.Fatalf("non-deterministic result at iter %d", i)
		}
		for j := range got.Unsatisfied {
			if got.Unsatisfied[j].Rule.Name != first.Unsatisfied[j].Rule.Name {
				t.Fatalf("non-deterministic unsatisfied order at iter %d", i)
			}
		}
	}
}

func TestEvaluateEmptyPolicyAndEmptyChain(t *testing.T) {
	// 空策略无条件通过。
	if res := Evaluate(Policy{}, "app", sampleChain(t)); !res.Satisfied {
		t.Fatal("empty policy must be satisfied")
	}
	// 空链上任何带规则的策略都不通过。
	res := Evaluate(Policy{Rules: []Rule{{Name: "r", Type: "build"}}}, "app", nil)
	if res.Satisfied || len(res.Unsatisfied) != 1 || res.Unsatisfied[0].Found != 0 {
		t.Fatalf("empty chain must fail any rule: %+v", res)
	}
}

func TestMatchRuleSemantics(t *testing.T) {
	st := Statement{Type: "build", Content: map[string]string{"builder": "ci", "os": "linux"}}
	cases := []struct {
		name string
		rule Rule
		want bool
	}{
		{"type only", Rule{Type: "build"}, true},
		{"type mismatch", Rule{Type: "test"}, false},
		{"subset match", Rule{Type: "build", Match: map[string]string{"builder": "ci"}}, true},
		{"all keys must match", Rule{Type: "build", Match: map[string]string{"builder": "ci", "os": "linux"}}, true},
		{"one key differs", Rule{Type: "build", Match: map[string]string{"builder": "ci", "os": "darwin"}}, false},
		{"missing key", Rule{Type: "build", Match: map[string]string{"arch": "amd64"}}, false},
	}
	for _, tc := range cases {
		if got := matchRule(tc.rule, st); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
