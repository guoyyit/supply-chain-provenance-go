package provenance

import (
	"testing"
	"time"
)

// registerN registers n build statements on one artifact through the service.
func registerN(t *testing.T, svc *Service, artifact string, n int) []Statement {
	t.Helper()
	out := make([]Statement, 0, n)
	for i := 0; i < n; i++ {
		st, err := svc.RegisterStatement(artifact, StatementTypeBuild, "ci-builder",
			map[string]string{"step": "compile", "n": string(rune('a' + i%26))})
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		out = append(out, st)
	}
	return out
}

// seedStore writes the given statements directly into a fresh store,
// bypassing service-level validation (simulating a tampered on-disk log).
func seedStore(t *testing.T, dir string, statements []Statement) {
	t.Helper()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range statements {
		if err := st.AppendStatement(s); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

func validStatements(t *testing.T, artifact string, n int) []Statement {
	t.Helper()
	ts := time.Unix(1700000000, 0).UTC()
	out := make([]Statement, 0, n)
	var prev Digest
	for i := 1; i <= n; i++ {
		st := NewStatement(artifact, StatementTypeBuild, "ci",
			map[string]string{"i": string(rune('0' + i))}, uint64(i), prev, ts)
		out = append(out, st)
		prev = st.Digest
	}
	return out
}

func TestServiceDetectsTamperedContent(t *testing.T) {
	dir := t.TempDir()
	stmts := validStatements(t, "a1", 3)
	// Attacker rewrites statement 2's content but keeps its stored digest.
	stmts[1].Content["i"] = "forged"
	seedStore(t, dir, stmts)

	svc, err := OpenService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	verr := svc.VerifyArtifact("a1")
	if verr == nil {
		t.Fatal("expected verification failure")
	}
	if verr.Reason != ReasonTampered || verr.Index != 1 {
		t.Fatalf("want tampered at index 1, got %+v", verr)
	}
}

func TestServiceDetectsMissingStatement(t *testing.T) {
	dir := t.TempDir()
	stmts := validStatements(t, "a1", 3)
	// Statement 2 is deleted from the log; statement 3 still links to it.
	seedStore(t, dir, []Statement{stmts[0], stmts[2]})

	svc, err := OpenService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	verr := svc.VerifyArtifact("a1")
	if verr == nil || verr.Reason != ReasonMissingStatement || verr.Index != 1 {
		t.Fatalf("want missing_statement at index 1, got %+v", verr)
	}
}

func TestServiceDetectsBrokenLink(t *testing.T) {
	dir := t.TempDir()
	stmts := validStatements(t, "a1", 2)
	// A third statement with a valid self-digest but a wrong predecessor.
	ts := time.Unix(1700000000, 0).UTC()
	bad := NewStatement("a1", StatementTypeBuild, "ci", map[string]string{"i": "3"},
		3, Digest("sha256:deadbeef"), ts)
	seedStore(t, dir, append(stmts, bad))

	svc, err := OpenService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	verr := svc.VerifyArtifact("a1")
	if verr == nil || verr.Reason != ReasonBrokenLink || verr.Index != 2 {
		t.Fatalf("want broken_link at index 2, got %+v", verr)
	}
}

func TestPolicyEvaluationDeterministic(t *testing.T) {
	dir := t.TempDir()
	svc, err := OpenService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	if _, err := svc.RegisterStatement("app", StatementTypeBuild, "ci-builder",
		map[string]string{"compiler": "go1.25", "os": "linux"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterStatement("app", StatementTypeMaterial, "ci-builder",
		map[string]string{"dep": "github.com/foo/bar", "version": "v1.2.3"}); err != nil {
		t.Fatal(err)
	}

	policy := Policy{
		Name: "release-gate",
		Rules: []Rule{
			{Name: "built-by-ci", StatementType: StatementTypeBuild,
				Conditions: []Condition{{Field: "compiler", Op: OpContains, Value: "go"}}},
			{Name: "deps-declared", StatementType: StatementTypeMaterial,
				Conditions: []Condition{{Field: "dep", Op: OpExists}}},
			{Name: "tests-passed", StatementType: StatementTypeTest,
				Conditions: []Condition{{Field: "status", Op: OpEquals, Value: "ok"}}},
		},
	}
	if err := svc.SetPolicy(policy); err != nil {
		t.Fatal(err)
	}

	res, err := svc.Evaluate("app")
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Fatal("expected policy to fail: no test statement registered")
	}
	if len(res.FailedRules) != 1 || res.FailedRules[0].Rule.Name != "tests-passed" {
		t.Fatalf("want exactly tests-passed to fail, got %+v", res.FailedRules)
	}

	// Deterministic: same state, same outcome, byte-identical failed rules.
	res2, err := svc.Evaluate("app")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Passed != res.Passed || len(res2.FailedRules) != len(res.FailedRules) ||
		res2.FailedRules[0].Rule.Name != res.FailedRules[0].Rule.Name ||
		res2.ChainHead != res.ChainHead {
		t.Fatalf("non-deterministic evaluation: %+v vs %+v", res, res2)
	}

	// Satisfy the missing rule and re-evaluate.
	if _, err := svc.RegisterStatement("app", StatementTypeTest, "ci-builder",
		map[string]string{"status": "ok"}); err != nil {
		t.Fatal(err)
	}
	res3, err := svc.Evaluate("app")
	if err != nil {
		t.Fatal(err)
	}
	if !res3.Passed {
		t.Fatalf("expected pass after registering test statement, got %+v", res3.FailedRules)
	}
	if res3.ChainLength != 3 {
		t.Fatalf("want chain length 3, got %d", res3.ChainLength)
	}
}

func TestServiceCrashRecoveryKeepsCommittedState(t *testing.T) {
	dir := t.TempDir()

	svc, err := OpenService(dir)
	if err != nil {
		t.Fatal(err)
	}
	registerN(t, svc, "app", 5)
	if err := svc.SetPolicy(Policy{Name: "p1", Rules: []Rule{
		{Name: "has-build", StatementType: StatementTypeBuild},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Evaluate("app"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart: committed statements, policy and conclusions must survive.
	svc2, err := OpenService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	if got := len(svc2.Statements("app")); got != 5 {
		t.Fatalf("want 5 statements after restart, got %d", got)
	}
	if verr := svc2.VerifyArtifact("app"); verr != nil {
		t.Fatalf("verify after restart: %v", verr)
	}
	if p := svc2.Policy(); p.Name != "p1" || len(p.Rules) != 1 {
		t.Fatalf("policy not recovered: %+v", p)
	}
	if got := len(svc2.Results()); got != 1 {
		t.Fatalf("want 1 historical conclusion, got %d", got)
	}
}
