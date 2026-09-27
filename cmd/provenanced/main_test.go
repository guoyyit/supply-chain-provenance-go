package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guoyyit/supply-chain-provenance-go/provenance"
)

func do(t *testing.T, mux http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestHTTPEndToEnd(t *testing.T) {
	dir := t.TempDir()

	svc, err := provenance.OpenService(dir)
	if err != nil {
		t.Fatal(err)
	}
	mux := newMux(svc)

	// Register two statements.
	for _, typ := range []string{"build", "material"} {
		rec := do(t, mux, http.MethodPost, "/v1/artifacts/app/statements", map[string]any{
			"type": typ, "subject": "ci", "content": map[string]string{"k": "v"},
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("register %s: status %d body %s", typ, rec.Code, rec.Body)
		}
	}

	// Verify chain.
	if rec := do(t, mux, http.MethodGet, "/v1/artifacts/app/verify", nil); rec.Code != http.StatusOK {
		t.Fatalf("verify: status %d body %s", rec.Code, rec.Body)
	}

	// Set a policy that requires a test statement (not yet registered).
	rec := do(t, mux, http.MethodPut, "/v1/policy", map[string]any{
		"name": "gate",
		"rules": []map[string]any{
			{"name": "has-build", "statement_type": "build"},
			{"name": "has-test", "statement_type": "test"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("set policy: status %d body %s", rec.Code, rec.Body)
	}

	// Evaluate: must fail and name the missing rule.
	rec = do(t, mux, http.MethodPost, "/v1/artifacts/app/evaluate", nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("evaluate: status %d body %s", rec.Code, rec.Body)
	}
	var result provenance.PolicyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Passed || len(result.FailedRules) != 1 || result.FailedRules[0].Rule.Name != "has-test" {
		t.Fatalf("unexpected evaluation: %+v", result)
	}

	// Restart the service on the same dir: statements, policy and the
	// historical conclusion must survive.
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	svc2, err := provenance.OpenService(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc2.Close()
	mux2 := newMux(svc2)

	rec = do(t, mux2, http.MethodGet, "/v1/artifacts/app/statements", nil)
	var list struct {
		Statements []provenance.Statement `json:"statements"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Statements) != 2 {
		t.Fatalf("want 2 statements after restart, got %d", len(list.Statements))
	}
	rec = do(t, mux2, http.MethodGet, "/v1/results", nil)
	var results struct {
		Results []provenance.PolicyResult `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results.Results) != 1 || results.Results[0].PolicyName != "gate" {
		t.Fatalf("historical conclusions lost: %+v", results.Results)
	}
}
