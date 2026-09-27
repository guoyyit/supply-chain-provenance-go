package provenance

import (
	"fmt"
	"strings"
)

// MatchOp is a content matching operator.
type MatchOp string

const (
	// OpExists requires the field to be present.
	OpExists MatchOp = "exists"
	// OpEquals requires the field value to equal Value exactly.
	OpEquals MatchOp = "equals"
	// OpContains requires the field value to contain Value as a substring.
	OpContains MatchOp = "contains"
)

// Condition matches one Content field of a statement.
type Condition struct {
	Field string  `json:"field"`
	Op    MatchOp `json:"op"`
	Value string  `json:"value,omitempty"`
}

// Rule requires at least one statement of StatementType for which every
// Condition matches. Rules are evaluated in declared order.
type Rule struct {
	Name          string        `json:"name"`
	StatementType StatementType `json:"statement_type"`
	Conditions    []Condition   `json:"conditions,omitempty"`
}

// Policy is an ordered set of rules; release is allowed only when every rule
// is satisfied. A policy with no rules passes vacuously.
type Policy struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

// RuleResult reports the outcome of one rule.
type RuleResult struct {
	Rule      Rule   `json:"rule"`
	Satisfied bool   `json:"satisfied"`
	Detail    string `json:"detail,omitempty"`
}

// PolicyResult is the deterministic outcome of evaluating a policy.
type PolicyResult struct {
	PolicyName  string       `json:"policy_name"`
	ArtifactID  string       `json:"artifact_id"`
	Passed      bool         `json:"passed"`
	FailedRules []RuleResult `json:"failed_rules,omitempty"`
	ChainHead   Digest       `json:"chain_head"`
	ChainLength int          `json:"chain_length"`
}

// Evaluate deterministically evaluates p against statements. Statements are
// scanned in chain order; the first matching statement satisfies each rule.
// Failed rules are reported in declared policy order. This function is pure:
// callers must ensure the statements form a verified chain.
func Evaluate(p Policy, artifactID string, statements []Statement, head Digest) PolicyResult {
	res := PolicyResult{
		PolicyName:  p.Name,
		ArtifactID:  artifactID,
		Passed:      true,
		ChainHead:   head,
		ChainLength: len(statements),
	}
	for _, rule := range p.Rules {
		satisfied, detail := evaluateRule(rule, statements)
		if !satisfied {
			res.Passed = false
			res.FailedRules = append(res.FailedRules, RuleResult{
				Rule:      rule,
				Satisfied: false,
				Detail:    detail,
			})
		}
	}
	return res
}

// evaluateRule returns whether at least one statement satisfies the rule and,
// if not, a deterministic explanation of why.
func evaluateRule(rule Rule, statements []Statement) (bool, string) {
	var typeSeen bool
	for _, st := range statements {
		if st.Type != rule.StatementType {
			continue
		}
		typeSeen = true
		if ok, cond := matchConditions(rule.Conditions, st.Content); ok {
			return true, ""
		} else {
			// remember the last failing condition deterministically (first
			// condition of the last matching-type statement in chain order)
			_ = cond
		}
	}
	if !typeSeen {
		return false, fmt.Sprintf("no statement of type %q found", rule.StatementType)
	}
	return false, fmt.Sprintf("statement of type %q exists but conditions not met: %s",
		rule.StatementType, describeConditions(rule.Conditions))
}

// matchConditions reports whether all conditions match content. On failure it
// returns the first unsatisfied condition (in declared order).
func matchConditions(conditions []Condition, content map[string]string) (bool, Condition) {
	for _, cond := range conditions {
		val, present := content[cond.Field]
		switch cond.Op {
		case OpExists:
			if !present {
				return false, cond
			}
		case OpEquals:
			if !present || val != cond.Value {
				return false, cond
			}
		case OpContains:
			if !present || !strings.Contains(val, cond.Value) {
				return false, cond
			}
		default:
			return false, cond
		}
	}
	return true, Condition{}
}

// describeConditions renders conditions in declared (deterministic) order for
// error messages.
func describeConditions(conditions []Condition) string {
	parts := make([]string, 0, len(conditions))
	for _, c := range conditions {
		if c.Op == OpExists {
			parts = append(parts, fmt.Sprintf("%s[%s]", c.Field, c.Op))
		} else {
			parts = append(parts, fmt.Sprintf("%s[%s %q]", c.Field, c.Op, c.Value))
		}
	}
	return strings.Join(parts, " AND ")
}
