package provenance

import "fmt"

// Rule 描述一条策略规则：要求链中存在满足条件的声明。
type Rule struct {
	Name     string            `json:"name"`      // 规则名，用于报告
	Type     string            `json:"type"`      // 要求的声明类型
	Match    map[string]string `json:"match"`     // 内容匹配条件（全部键值相等才算匹配）
	MinCount int               `json:"min_count"` // 至少需要的匹配条数，<=0 视为 1
}

// Policy 由多条规则组成，全部满足才判定通过。
type Policy struct {
	Rules []Rule `json:"rules"`
}

// UnsatisfiedRule 记录一条未满足的规则及原因。
type UnsatisfiedRule struct {
	Rule     Rule   `json:"rule"`
	Found    int    `json:"found"`    // 实际匹配条数
	Required int    `json:"required"` // 要求的最少条数
	Reason   string `json:"reason"`
}

// PolicyResult 是策略判定结果，确定性输出。
type PolicyResult struct {
	ArtifactID  string            `json:"artifact_id"`
	Statements  int               `json:"statements"` // 判定时基于的链长度
	HeadHash    string            `json:"head_hash"`  // 判定时基于的链头摘要
	Satisfied   bool              `json:"satisfied"`
	Unsatisfied []UnsatisfiedRule `json:"unsatisfied,omitempty"`
}

// Evaluate 对给定声明快照执行策略判定。
// 确定性：规则按声明顺序逐条匹配，未满足规则按策略中声明的顺序输出。
func Evaluate(p Policy, artifactID string, stmts []Statement) PolicyResult {
	res := PolicyResult{ArtifactID: artifactID, Statements: len(stmts)}
	if len(stmts) > 0 {
		res.HeadHash = stmts[len(stmts)-1].Hash
	}

	for _, r := range p.Rules {
		required := r.MinCount
		if required <= 0 {
			required = 1
		}
		found := 0
		for _, st := range stmts {
			if matchRule(r, st) {
				found++
			}
		}
		if found < required {
			res.Unsatisfied = append(res.Unsatisfied, UnsatisfiedRule{
				Rule:     r,
				Found:    found,
				Required: required,
				Reason: fmt.Sprintf("rule %q requires at least %d statement(s) of type %q matching %v, found %d",
					r.Name, required, r.Type, r.Match, found),
			})
		}
	}
	res.Satisfied = len(res.Unsatisfied) == 0
	return res
}

// matchRule 判断单条声明是否满足规则的类型与内容条件。
// 规则的每个 Match 键都必须存在于声明内容中且值相等。
func matchRule(r Rule, st Statement) bool {
	if st.Type != r.Type {
		return false
	}
	for k, v := range r.Match {
		if st.Content[k] != v {
			return false
		}
	}
	return true
}
