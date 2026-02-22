package app

import (
	"path/filepath"
	"testing"

	"github.com/samirkhoja/agent-proxy/internal/config"
	"github.com/samirkhoja/agent-proxy/internal/model"
)

func TestRunRulesAddRegex(t *testing.T) {
	tmp := t.TempDir()
	rulesPath := filepath.Join(tmp, "rules.json")

	code := runRulesAddRegex([]string{
		"--file", rulesPath,
		"--name", "customer_id",
		"--regex", `CUST-[0-9]{6}`,
		"--risk", "high",
		"--block",
	})
	if code != 0 {
		t.Fatalf("runRulesAddRegex returned %d", code)
	}

	rules, err := config.LoadRules(rulesPath)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if !hasCustomPattern(rules, "customer_id", `CUST-[0-9]{6}`) {
		t.Fatalf("custom pattern was not written: %+v", rules.CustomPatterns)
	}
	if !containsFold(rules.BlockPatterns, "customer_id") {
		t.Fatalf("expected customer_id to be in block patterns")
	}
	if got := rules.RiskLevels["customer_id"]; got != model.RiskHigh {
		t.Fatalf("expected customer_id risk high, got %q", got)
	}

	code = runRulesAddRegex([]string{
		"--file", rulesPath,
		"--name", "customer_id",
		"--regex", `CUST-[A-Z]{6}`,
	})
	if code == 0 {
		t.Fatalf("expected duplicate add without --replace to fail")
	}

	code = runRulesAddRegex([]string{
		"--file", rulesPath,
		"--name", "customer_id",
		"--regex", `CUST-[A-Z]{6}`,
		"--risk", "medium",
		"--replace",
	})
	if code != 0 {
		t.Fatalf("replace returned %d", code)
	}

	rules, err = config.LoadRules(rulesPath)
	if err != nil {
		t.Fatalf("load rules after replace: %v", err)
	}
	if !hasCustomPattern(rules, "customer_id", `CUST-[A-Z]{6}`) {
		t.Fatalf("custom pattern was not replaced: %+v", rules.CustomPatterns)
	}
	if got := rules.RiskLevels["customer_id"]; got != model.RiskMedium {
		t.Fatalf("expected customer_id risk medium after replace, got %q", got)
	}
}

func hasCustomPattern(r config.Rules, name, regex string) bool {
	for _, p := range r.CustomPatterns {
		if p.Name == name && p.Regex == regex {
			return true
		}
	}
	return false
}
