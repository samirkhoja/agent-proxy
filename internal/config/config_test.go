package config

import (
	"path/filepath"
	"testing"

	"github.com/samirkhoja/agent-proxy/internal/model"
)

func TestSaveRulesRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "rules.json")
	r := DefaultRules()
	r.CustomPatterns = append(r.CustomPatterns, Pattern{Name: "employee_id", Regex: `EMP[0-9]{6}`})

	if err := SaveRules(path, r); err != nil {
		t.Fatalf("SaveRules: %v", err)
	}
	loaded, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if len(loaded.CustomPatterns) != 1 {
		t.Fatalf("expected one custom pattern, got %d", len(loaded.CustomPatterns))
	}
	if loaded.CustomPatterns[0].Name != "employee_id" {
		t.Fatalf("unexpected pattern name: %s", loaded.CustomPatterns[0].Name)
	}
}

func TestDefaultRulesSafetyDefaults(t *testing.T) {
	r := DefaultRules()
	if r.MaxRequestBytes <= 0 {
		t.Fatalf("expected max_request_bytes > 0")
	}
	if len(r.IncludeHosts) == 0 {
		t.Fatalf("expected default include hosts to be non-empty")
	}
	if len(r.RiskLevels) == 0 {
		t.Fatalf("expected default risk levels to be non-empty")
	}
}

func TestValidateRulesRejectsInvalidRiskLevel(t *testing.T) {
	r := DefaultRules()
	r.RiskLevels["foo"] = model.RiskLevel("critical")
	if err := ValidateRules(r); err == nil {
		t.Fatalf("expected ValidateRules to fail for invalid risk level")
	}
}
