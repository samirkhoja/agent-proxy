package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samirkhoja/agent-proxy/internal/model"
)

const (
	DefaultMaxBodyBytes    = 1 << 20
	DefaultMaxRequestBytes = 8 << 20
	DefaultPreviewChars    = 0
)

var defaultIncludeHosts = []string{
	"openai.com",
	"openai.azure.com",
	"anthropic.com",
	"generativelanguage.googleapis.com",
	"aiplatform.googleapis.com",
	"bedrock",
	"cohere.ai",
	"ollama",
	"localhost",
	"127.0.0.1",
	"::1",
}

var defaultRiskLevels = map[string]model.RiskLevel{
	"ssn":                model.RiskHigh,
	"openai_key":         model.RiskHigh,
	"anthropic_key":      model.RiskHigh,
	"aws_access_key":     model.RiskHigh,
	"jwt":                model.RiskHigh,
	"private_key_block":  model.RiskHigh,
	"credit_card":        model.RiskHigh,
	"high_entropy_token": model.RiskHigh,
	"email":              model.RiskMedium,
}

type Pattern struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

type Rules struct {
	Keywords        []string                   `json:"keywords"`
	CustomPatterns  []Pattern                  `json:"custom_patterns"`
	BlockPatterns   []string                   `json:"block_patterns"`
	RiskLevels      map[string]model.RiskLevel `json:"risk_levels,omitempty"`
	MaxBodyBytes    int64                      `json:"max_body_bytes"`
	MaxRequestBytes int64                      `json:"max_request_bytes"`
	PreviewChars    int                        `json:"preview_chars"`
	RedactPreview   bool                       `json:"redact_preview"`
	EntropyEnabled  bool                       `json:"entropy_enabled"`
	EntropyMinLen   int                        `json:"entropy_min_len"`
	EntropyMinScore float64                    `json:"entropy_min_score"`
	IncludeHosts    []string                   `json:"include_hosts"`
	ExcludeHosts    []string                   `json:"exclude_hosts"`
}

func DefaultRules() Rules {
	includes := make([]string, len(defaultIncludeHosts))
	copy(includes, defaultIncludeHosts)
	risks := make(map[string]model.RiskLevel, len(defaultRiskLevels))
	for k, v := range defaultRiskLevels {
		risks[k] = v
	}
	return Rules{
		MaxBodyBytes:    DefaultMaxBodyBytes,
		MaxRequestBytes: DefaultMaxRequestBytes,
		PreviewChars:    DefaultPreviewChars,
		RedactPreview:   true,
		EntropyEnabled:  true,
		EntropyMinLen:   24,
		EntropyMinScore: 3.8,
		IncludeHosts:    includes,
		RiskLevels:      risks,
	}
}

func LoadRules(path string) (Rules, error) {
	r := DefaultRules()
	if path == "" {
		return r, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return r, fmt.Errorf("read rules: %w", err)
	}

	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("parse rules json: %w", err)
	}
	if err := ValidateRules(r); err != nil {
		return r, err
	}
	return r, nil
}

func ValidateRules(r Rules) error {
	if r.MaxBodyBytes <= 0 {
		return errors.New("max_body_bytes must be > 0")
	}
	if r.MaxRequestBytes <= 0 {
		return errors.New("max_request_bytes must be > 0")
	}
	if r.PreviewChars < 0 {
		return errors.New("preview_chars must be >= 0")
	}
	if r.EntropyMinLen < 0 {
		return errors.New("entropy_min_len must be >= 0")
	}
	if r.EntropyMinScore < 0 {
		return errors.New("entropy_min_score must be >= 0")
	}
	for _, p := range r.CustomPatterns {
		if p.Name == "" {
			return errors.New("custom pattern name is required")
		}
		if p.Regex == "" {
			return fmt.Errorf("custom pattern %q regex is required", p.Name)
		}
	}
	for name, risk := range r.RiskLevels {
		n := strings.TrimSpace(name)
		if n == "" {
			return errors.New("risk_levels keys must be non-empty")
		}
		switch risk {
		case model.RiskLow, model.RiskMedium, model.RiskHigh:
		default:
			return fmt.Errorf("risk_levels[%q] must be one of: low, medium, high", n)
		}
	}
	return nil
}

func SaveRules(path string, r Rules) error {
	if path == "" {
		return errors.New("rules path is required")
	}
	if err := ValidateRules(r); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("ensure rules directory: %w", err)
	}

	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}
	b = append(b, '\n')

	// Write-then-rename avoids leaving a partially written rules file on crash.
	tmp, err := os.CreateTemp(filepath.Dir(path), "rules-*.json")
	if err != nil {
		return fmt.Errorf("create temp rules file: %w", err)
	}
	tmpPath := tmp.Name()
	success := false
	defer func() {
		_ = tmp.Close()
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(b); err != nil {
		return fmt.Errorf("write temp rules file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod temp rules file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp rules file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace rules file: %w", err)
	}
	success = true
	return nil
}
