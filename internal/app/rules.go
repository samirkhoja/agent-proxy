package app

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samirkhoja/agent-proxy/internal/config"
	"github.com/samirkhoja/agent-proxy/internal/model"
	"github.com/samirkhoja/agent-proxy/internal/util"
)

func runRules(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentproxy rules [add-regex|list] [flags]")
		return 1
	}
	switch args[0] {
	case "add-regex":
		return runRulesAddRegex(args[1:])
	case "list":
		return runRulesList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown rules command: %s\n", args[0])
		return 1
	}
}

func runRulesAddRegex(args []string) int {
	fs := flag.NewFlagSet("rules add-regex", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", util.DefaultDataDir(), "agentproxy data directory")
	file := fs.String("file", "", "rules file path (default: <dir>/rules.json)")
	name := fs.String("name", "", "pattern name")
	expr := fs.String("regex", "", "regular expression to add")
	risk := fs.String("risk", "", "risk level for this pattern: low|medium|high")
	block := fs.Bool("block", false, "add this pattern name to block_patterns")
	replace := fs.Bool("replace", false, "replace existing custom pattern with same name")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	n := strings.TrimSpace(*name)
	rx := strings.TrimSpace(*expr)
	if n == "" {
		fmt.Fprintln(os.Stderr, "--name is required")
		return 1
	}
	if rx == "" {
		fmt.Fprintln(os.Stderr, "--regex is required")
		return 1
	}
	if _, err := regexp.Compile(rx); err != nil {
		fmt.Fprintf(os.Stderr, "invalid --regex: %v\n", err)
		return 1
	}
	patternRisk, hasPatternRisk, err := parseRiskFlag(*risk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --risk: %v\n", err)
		return 1
	}

	rulesPath := strings.TrimSpace(*file)
	if rulesPath == "" {
		rulesPath = util.RulesPath(*dir)
	}
	if err := util.EnsureDir(filepath.Dir(rulesPath)); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create rules directory: %v\n", err)
		return 1
	}

	rules := config.DefaultRules()
	if _, err := os.Stat(rulesPath); err == nil {
		// Preserve existing non-regex settings when extending rules.
		loaded, err := config.LoadRules(rulesPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load rules file: %v\n", err)
			return 1
		}
		rules = loaded
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "failed to access rules file: %v\n", err)
		return 1
	}

	pattern := config.Pattern{Name: n, Regex: rx}
	replaced := false
	for i := range rules.CustomPatterns {
		if strings.EqualFold(rules.CustomPatterns[i].Name, n) {
			if !*replace {
				fmt.Fprintf(os.Stderr, "custom pattern %q already exists; use --replace to update it\n", n)
				return 1
			}
			rules.CustomPatterns[i] = pattern
			replaced = true
			break
		}
	}
	if !replaced {
		rules.CustomPatterns = append(rules.CustomPatterns, pattern)
	}

	if *block && !containsFold(rules.BlockPatterns, n) {
		rules.BlockPatterns = append(rules.BlockPatterns, n)
	}
	if rules.RiskLevels == nil {
		rules.RiskLevels = map[string]model.RiskLevel{}
	}
	if hasPatternRisk {
		rules.RiskLevels[n] = patternRisk
	}

	if err := config.SaveRules(rulesPath, rules); err != nil {
		fmt.Fprintf(os.Stderr, "failed to save rules file: %v\n", err)
		return 1
	}

	action := "added"
	if replaced {
		action = "updated"
	}
	fmt.Printf("rules update: %s %q\n", action, n)
	fmt.Printf("  file: %s\n", rulesPath)
	if *block {
		fmt.Printf("  block pattern: %s\n", n)
	}
	if hasPatternRisk {
		fmt.Printf("  risk: %s\n", patternRisk)
	}
	fmt.Printf("  run with: agentproxy run --rules %s\n", rulesPath)
	return 0
}

func runRulesList(args []string) int {
	fs := flag.NewFlagSet("rules list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", util.DefaultDataDir(), "agentproxy data directory")
	file := fs.String("file", "", "rules file path (default: <dir>/rules.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rulesPath := strings.TrimSpace(*file)
	if rulesPath == "" {
		rulesPath = util.RulesPath(*dir)
	}
	if _, err := os.Stat(rulesPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("no rules file at %s\n", rulesPath)
			return 0
		}
		fmt.Fprintf(os.Stderr, "failed to access rules file: %v\n", err)
		return 1
	}

	rules, err := config.LoadRules(rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load rules file: %v\n", err)
		return 1
	}
	fmt.Printf("rules file: %s\n", rulesPath)
	if len(rules.CustomPatterns) == 0 {
		fmt.Println("custom patterns: (none)")
		return 0
	}
	fmt.Println("custom patterns:")
	for _, p := range rules.CustomPatterns {
		blocked := ""
		if containsFold(rules.BlockPatterns, p.Name) {
			blocked = " [block]"
		}
		risk := lookupRisk(rules, p.Name)
		fmt.Printf("  - %s = %s [risk=%s]%s\n", p.Name, p.Regex, risk, blocked)
	}
	return 0
}

func containsFold(list []string, needle string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(needle)) {
			return true
		}
	}
	return false
}

func parseRiskFlag(raw string) (model.RiskLevel, bool, error) {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	if trimmed == "" {
		return model.RiskMedium, false, nil
	}
	switch model.RiskLevel(trimmed) {
	case model.RiskLow, model.RiskMedium, model.RiskHigh:
		return model.RiskLevel(trimmed), true, nil
	default:
		return "", false, errors.New("must be one of: low, medium, high")
	}
}

func lookupRisk(rules config.Rules, patternName string) model.RiskLevel {
	if rules.RiskLevels != nil {
		if r, ok := rules.RiskLevels[patternName]; ok {
			return r
		}
		for k, r := range rules.RiskLevels {
			if strings.EqualFold(k, patternName) {
				return r
			}
		}
	}
	return model.RiskMedium
}
