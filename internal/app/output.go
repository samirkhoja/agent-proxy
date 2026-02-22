package app

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/model"
)

func printEventLine(e model.Event) {
	ts := e.Timestamp.Format(time.RFC3339)
	if ts == "0001-01-01T00:00:00Z" {
		ts = "unknown-time"
	}
	action := colorizeAction(e.Action)
	risk := colorizeRiskLabel(eventRiskLevel(e))
	target := strings.TrimSpace(e.URL)
	if target == "" {
		target = e.Host
	}
	fmt.Printf("[%s] %s %s | action=%s risk=%s | sensitive=%t bytes=%d\n", ts, e.Method, target, action, risk, e.Sensitive, e.BodyBytes)
	if len(e.Findings) > 0 {
		names := make([]string, 0, len(e.Findings))
		for _, f := range e.Findings {
			names = append(names, colorizeFinding(f))
		}
		fmt.Printf("  findings: %s\n", strings.Join(names, ", "))
	}
	if e.BodyPreview != "" {
		fmt.Printf("  preview: %s\n", e.BodyPreview)
	}
	if e.Error != "" {
		fmt.Printf("  error: %s\n", e.Error)
	}
}

func eventRiskLevel(e model.Event) string {
	if e.Action == model.ActionBlock {
		return "high"
	}
	for _, f := range e.Findings {
		if f.Risk == model.RiskHigh || f.Blocked {
			return "high"
		}
	}
	if hasRisk(e.Findings, model.RiskMedium) || e.Sensitive {
		return "medium"
	}
	return "low"
}

func colorizeAction(action model.Action) string {
	switch action {
	case model.ActionBlock:
		return paint(string(action), ansiRed)
	case model.ActionAlert:
		return paint(string(action), ansiYellow)
	case model.ActionAllow:
		return paint(string(action), ansiGreen)
	case model.ActionSkip:
		return paint(string(action), ansiCyan)
	default:
		return string(action)
	}
}

func colorizeRiskLabel(level string) string {
	switch strings.ToLower(level) {
	case "high":
		return paint(strings.ToUpper(level), ansiRed)
	case "medium":
		return paint(strings.ToUpper(level), ansiYellow)
	default:
		return paint(strings.ToUpper(level), ansiGreen)
	}
}

func colorizeFinding(f model.Finding) string {
	label := fmt.Sprintf("%s(x%d)", f.Name, f.Count)
	if f.Blocked || f.Risk == model.RiskHigh {
		return paint(label, ansiRed)
	}
	if f.Risk == model.RiskLow {
		return paint(label, ansiGreen)
	}
	return paint(label, ansiYellow)
}

func hasRisk(findings []model.Finding, risk model.RiskLevel) bool {
	for _, f := range findings {
		if f.Risk == risk {
			return true
		}
	}
	return false
}

func paint(text, colorCode string) string {
	if !shouldUseANSIColor() {
		return text
	}
	return colorCode + text + ansiReset
}

func shouldUseANSIColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("CLICOLOR_FORCE") == "1" {
		return true
	}
	term := strings.ToLower(strings.TrimSpace(os.Getenv("TERM")))
	if term == "" || term == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)
