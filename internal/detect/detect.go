package detect

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/samirkhoja/agent-proxy/internal/config"
	"github.com/samirkhoja/agent-proxy/internal/model"
)

type compiledPattern struct {
	name string
	re   *regexp.Regexp
}

type Detector struct {
	rules          config.Rules
	patterns       []compiledPattern
	keywordLower   []string
	blockPattern   map[string]struct{}
	riskLevels     map[string]model.RiskLevel
	tokenPattern   *regexp.Regexp
	creditCardRe   *regexp.Regexp
	keywordPattern *regexp.Regexp
}

func New(rules config.Rules) (*Detector, error) {
	patterns := []config.Pattern{
		{Name: "email", Regex: `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`},
		{Name: "ssn", Regex: `\b\d{3}-\d{2}-\d{4}\b`},
		{Name: "openai_key", Regex: `\bsk-[A-Za-z0-9]{20,}\b`},
		{Name: "anthropic_key", Regex: `\bsk-ant-[A-Za-z0-9_\-]{20,}\b`},
		{Name: "aws_access_key", Regex: `\bAKIA[0-9A-Z]{16}\b`},
		{Name: "jwt", Regex: `\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`},
		{Name: "private_key_block", Regex: `-----BEGIN [A-Z ]*PRIVATE KEY-----`},
	}
	patterns = append(patterns, rules.CustomPatterns...)

	compiled := make([]compiledPattern, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, compiledPattern{name: p.Name, re: re})
	}

	kw := make([]string, 0, len(rules.Keywords))
	for _, k := range rules.Keywords {
		if trimmed := strings.TrimSpace(strings.ToLower(k)); trimmed != "" {
			kw = append(kw, trimmed)
		}
	}

	blockSet := make(map[string]struct{}, len(rules.BlockPatterns))
	for _, name := range rules.BlockPatterns {
		if n := strings.TrimSpace(strings.ToLower(name)); n != "" {
			blockSet[n] = struct{}{}
		}
	}
	riskLevels := make(map[string]model.RiskLevel, len(rules.RiskLevels))
	for name, risk := range rules.RiskLevels {
		if n := strings.TrimSpace(strings.ToLower(name)); n != "" {
			riskLevels[n] = risk
		}
	}

	tokenPattern, err := regexp.Compile(`[A-Za-z0-9_\-]{24,}`)
	if err != nil {
		return nil, err
	}
	creditCardRe, err := regexp.Compile(`\b(?:\d[ -]*?){13,19}\b`)
	if err != nil {
		return nil, err
	}

	return &Detector{
		rules:        rules,
		patterns:     compiled,
		keywordLower: kw,
		blockPattern: blockSet,
		riskLevels:   riskLevels,
		tokenPattern: tokenPattern,
		creditCardRe: creditCardRe,
	}, nil
}

func (d *Detector) Scan(body []byte) ([]model.Finding, bool) {
	if len(body) == 0 {
		return nil, false
	}
	text := string(body)

	agg := map[string]*model.Finding{}

	for _, p := range d.patterns {
		all := p.re.FindAllString(text, -1)
		if len(all) == 0 {
			continue
		}
		for _, m := range all {
			addFinding(agg, p.name, m)
		}
	}

	// Credit card detection with Luhn filtering.
	for _, candidate := range d.creditCardRe.FindAllString(text, -1) {
		digits := onlyDigits(candidate)
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if passesLuhn(digits) {
			addFinding(agg, "credit_card", candidate)
		}
	}

	if len(d.keywordLower) > 0 {
		lower := strings.ToLower(text)
		for _, kw := range d.keywordLower {
			if strings.Contains(lower, kw) {
				addFinding(agg, "keyword:"+kw, kw)
			}
		}
	}

	if d.rules.EntropyEnabled {
		// Entropy-based check is a fallback for secrets that evade known regexes.
		for _, token := range d.tokenPattern.FindAllString(text, -1) {
			if len(token) < d.rules.EntropyMinLen {
				continue
			}
			if !looksSecretLike(token) {
				continue
			}
			if shannonEntropy(token) >= d.rules.EntropyMinScore {
				addFinding(agg, "high_entropy_token", token)
			}
		}
	}

	if len(agg) == 0 {
		return nil, false
	}

	findings := make([]model.Finding, 0, len(agg))
	for _, f := range agg {
		f.Risk = d.riskForFinding(f.Name)
		if _, ok := d.blockPattern[strings.ToLower(f.Name)]; ok {
			f.Blocked = true
		}
		findings = append(findings, *f)
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Name < findings[j].Name
	})
	return findings, true
}

func addFinding(agg map[string]*model.Finding, name, sample string) {
	f, ok := agg[name]
	if !ok {
		agg[name] = &model.Finding{Name: name, Sample: compactSample(sample), Count: 1}
		return
	}
	f.Count++
	if f.Sample == "" {
		f.Sample = compactSample(sample)
	}
}

func compactSample(s string) string {
	return strings.TrimSpace(s)
}

func onlyDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func passesLuhn(s string) bool {
	sum := 0
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if alt {
			d = d * 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func looksSecretLike(token string) bool {
	var hasLower, hasUpper, hasDigit bool
	for _, r := range token {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	return hasLower && hasUpper && hasDigit
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	count := map[rune]float64{}
	for _, r := range s {
		count[r]++
	}
	var entropy float64
	l := float64(len(s))
	for _, c := range count {
		p := c / l
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func RedactPreview(preview string, findings []model.Finding) string {
	out := preview
	for _, f := range findings {
		sample := strings.TrimSpace(f.Sample)
		if sample == "" {
			continue
		}
		token := "[REDACTED:" + f.Name + "]"
		out = strings.ReplaceAll(out, sample, token)
	}
	return out
}

func (d *Detector) riskForFinding(name string) model.RiskLevel {
	key := strings.ToLower(strings.TrimSpace(name))
	if risk, ok := d.riskLevels[key]; ok {
		return risk
	}
	if strings.HasPrefix(key, "keyword:") {
		return model.RiskMedium
	}
	return model.RiskMedium
}
