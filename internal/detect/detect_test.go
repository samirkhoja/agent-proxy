package detect

import (
	"strings"
	"testing"

	"github.com/samirkhoja/agent-proxy/internal/config"
	"github.com/samirkhoja/agent-proxy/internal/model"
)

func TestScanBuiltinsAndBlocking(t *testing.T) {
	rules := config.DefaultRules()
	rules.BlockPatterns = []string{"ssn"}
	d, err := New(rules)
	if err != nil {
		t.Fatalf("New detector: %v", err)
	}

	payload := []byte(`{"input":"Contact me at me@example.com ssn 123-45-6789"}`)
	findings, sensitive := d.Scan(payload)
	if !sensitive {
		t.Fatalf("expected sensitive=true")
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings")
	}

	var hasEmail, hasSSN, ssnBlocked bool
	for _, f := range findings {
		if f.Name == "email" {
			hasEmail = true
		}
		if f.Name == "ssn" {
			hasSSN = true
			if f.Blocked {
				ssnBlocked = true
			}
		}
	}
	if !hasEmail || !hasSSN {
		t.Fatalf("expected email and ssn findings, got %+v", findings)
	}
	if !ssnBlocked {
		t.Fatalf("expected ssn finding to be blocked")
	}
}

func TestRedactPreview(t *testing.T) {
	in := "token sk-abc123abc123abc123abc123"
	redacted := RedactPreview(in, []model.Finding{{Name: "openai_key", Sample: "sk-abc123abc123abc123abc123", Count: 1}})
	if redacted == in {
		t.Fatalf("expected preview to be redacted")
	}
}

func TestRedactPreviewLongMatch(t *testing.T) {
	longSecret := "sk-" + strings.Repeat("A", 180)
	in := "token=" + longSecret
	redacted := RedactPreview(in, []model.Finding{{Name: "openai_key", Sample: longSecret, Count: 1}})
	if strings.Contains(redacted, longSecret) {
		t.Fatalf("expected long secret to be fully redacted, got: %q", redacted)
	}
}
