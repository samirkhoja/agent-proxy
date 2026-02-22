package model

import "time"

type Action string

const (
	ActionAllow Action = "allow"
	ActionAlert Action = "alert"
	ActionBlock Action = "block"
	ActionSkip  Action = "skip"
)

type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// Event represents one outbound request observation.
type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	Provider    string    `json:"provider"`
	Host        string    `json:"host"`
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	Sensitive   bool      `json:"sensitive"`
	Action      Action    `json:"action"`
	Findings    []Finding `json:"findings,omitempty"`
	BodyPreview string    `json:"body_preview,omitempty"`
	BodyBytes   int       `json:"body_bytes"`
	Truncated   bool      `json:"truncated"`
	TLS         bool      `json:"tls"`
	Error       string    `json:"error,omitempty"`
}

// Finding captures one detector hit.
type Finding struct {
	Name    string    `json:"name"`
	Sample  string    `json:"sample,omitempty"`
	Count   int       `json:"count"`
	Blocked bool      `json:"blocked"`
	Risk    RiskLevel `json:"risk,omitempty"`
}
