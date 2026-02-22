package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/model"
)

func TestPruneOlderThan(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "events.jsonl")
	s := NewJSONLStore(path)

	now := time.Now().UTC()
	old := model.Event{Timestamp: now.Add(-10 * 24 * time.Hour), Provider: "openai"}
	newer := model.Event{Timestamp: now.Add(-2 * time.Hour), Provider: "anthropic"}

	if err := s.Append(old); err != nil {
		t.Fatalf("append old: %v", err)
	}
	if err := s.Append(newer); err != nil {
		t.Fatalf("append newer: %v", err)
	}

	kept, removed, err := PruneOlderThan(path, now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	if removed != 1 || kept != 1 {
		t.Fatalf("got kept=%d removed=%d, want kept=1 removed=1", kept, removed)
	}

	events, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(events) != 1 || events[0].Provider != "anthropic" {
		t.Fatalf("unexpected events after prune: %+v", events)
	}
}
