package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/model"
)

type JSONLStore struct {
	path string
	mu   sync.Mutex
}

func NewJSONLStore(path string) *JSONLStore {
	return &JSONLStore{path: path}
}

func (s *JSONLStore) Append(e model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open events file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if err := enc.Encode(e); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

func ReadAll(path string) ([]model.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open events file: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReader(f))
	var out []model.Event
	for {
		var e model.Event
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return out, fmt.Errorf("decode events: %w", err)
		}
		out = append(out, e)
	}
	return out, nil
}

// PruneOlderThan removes events with timestamps older than cutoff.
// Events with zero timestamps are kept to avoid deleting malformed historical records.
func PruneOlderThan(path string, cutoff time.Time) (kept int, removed int, err error) {
	events, err := ReadAll(path)
	if err != nil {
		return 0, 0, err
	}
	if len(events) == 0 {
		return 0, 0, nil
	}

	filtered := make([]model.Event, 0, len(events))
	for _, e := range events {
		if e.Timestamp.IsZero() || !e.Timestamp.Before(cutoff) {
			filtered = append(filtered, e)
			continue
		}
		removed++
	}
	if removed == 0 {
		return len(events), 0, nil
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "events-prune-*.jsonl")
	if err != nil {
		return 0, 0, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	success := false
	defer func() {
		_ = tmp.Close()
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	enc := json.NewEncoder(tmp)
	for _, e := range filtered {
		if err := enc.Encode(e); err != nil {
			return 0, 0, fmt.Errorf("write pruned event: %w", err)
		}
	}
	if err := tmp.Chmod(0o600); err != nil {
		return 0, 0, fmt.Errorf("set temp mode: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, 0, fmt.Errorf("close temp file: %w", err)
	}
	// Atomic replace keeps readers from seeing a partially pruned file.
	if err := os.Rename(tmpPath, path); err != nil {
		return 0, 0, fmt.Errorf("replace events file: %w", err)
	}
	success = true
	return len(filtered), removed, nil
}
