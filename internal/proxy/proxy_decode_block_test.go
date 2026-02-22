package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/config"
	"github.com/samirkhoja/agent-proxy/internal/model"
	"github.com/samirkhoja/agent-proxy/internal/store"
	"github.com/samirkhoja/agent-proxy/internal/util"
)

func TestForwardRequestBlocksUnsupportedEncoding(t *testing.T) {
	tmp := t.TempDir()
	if _, err := SetupCA(tmp, "agentproxy test ca", false); err != nil {
		t.Fatalf("setup ca: %v", err)
	}

	srv, err := NewServer(Options{
		Listen:  "127.0.0.1:8787",
		DataDir: tmp,
		Rules:   config.DefaultRules(),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", io.NopCloser(strings.NewReader("compressed")))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Encoding", "br")

	resp := srv.forwardRequest(req, true)
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d want=%d", resp.StatusCode, http.StatusUnsupportedMediaType)
	}
	_ = resp.Body.Close()

	events, err := store.ReadAll(util.EventsPath(tmp))
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].Action != model.ActionBlock {
		t.Fatalf("expected action block, got %q", events[0].Action)
	}
	if events[0].Error == "" {
		t.Fatalf("expected decode error to be logged")
	}
}

func TestForwardRequestAutoBlocksHighRiskFinding(t *testing.T) {
	tmp := t.TempDir()
	if _, err := SetupCA(tmp, "agentproxy test ca", false); err != nil {
		t.Fatalf("setup ca: %v", err)
	}

	rules := config.DefaultRules()
	// Do not block all sensitive requests; only test auto high-risk behavior.
	srv, err := NewServer(Options{
		Listen:            "127.0.0.1:8787",
		DataDir:           tmp,
		Rules:             rules,
		AutoBlockHighRisk: true,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", io.NopCloser(strings.NewReader(`{"input":"key sk-abcdefghijklmnopqrstuvwxy12345"}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	resp := srv.forwardRequest(req, true)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", resp.StatusCode, http.StatusForbidden)
	}
	_ = resp.Body.Close()

	events, err := store.ReadAll(util.EventsPath(tmp))
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].Action != model.ActionBlock {
		t.Fatalf("expected action block, got %q", events[0].Action)
	}
	if len(events[0].Findings) == 0 {
		t.Fatalf("expected high-risk finding to be logged")
	}
	if events[0].Findings[0].Risk != model.RiskHigh {
		t.Fatalf("expected high risk finding, got %q", events[0].Findings[0].Risk)
	}
}

func TestForwardRequestCallsEventSink(t *testing.T) {
	tmp := t.TempDir()
	if _, err := SetupCA(tmp, "agentproxy test ca", false); err != nil {
		t.Fatalf("setup ca: %v", err)
	}

	var sinkEvents []model.Event
	sinkDone := make(chan struct{}, 1)
	srv, err := NewServer(Options{
		Listen:  "127.0.0.1:8787",
		DataDir: tmp,
		Rules:   config.DefaultRules(),
		EventSink: func(e model.Event) {
			sinkEvents = append(sinkEvents, e)
			select {
			case sinkDone <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", io.NopCloser(strings.NewReader("compressed")))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Encoding", "br")

	resp := srv.forwardRequest(req, true)
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d want=%d", resp.StatusCode, http.StatusUnsupportedMediaType)
	}
	_ = resp.Body.Close()

	select {
	case <-sinkDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for sink event")
	}
	if len(sinkEvents) != 1 {
		t.Fatalf("expected sink to receive one event, got %d", len(sinkEvents))
	}
	if sinkEvents[0].Action != model.ActionBlock {
		t.Fatalf("expected sink event action block, got %q", sinkEvents[0].Action)
	}
}
