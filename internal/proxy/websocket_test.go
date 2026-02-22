package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/config"
	"github.com/samirkhoja/agent-proxy/internal/model"
	"github.com/samirkhoja/agent-proxy/internal/store"
	"github.com/samirkhoja/agent-proxy/internal/util"
)

func TestForwardWebSocketClientFramesAllowsAndForwardsText(t *testing.T) {
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

	frame := buildMaskedClientTextFrame([]byte(`{"input":"hello world"}`))
	reader := bufio.NewReader(bytes.NewReader(frame))
	var client bytes.Buffer
	var upstream bytes.Buffer
	target, _ := url.Parse("https://api.openai.com/v1/realtime")

	blocked, err := srv.forwardWebSocketClientFrames(reader, &client, &upstream, target, "openai", true)
	if blocked {
		t.Fatalf("expected blocked=false")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	if !bytes.Equal(upstream.Bytes(), frame) {
		t.Fatalf("expected forwarded frame bytes to match original frame")
	}
	if client.Len() != 0 {
		t.Fatalf("expected no close frame written to client on allow")
	}

	events, err := store.ReadAll(util.EventsPath(tmp))
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].Method != "WS" {
		t.Fatalf("expected method WS, got %q", events[0].Method)
	}
	if events[0].Action != model.ActionAllow {
		t.Fatalf("expected action allow, got %q", events[0].Action)
	}
}

func TestForwardWebSocketClientFramesBlocksSensitiveMessage(t *testing.T) {
	tmp := t.TempDir()
	if _, err := SetupCA(tmp, "agentproxy test ca", false); err != nil {
		t.Fatalf("setup ca: %v", err)
	}
	srv, err := NewServer(Options{
		Listen:           "127.0.0.1:8787",
		DataDir:          tmp,
		Rules:            config.DefaultRules(),
		BlockOnSensitive: true,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	frame := buildMaskedClientTextFrame([]byte(`{"input":"token sk-abcdefghijklmnopqrstuvwxy12345"}`))
	reader := bufio.NewReader(bytes.NewReader(frame))
	var client bytes.Buffer
	var upstream bytes.Buffer
	target, _ := url.Parse("https://api.openai.com/v1/realtime")

	blocked, err := srv.forwardWebSocketClientFrames(reader, &client, &upstream, target, "openai", true)
	if !blocked {
		t.Fatalf("expected blocked=true")
	}
	if err != nil {
		t.Fatalf("expected nil error when blocked, got %v", err)
	}
	if client.Len() == 0 {
		t.Fatalf("expected protocol close frame sent to client")
	}
	code, ok := parseCloseFrameCode(client.Bytes(), false)
	if !ok || code != websocketClosePolicyViolation {
		t.Fatalf("expected client close code %d, got %d (ok=%t)", websocketClosePolicyViolation, code, ok)
	}
	if upstream.Len() == 0 {
		t.Fatalf("expected upstream close frame sent")
	}
	if _, ok := parseCloseFrameCode(upstream.Bytes(), true); !ok {
		t.Fatalf("expected masked upstream close frame")
	}

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
		t.Fatalf("expected findings for blocked websocket message")
	}
}

func TestForwardWebSocketClientFramesSkipForUnconfiguredHost(t *testing.T) {
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

	frame := buildMaskedClientTextFrame([]byte(`{"input":"hello world"}`))
	reader := bufio.NewReader(bytes.NewReader(frame))
	var client bytes.Buffer
	var upstream bytes.Buffer
	target, _ := url.Parse("https://example.com/socket")

	blocked, err := srv.forwardWebSocketClientFrames(reader, &client, &upstream, target, "unknown", true)
	if blocked {
		t.Fatalf("expected blocked=false")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	if !bytes.Equal(upstream.Bytes(), frame) {
		t.Fatalf("expected forwarded frame bytes to match original frame")
	}
	if client.Len() != 0 {
		t.Fatalf("expected no close frame written to client on skip")
	}

	events, err := store.ReadAll(util.EventsPath(tmp))
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].Action != model.ActionSkip {
		t.Fatalf("expected action skip, got %q", events[0].Action)
	}
}

func TestForwardWebSocketClientFramesBlocksOversizedFrameAndLogsEvent(t *testing.T) {
	tmp := t.TempDir()
	if _, err := SetupCA(tmp, "agentproxy test ca", false); err != nil {
		t.Fatalf("setup ca: %v", err)
	}
	rules := config.DefaultRules()
	rules.MaxRequestBytes = 32
	rules.MaxBodyBytes = 32
	srv, err := NewServer(Options{
		Listen:  "127.0.0.1:8787",
		DataDir: tmp,
		Rules:   rules,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	payload := bytes.Repeat([]byte("A"), 64)
	frame := buildMaskedClientTextFrame(payload)
	reader := bufio.NewReader(bytes.NewReader(frame))
	var client bytes.Buffer
	var upstream bytes.Buffer
	target, _ := url.Parse("https://api.openai.com/v1/realtime")

	blocked, err := srv.forwardWebSocketClientFrames(reader, &client, &upstream, target, "openai", true)
	if !blocked {
		t.Fatalf("expected blocked=true")
	}
	if err != nil {
		t.Fatalf("expected nil error when blocked, got %v", err)
	}
	if client.Len() == 0 {
		t.Fatalf("expected close frame to client")
	}
	if _, ok := parseCloseFrameCode(client.Bytes(), false); !ok {
		t.Fatalf("expected unmasked client close frame")
	}
	if upstream.Len() == 0 {
		t.Fatalf("expected close frame to upstream")
	}
	if _, ok := parseCloseFrameCode(upstream.Bytes(), true); !ok {
		t.Fatalf("expected masked upstream close frame")
	}

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
		t.Fatalf("expected oversized frame error in event")
	}
}

func TestStreamWebSocketReturnsWhenUpstreamClosesFirst(t *testing.T) {
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

	clientProxyConn, _ := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	defer clientProxyConn.Close()
	defer upstreamPeer.Close()

	target, _ := url.Parse("https://api.openai.com/v1/realtime")
	done := make(chan error, 1)
	go func() {
		done <- srv.streamWebSocket(clientProxyConn, bufio.NewReader(clientProxyConn), upstreamConn, target, "openai", true)
	}()

	_ = upstreamPeer.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("streamWebSocket returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("streamWebSocket did not return after upstream close")
	}
}

func buildMaskedClientTextFrame(payload []byte) []byte {
	const opcodeText = 0x1
	first := byte(0x80 | opcodeText) // FIN + text
	maskKey := []byte{0x11, 0x22, 0x33, 0x44}

	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ maskKey[i%4]
	}

	frame := []byte{first}
	payloadLen := len(payload)
	switch {
	case payloadLen < 126:
		frame = append(frame, byte(0x80|payloadLen))
	case payloadLen <= 0xFFFF:
		frame = append(frame, 0x80|126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(payloadLen))
		frame = append(frame, ext...)
	default:
		panic("test helper only supports payloads <= 65535 bytes")
	}
	frame = append(frame, maskKey...)
	frame = append(frame, masked...)
	return frame
}

func parseCloseFrameCode(frame []byte, expectMasked bool) (uint16, bool) {
	if len(frame) < 2 {
		return 0, false
	}
	if frame[0] != 0x88 {
		return 0, false
	}
	masked := (frame[1] & 0x80) != 0
	if masked != expectMasked {
		return 0, false
	}
	payloadLen := int(frame[1] & 0x7F)
	offset := 2
	var maskKey []byte
	if masked {
		if len(frame) < offset+4 {
			return 0, false
		}
		maskKey = frame[offset : offset+4]
		offset += 4
	}
	if payloadLen < 2 || len(frame) < offset+payloadLen {
		return 0, false
	}
	payload := append([]byte(nil), frame[offset:offset+payloadLen]...)
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	if len(payload) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(payload[:2]), true
}
