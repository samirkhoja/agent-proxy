package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadBodyLimitedWithinLimit(t *testing.T) {
	got, tooLarge, err := readBodyLimited(io.NopCloser(bytes.NewReader([]byte("hello"))), 10)
	if err != nil {
		t.Fatalf("readBodyLimited error: %v", err)
	}
	if tooLarge {
		t.Fatalf("expected tooLarge=false")
	}
	if string(got) != "hello" {
		t.Fatalf("unexpected body: %q", string(got))
	}
}

func TestReadBodyLimitedOverflow(t *testing.T) {
	got, tooLarge, err := readBodyLimited(io.NopCloser(bytes.NewReader([]byte("hello world"))), 5)
	if err != nil {
		t.Fatalf("readBodyLimited error: %v", err)
	}
	if !tooLarge {
		t.Fatalf("expected tooLarge=true")
	}
	if string(got) != "hello" {
		t.Fatalf("unexpected truncated body: %q", string(got))
	}
}

func TestWriteHTTP11ResponseNormalizesProto(t *testing.T) {
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(`{"ok":true}`)),
		ContentLength: int64(len(`{"ok":true}`)),
	}

	var out bytes.Buffer
	closeAfter, err := writeHTTP11Response(&out, resp)
	if err != nil {
		t.Fatalf("writeHTTP11Response error: %v", err)
	}
	if closeAfter {
		t.Fatalf("expected closeAfter=false for known-length response")
	}
	firstLine := strings.SplitN(out.String(), "\r\n", 2)[0]
	if firstLine != "HTTP/1.1 200 OK" {
		t.Fatalf("unexpected status line: %q", firstLine)
	}
}

func TestWriteHTTP11ResponseUnknownLengthForcesClose(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("hello")),
		// Simulate a response with unknown length and no chunked framing.
		ContentLength: -1,
	}

	var out bytes.Buffer
	closeAfter, err := writeHTTP11Response(&out, resp)
	if err != nil {
		t.Fatalf("writeHTTP11Response error: %v", err)
	}
	if !closeAfter {
		t.Fatalf("expected closeAfter=true for unknown-length response")
	}
	wire := out.String()
	if !strings.Contains(wire, "\r\nConnection: close\r\n") {
		t.Fatalf("expected Connection: close header, got %q", wire)
	}
}

func TestShouldSend100Continue(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Expect", "100-continue")
	if !shouldSend100Continue(req) {
		t.Fatalf("expected shouldSend100Continue=true")
	}
}
