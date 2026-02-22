package proxy

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/detect"
	"github.com/samirkhoja/agent-proxy/internal/model"
)

const (
	websocketOpcodeContinuation = 0x0
	websocketOpcodeText         = 0x1
	websocketOpcodeBinary       = 0x2
	websocketOpcodeClose        = 0x8
	websocketOpcodePing         = 0x9
	websocketOpcodePong         = 0xA

	websocketClosePolicyViolation = 1008
)

var errWebSocketMessageTooLarge = errors.New("websocket message too large")

type websocketFrame struct {
	fin     bool
	opcode  byte
	payload []byte
	raw     []byte
}

type bufferedTextMessage struct {
	active      bool
	raw         bytes.Buffer
	payload     bytes.Buffer
	payloadSize int
	truncated   bool
}

func (m *bufferedTextMessage) reset() {
	m.active = false
	m.raw.Reset()
	m.payload.Reset()
	m.payloadSize = 0
	m.truncated = false
}

func (m *bufferedTextMessage) append(frame websocketFrame, maxRawBytes, maxScanBytes int64) error {
	nextRaw := int64(m.raw.Len() + len(frame.raw))
	if nextRaw > maxRawBytes {
		return errWebSocketMessageTooLarge
	}
	if _, err := m.raw.Write(frame.raw); err != nil {
		return err
	}

	m.payloadSize += len(frame.payload)
	if int64(m.payload.Len()) < maxScanBytes {
		remaining := int(maxScanBytes - int64(m.payload.Len()))
		chunk := frame.payload
		if len(chunk) > remaining {
			chunk = chunk[:remaining]
			m.truncated = true
		}
		if _, err := m.payload.Write(chunk); err != nil {
			return err
		}
	}
	if int64(m.payloadSize) > maxScanBytes {
		m.truncated = true
	}
	return nil
}

func (s *Server) handleWebSocketForwardHTTP(w http.ResponseWriter, req *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if rw == nil || rw.Reader == nil {
		return
	}

	if _, err := s.handleWebSocketUpgrade(req, conn, rw.Reader, false); err != nil {
		s.logger.Printf("websocket upgrade failed host=%s err=%v", req.Host, err)
	}
}

func (s *Server) handleWebSocketUpgrade(req *http.Request, clientConn net.Conn, clientReader *bufio.Reader, isTLS bool) (bool, error) {
	target := deriveTargetURL(req, isTLS)
	host := target.Hostname()
	provider := providerForHost(host)

	resp, upstream, err := s.forwardWebSocketHandshake(req, target)
	if err != nil {
		synth := s.syntheticResponse(http.StatusBadGateway, "websocket upstream handshake failed")
		closeAfter, writeErr := writeHTTP11Response(clientConn, synth)
		_ = synth.Body.Close()
		if writeErr != nil {
			return true, writeErr
		}
		_ = closeAfter
		return true, nil
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		closeAfter, err := writeHTTP11Response(clientConn, resp)
		_ = resp.Body.Close()
		if err != nil {
			return true, err
		}
		return closeAfter, nil
	}

	if err := writeSwitchingProtocolsResponse(clientConn, resp); err != nil {
		_ = upstream.Close()
		return true, err
	}

	streamErr := s.streamWebSocket(clientConn, clientReader, upstream, target, provider, isTLS)
	if streamErr != nil && !isExpectedStreamEndErr(streamErr) {
		return true, streamErr
	}
	return true, nil
}

func (s *Server) forwardWebSocketHandshake(in *http.Request, target *url.URL) (*http.Response, io.ReadWriteCloser, error) {
	outReq, err := buildWebSocketOutboundRequest(in, target)
	if err != nil {
		return nil, nil, err
	}
	transport := s.wsTransport
	if transport == nil {
		transport = s.transport
	}
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		return nil, nil, err
	}
	resp.Header.Set("X-Agentproxy", "1")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return resp, nil, nil
	}
	upstream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		_ = resp.Body.Close()
		return nil, nil, errors.New("websocket upgrade response body is not read-write")
	}
	return resp, upstream, nil
}

func buildWebSocketOutboundRequest(in *http.Request, target *url.URL) (*http.Request, error) {
	outReq, err := http.NewRequestWithContext(in.Context(), in.Method, target.String(), nil)
	if err != nil {
		return nil, err
	}
	outReq.Header = cloneHeader(in.Header)
	removeWebSocketProxyHeaders(outReq.Header)
	// Disable negotiated websocket compression in v1 so text frame inspection stays transparent.
	outReq.Header.Del("Sec-WebSocket-Extensions")
	outReq.Host = target.Host
	if in.Host != "" {
		outReq.Host = in.Host
	}
	outReq.ContentLength = 0
	return outReq, nil
}

func removeWebSocketProxyHeaders(h http.Header) {
	for _, k := range []string{
		"Proxy-Connection",
		"Proxy-Authenticate",
		"Proxy-Authorization",
	} {
		h.Del(k)
	}
}

func writeSwitchingProtocolsResponse(w io.Writer, resp *http.Response) error {
	if resp == nil {
		return errors.New("nil response")
	}
	statusText := http.StatusText(resp.StatusCode)
	if statusText == "" {
		statusText = "Switching Protocols"
	}
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %03d %s\r\n", resp.StatusCode, statusText); err != nil {
		return err
	}
	headers := cloneHeader(resp.Header)
	headers.Del("Content-Length")
	headers.Del("Transfer-Encoding")
	headers.Del("Trailer")
	if err := headers.Write(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func (s *Server) streamWebSocket(clientConn net.Conn, clientReader *bufio.Reader, upstream io.ReadWriteCloser, target *url.URL, provider string, isTLS bool) error {
	defer upstream.Close()

	type clientResult struct {
		blocked bool
		err     error
	}
	clientDone := make(chan clientResult, 1)
	upstreamCopyDone := make(chan error, 1)
	go func() {
		blocked, err := s.forwardWebSocketClientFrames(clientReader, clientConn, upstream, target, provider, isTLS)
		clientDone <- clientResult{blocked: blocked, err: err}
	}()
	go func() {
		_, err := io.Copy(clientConn, upstream)
		upstreamCopyDone <- err
	}()

	var blocked bool
	var forwardErr error
	var upstreamErr error
	select {
	case result := <-clientDone:
		blocked = result.blocked
		forwardErr = result.err
		_ = upstream.Close()
		select {
		case upstreamErr = <-upstreamCopyDone:
		case <-time.After(500 * time.Millisecond):
		}
	case upstreamErr = <-upstreamCopyDone:
		// Upstream ended first. Close client conn to unblock websocket frame reads.
		_ = clientConn.Close()
		select {
		case result := <-clientDone:
			blocked = result.blocked
			forwardErr = result.err
		case <-time.After(500 * time.Millisecond):
		}
	}

	if blocked {
		return nil
	}
	if isExpectedStreamEndErr(forwardErr) {
		forwardErr = nil
	}
	if !isExpectedStreamEndErr(upstreamErr) && forwardErr == nil {
		forwardErr = upstreamErr
	}
	return forwardErr
}

func (s *Server) forwardWebSocketClientFrames(clientReader *bufio.Reader, clientWriter io.Writer, upstream io.Writer, target *url.URL, provider string, isTLS bool) (bool, error) {
	inspectable := s.hostSet.allowHost(target.Hostname())
	maxRawBytes := s.opts.Rules.MaxRequestBytes
	maxScanBytes := s.opts.Rules.MaxBodyBytes

	msg := bufferedTextMessage{}
	for {
		frame, err := readWebSocketFrame(clientReader, maxRawBytes)
		if err != nil {
			if errors.Is(err, errWebSocketMessageTooLarge) {
				s.recordWebSocketTooLargeEvent(provider, target, isTLS, int(maxRawBytes), err)
				writePolicyViolationCloseFrames(clientWriter, upstream)
				return true, nil
			}
			return false, err
		}

		switch frame.opcode {
		case websocketOpcodeText:
			// Text messages are buffered until FIN so policy can block before bytes are forwarded upstream.
			if msg.active {
				if err := writeAll(upstream, msg.raw.Bytes()); err != nil {
					return false, err
				}
				msg.reset()
			}
			msg.active = true
			if err := msg.append(frame, maxRawBytes, maxScanBytes); err != nil {
				s.recordWebSocketTooLargeEvent(provider, target, isTLS, msg.payloadSize+len(frame.payload), err)
				writePolicyViolationCloseFrames(clientWriter, upstream)
				return true, nil
			}
			if frame.fin {
				blocked, err := s.inspectAndForwardWebSocketMessage(upstream, provider, target, isTLS, inspectable, &msg)
				msg.reset()
				if err != nil {
					return false, err
				}
				if blocked {
					writePolicyViolationCloseFrames(clientWriter, upstream)
					return true, nil
				}
			}
		case websocketOpcodeContinuation:
			if msg.active {
				if err := msg.append(frame, maxRawBytes, maxScanBytes); err != nil {
					s.recordWebSocketTooLargeEvent(provider, target, isTLS, msg.payloadSize+len(frame.payload), err)
					writePolicyViolationCloseFrames(clientWriter, upstream)
					return true, nil
				}
				if frame.fin {
					blocked, err := s.inspectAndForwardWebSocketMessage(upstream, provider, target, isTLS, inspectable, &msg)
					msg.reset()
					if err != nil {
						return false, err
					}
					if blocked {
						writePolicyViolationCloseFrames(clientWriter, upstream)
						return true, nil
					}
				}
				continue
			}
			if err := writeAll(upstream, frame.raw); err != nil {
				return false, err
			}
		default:
			if msg.active && !isWebSocketControlOpcode(frame.opcode) {
				// If frame sequencing is unexpected, flush buffered bytes so stream continuity is preserved.
				if err := writeAll(upstream, msg.raw.Bytes()); err != nil {
					return false, err
				}
				msg.reset()
			}
			if err := writeAll(upstream, frame.raw); err != nil {
				return false, err
			}
		}
	}
}

func (s *Server) inspectAndForwardWebSocketMessage(upstream io.Writer, provider string, target *url.URL, isTLS, inspectable bool, msg *bufferedTextMessage) (bool, error) {
	findings := []model.Finding{}
	sensitive := false
	if inspectable {
		findings, sensitive = s.detector.Scan(msg.payload.Bytes())
	}

	blocked := false
	if sensitive {
		blocked = s.opts.BlockOnSensitive || hasRuleBlocked(findings) || (s.opts.AutoBlockHighRisk && hasHighRiskFindings(findings))
	}

	action := model.ActionAllow
	if !inspectable {
		action = model.ActionSkip
	}
	if sensitive && !blocked {
		action = model.ActionAlert
	}
	if blocked {
		action = model.ActionBlock
	}

	preview := ""
	if sensitive && s.opts.Rules.PreviewChars > 0 {
		preview = clipRunes(msg.payload.String(), s.opts.Rules.PreviewChars)
		if s.opts.Rules.RedactPreview {
			preview = detect.RedactPreview(preview, findings)
		}
	}

	event := model.Event{
		Timestamp:   time.Now().UTC(),
		Provider:    provider,
		Host:        target.Hostname(),
		Method:      "WS",
		URL:         sanitizeURLForEvent(target),
		Sensitive:   sensitive,
		Action:      action,
		Findings:    findingsForEvent(findings),
		BodyPreview: preview,
		BodyBytes:   msg.payloadSize,
		Truncated:   msg.truncated,
		TLS:         isTLS,
	}
	if blocked {
		event.Error = "websocket message blocked by agentproxy policy"
	}
	s.recordEvent(event)

	if blocked {
		return true, nil
	}
	if err := writeAll(upstream, msg.raw.Bytes()); err != nil {
		return false, err
	}
	return false, nil
}

func (s *Server) recordWebSocketTooLargeEvent(provider string, target *url.URL, isTLS bool, bodyBytes int, cause error) {
	event := model.Event{
		Timestamp: time.Now().UTC(),
		Provider:  provider,
		Host:      target.Hostname(),
		Method:    "WS",
		URL:       sanitizeURLForEvent(target),
		Action:    model.ActionBlock,
		BodyBytes: bodyBytes,
		Truncated: true,
		TLS:       isTLS,
		Error:     fmt.Sprintf("websocket message exceeded max_request_bytes (%d): %v", s.opts.Rules.MaxRequestBytes, cause),
	}
	s.recordEvent(event)
}

func isWebSocketUpgrade(req *http.Request) bool {
	if req == nil || !strings.EqualFold(req.Method, http.MethodGet) {
		return false
	}
	if !headerContainsToken(req.Header, "Connection", "upgrade") {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket") {
		return false
	}
	return req.Header.Get("Sec-WebSocket-Key") != ""
}

func headerContainsToken(h http.Header, key, token string) bool {
	values := h.Values(key)
	needle := strings.ToLower(strings.TrimSpace(token))
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if strings.ToLower(strings.TrimSpace(part)) == needle {
				return true
			}
		}
	}
	return false
}

func readWebSocketFrame(r *bufio.Reader, maxPayloadBytes int64) (websocketFrame, error) {
	var frame websocketFrame

	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return frame, err
	}

	frame.fin = (header[0] & 0x80) != 0
	frame.opcode = header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	payloadLen := int64(header[1] & 0x7F)

	raw := make([]byte, 0, 2+8+4)
	raw = append(raw, header...)

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return frame, err
		}
		raw = append(raw, ext...)
		payloadLen = int64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return frame, err
		}
		raw = append(raw, ext...)
		u := binary.BigEndian.Uint64(ext)
		if u > uint64(maxPayloadBytes) {
			return frame, errWebSocketMessageTooLarge
		}
		if u > uint64(int(^uint(0)>>1)) {
			return frame, errWebSocketMessageTooLarge
		}
		payloadLen = int64(u)
	}
	if payloadLen > maxPayloadBytes {
		return frame, errWebSocketMessageTooLarge
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(r, maskKey); err != nil {
			return frame, err
		}
		raw = append(raw, maskKey...)
	}

	payload := make([]byte, int(payloadLen))
	if _, err := io.ReadFull(r, payload); err != nil {
		return frame, err
	}
	raw = append(raw, payload...)

	decoded := append([]byte(nil), payload...)
	if masked {
		for i := range decoded {
			decoded[i] ^= maskKey[i%4]
		}
	}

	frame.payload = decoded
	frame.raw = raw
	return frame, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func writePolicyViolationCloseFrames(clientWriter, upstreamWriter io.Writer) {
	_ = writeWebSocketCloseFrame(clientWriter, websocketClosePolicyViolation, "policy violation", false)
	// Proxy acts as websocket client on upstream leg, so close frame must be masked.
	_ = writeWebSocketCloseFrame(upstreamWriter, websocketClosePolicyViolation, "policy violation", true)
}

func writeWebSocketCloseFrame(w io.Writer, code uint16, reason string, masked bool) error {
	if w == nil {
		return nil
	}
	reasonBytes := []byte(reason)
	if len(reasonBytes) > 123 {
		reasonBytes = reasonBytes[:123]
	}
	payload := make([]byte, 2+len(reasonBytes))
	binary.BigEndian.PutUint16(payload[:2], code)
	copy(payload[2:], reasonBytes)

	frame := make([]byte, 0, 2+4+len(payload))
	frame = append(frame, 0x80|websocketOpcodeClose)
	if masked {
		frame = append(frame, 0x80|byte(len(payload)))
		maskKey := make([]byte, 4)
		if _, err := rand.Read(maskKey); err != nil {
			return err
		}
		frame = append(frame, maskKey...)
		maskedPayload := make([]byte, len(payload))
		for i := range payload {
			maskedPayload[i] = payload[i] ^ maskKey[i%4]
		}
		frame = append(frame, maskedPayload...)
	} else {
		frame = append(frame, byte(len(payload)))
		frame = append(frame, payload...)
	}
	return writeAll(w, frame)
}

func isWebSocketControlOpcode(opcode byte) bool {
	switch opcode {
	case websocketOpcodeClose, websocketOpcodePing, websocketOpcodePong:
		return true
	default:
		return false
	}
}

func isExpectedStreamEndErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	if isClosedConnErr(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "closed pipe") || strings.Contains(msg, "connection reset by peer")
}
