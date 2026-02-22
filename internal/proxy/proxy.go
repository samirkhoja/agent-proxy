package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/samirkhoja/agent-proxy/internal/config"
	"github.com/samirkhoja/agent-proxy/internal/detect"
	"github.com/samirkhoja/agent-proxy/internal/model"
	"github.com/samirkhoja/agent-proxy/internal/store"
	"github.com/samirkhoja/agent-proxy/internal/util"
)

type Options struct {
	Listen            string
	DataDir           string
	Rules             config.Rules
	BlockOnSensitive  bool
	AutoBlockHighRisk bool
	AsyncEventWrite   bool
	Logger            *log.Logger
	EventSink         func(model.Event)
}

type Server struct {
	opts        Options
	logger      *log.Logger
	detector    *detect.Detector
	store       *store.JSONLStore
	transport   *http.Transport
	wsTransport *http.Transport
	ca          *CertificateAuthority
	certCache   *CertCache
	hostSet     hostFilter
}

type hostFilter struct {
	include []string
	exclude []string
}

func NewServer(opts Options) (*Server, error) {
	logger := opts.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:8787"
	}
	if opts.DataDir == "" {
		opts.DataDir = util.DefaultDataDir()
	}
	if opts.Rules.MaxBodyBytes == 0 {
		opts.Rules = config.DefaultRules()
	}
	if opts.Rules.MaxRequestBytes <= 0 {
		opts.Rules.MaxRequestBytes = config.DefaultMaxRequestBytes
	}
	if err := util.EnsureDir(opts.DataDir); err != nil {
		return nil, fmt.Errorf("ensure data dir: %w", err)
	}

	ca, err := LoadCA(util.CACertPath(opts.DataDir), util.CAKeyPath(opts.DataDir))
	if err != nil {
		return nil, fmt.Errorf("load ca: %w", err)
	}
	detector, err := detect.New(opts.Rules)
	if err != nil {
		return nil, fmt.Errorf("build detector: %w", err)
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSHandshakeTimeout:   15 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	wsTransport := &http.Transport{
		Proxy:                 nil,
		TLSHandshakeTimeout:   15 * time.Second,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &Server{
		opts:        opts,
		logger:      logger,
		detector:    detector,
		store:       store.NewJSONLStore(util.EventsPath(opts.DataDir)),
		transport:   transport,
		wsTransport: wsTransport,
		ca:          ca,
		certCache:   NewCertCache(ca),
		hostSet: hostFilter{
			include: toLowerList(opts.Rules.IncludeHosts),
			exclude: toLowerList(opts.Rules.ExcludeHosts),
		},
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              s.opts.Listen,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	if isWebSocketUpgrade(r) {
		s.handleWebSocketForwardHTTP(w, r)
		return
	}
	s.handleForwardHTTP(w, r, false)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
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
	if rw != nil && rw.Reader.Buffered() > 0 {
		_, _ = io.CopyN(io.Discard, rw.Reader, int64(rw.Reader.Buffered()))
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	cert, err := s.certCache.CertForHost(r.Host)
	if err != nil {
		s.logger.Printf("generate cert host=%s err=%v", r.Host, err)
		return
	}

	tlsConn := tlsServer(conn, cert)
	if err := tlsConn.Handshake(); err != nil {
		s.logger.Printf("tls handshake failed host=%s err=%v", r.Host, err)
		return
	}
	defer tlsConn.Close()

	reader := bufio.NewReader(tlsConn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || isClosedConnErr(err) {
				return
			}
			s.logger.Printf("read mitm request failed host=%s err=%v", r.Host, err)
			return
		}

		req.URL.Scheme = "https"
		if req.URL.Host == "" {
			req.URL.Host = r.Host
		}
		if req.Host == "" {
			req.Host = req.URL.Host
		}
		if shouldSend100Continue(req) {
			if _, err := io.WriteString(tlsConn, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				return
			}
		}
		if isWebSocketUpgrade(req) {
			closeAfter, err := s.handleWebSocketUpgrade(req, tlsConn, reader, true)
			if err != nil {
				s.logger.Printf("websocket upgrade failed host=%s err=%v", r.Host, err)
				return
			}
			if closeAfter {
				return
			}
			continue
		}

		// Forward each decrypted request over a separate upstream TLS session.
		resp := s.forwardRequest(req, true)
		// Always write an HTTP/1.1 response on the client-side leg of CONNECT MITM.
		closeAfter, err := writeHTTP11Response(tlsConn, resp)
		if err != nil {
			_ = resp.Body.Close()
			return
		}
		_ = resp.Body.Close()
		if closeAfter {
			// Unknown-length HTTP/1.1 bodies are close-delimited; honor that framing.
			return
		}
	}
}

func (s *Server) handleForwardHTTP(w http.ResponseWriter, req *http.Request, isTLS bool) {
	resp := s.forwardRequest(req, isTLS)
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) forwardRequest(req *http.Request, isTLS bool) *http.Response {
	start := time.Now().UTC()
	target := deriveTargetURL(req, isTLS)
	host := target.Hostname()
	provider := providerForHost(host)

	body, tooLarge, err := readBodyLimited(req.Body, s.opts.Rules.MaxRequestBytes)
	if err != nil {
		return s.syntheticResponse(http.StatusBadRequest, "failed to read request body")
	}
	if tooLarge {
		event := model.Event{
			Timestamp: start,
			Provider:  provider,
			Host:      host,
			Method:    req.Method,
			URL:       sanitizeURLForEvent(target),
			Action:    model.ActionBlock,
			BodyBytes: len(body),
			Truncated: true,
			TLS:       isTLS,
			Error:     fmt.Sprintf("request body exceeded max_request_bytes (%d)", s.opts.Rules.MaxRequestBytes),
		}
		s.recordEvent(event)
		return s.syntheticResponse(http.StatusRequestEntityTooLarge, "request body too large")
	}

	scanBody := body
	truncated := false
	if int64(len(scanBody)) > s.opts.Rules.MaxBodyBytes {
		// Cap scan bytes to bound CPU/memory while preserving original outbound body.
		scanBody = scanBody[:s.opts.Rules.MaxBodyBytes]
		truncated = true
	}

	inspectable := s.hostSet.allowHost(host)
	findings := []model.Finding{}
	sensitive := false
	decodeErr := ""
	decoded := scanBody
	if inspectable {
		decoded, decodeErr = decodeForInspection(scanBody, req.Header.Get("Content-Encoding"))
		if decodeErr == "" {
			findings, sensitive = s.detector.Scan(decoded)
		}
	}

	decodeBlocked := inspectable && decodeErr != ""
	blocked := decodeBlocked
	if sensitive && !blocked {
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
		preview = clipRunes(string(decoded), s.opts.Rules.PreviewChars)
		if s.opts.Rules.RedactPreview {
			preview = detect.RedactPreview(preview, findings)
		}
	}
	if decodeErr != "" && preview == "" {
		preview = decodeErr
	}

	event := model.Event{
		Timestamp:   start,
		Provider:    provider,
		Host:        host,
		Method:      req.Method,
		URL:         sanitizeURLForEvent(target),
		Sensitive:   sensitive,
		Action:      action,
		Findings:    findingsForEvent(findings),
		BodyPreview: preview,
		BodyBytes:   len(body),
		Truncated:   truncated,
		TLS:         isTLS,
	}
	if decodeBlocked {
		event.Error = decodeErr
	}

	if blocked {
		s.recordEvent(event)
		if decodeBlocked {
			return s.syntheticResponse(http.StatusUnsupportedMediaType, "request blocked: body encoding cannot be inspected")
		}
		return s.syntheticResponse(http.StatusForbidden, "blocked by agentproxy policy")
	}

	// Outbound request forwards the original payload bytes unchanged.
	outReq, err := buildOutboundRequest(req, body, target)
	if err != nil {
		event.Error = err.Error()
		s.recordEvent(event)
		return s.syntheticResponse(http.StatusBadGateway, "failed to build outbound request")
	}

	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		event.Error = err.Error()
		s.recordEvent(event)
		return s.syntheticResponse(http.StatusBadGateway, "upstream request failed")
	}
	resp.Header.Set("X-Agentproxy", "1")
	s.recordEvent(event)
	return resp
}

func (s *Server) recordEvent(event model.Event) {
	write := func() {
		if err := s.store.Append(event); err != nil {
			s.logger.Printf("append event err=%v", err)
		}
		if s.opts.EventSink != nil {
			s.opts.EventSink(event)
		}
	}
	if s.opts.AsyncEventWrite {
		// In high-throughput runs, decouple event I/O from request latency.
		go write()
		return
	}
	write()
}

func (s *Server) syntheticResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(strings.NewReader(body + "\n")),
		ContentLength: int64(len(body) + 1),
		Header: http.Header{
			"Content-Type": []string{"text/plain; charset=utf-8"},
			"X-Agentproxy": []string{"1"},
		},
	}
}

func buildOutboundRequest(in *http.Request, body []byte, target *url.URL) (*http.Request, error) {
	outReq, err := http.NewRequestWithContext(in.Context(), in.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	outReq.Header = cloneHeader(in.Header)
	removeHopHeaders(outReq.Header)
	outReq.Host = target.Host
	if in.Host != "" {
		outReq.Host = in.Host
	}
	outReq.ContentLength = int64(len(body))
	return outReq, nil
}

func deriveTargetURL(req *http.Request, isTLS bool) *url.URL {
	if req.URL != nil && req.URL.IsAbs() {
		cloned := *req.URL
		return &cloned
	}
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	host := req.Host
	if req.URL != nil && req.URL.Host != "" {
		host = req.URL.Host
	}
	u := &url.URL{Scheme: scheme, Host: host}
	if req.URL != nil {
		u.Path = req.URL.Path
		u.RawPath = req.URL.RawPath
		u.RawQuery = req.URL.RawQuery
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u
}

func decodeForInspection(body []byte, encoding string) ([]byte, string) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	switch enc {
	case "", "identity":
		return body, ""
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, "gzip decode failed"
		}
		defer zr.Close()
		decoded, err := io.ReadAll(zr)
		if err != nil {
			return body, "gzip decode failed"
		}
		return decoded, ""
	case "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, "deflate decode failed"
		}
		defer zr.Close()
		decoded, err := io.ReadAll(zr)
		if err != nil {
			return body, "deflate decode failed"
		}
		return decoded, ""
	case "br":
		return body, "content-encoding br not decoded in zero-dependency build"
	default:
		return body, "unsupported content-encoding: " + enc
	}
}

func readBodyLimited(body io.ReadCloser, max int64) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	defer body.Close()
	limited := io.LimitReader(body, max+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return data[:max], true, nil
	}
	return data, false, nil
}

func hasRuleBlocked(findings []model.Finding) bool {
	for _, f := range findings {
		if f.Blocked {
			return true
		}
	}
	return false
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vv := range h {
		copied := make([]string, len(vv))
		copy(copied, vv)
		out[k] = copied
	}
	return out
}

func writeHTTP11Response(w io.Writer, resp *http.Response) (bool, error) {
	if resp == nil {
		return true, errors.New("nil response")
	}
	cloned := *resp
	cloned.Header = cloneHeader(resp.Header)
	// Normalize proto so downstream HTTP/1 clients can parse framing consistently.
	cloned.Proto = "HTTP/1.1"
	cloned.ProtoMajor = 1
	cloned.ProtoMinor = 1
	closeAfter := cloned.Close
	if cloned.ContentLength < 0 && !hasChunkedTransferEncoding(cloned.TransferEncoding) {
		// HTTP/1.1 without CL/TE is close-delimited, so we must close tunnel after write.
		cloned.Close = true
		closeAfter = true
	}
	removeHopHeaders(cloned.Header)
	if err := cloned.Write(w); err != nil {
		return true, err
	}
	return closeAfter, nil
}

func removeHopHeaders(h http.Header) {
	for _, k := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(k)
	}
}

func hasChunkedTransferEncoding(te []string) bool {
	return len(te) > 0 && strings.EqualFold(strings.TrimSpace(te[0]), "chunked")
}

func providerForHost(host string) string {
	h := strings.ToLower(host)
	switch {
	case strings.Contains(h, "openai.azure.com"):
		return "azure_openai"
	case strings.Contains(h, "openai.com"):
		return "openai"
	case strings.Contains(h, "anthropic.com"):
		return "anthropic"
	case strings.Contains(h, "generativelanguage.googleapis.com") || strings.Contains(h, "googleapis.com"):
		return "google"
	case strings.Contains(h, "bedrock") || strings.Contains(h, "amazonaws.com"):
		return "bedrock"
	case strings.Contains(h, "ollama") || strings.Contains(h, "localhost") || strings.Contains(h, "127.0.0.1"):
		return "local"
	default:
		return "unknown"
	}
}

func clipRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func toLowerList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if trimmed := strings.TrimSpace(strings.ToLower(s)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (h hostFilter) allowHost(host string) bool {
	lower := strings.ToLower(host)
	for _, denied := range h.exclude {
		if strings.Contains(lower, denied) {
			return false
		}
	}
	if len(h.include) == 0 {
		return true
	}
	for _, allow := range h.include {
		if strings.Contains(lower, allow) {
			return true
		}
	}
	return false
}

func tlsServer(conn net.Conn, cert *tls.Certificate) *tls.Conn {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	}
	return tls.Server(conn, cfg)
}

func isClosedConnErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") || strings.Contains(msg, "tls: bad record MAC")
}

func sanitizeURLForEvent(u *url.URL) string {
	if u == nil {
		return ""
	}
	cloned := *u
	cloned.RawQuery = ""
	cloned.Fragment = ""
	return cloned.String()
}

func findingsForEvent(in []model.Finding) []model.Finding {
	if len(in) == 0 {
		return nil
	}
	out := make([]model.Finding, len(in))
	for i, f := range in {
		// Persist names/counts only; samples are intentionally dropped from disk logs.
		out[i] = model.Finding{
			Name:    f.Name,
			Count:   f.Count,
			Blocked: f.Blocked,
			Risk:    f.Risk,
		}
	}
	return out
}

func hasHighRiskFindings(findings []model.Finding) bool {
	for _, f := range findings {
		if f.Risk == model.RiskHigh {
			return true
		}
	}
	return false
}

func shouldSend100Continue(req *http.Request) bool {
	if req == nil || req.Body == nil {
		return false
	}
	expect := strings.ToLower(strings.TrimSpace(req.Header.Get("Expect")))
	return expect == "100-continue"
}
