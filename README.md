# Agent Proxy

`agentproxy` is a zero-dependency Go CLI for monitoring outbound LLM API requests through a local proxy and flagging sensitive payload content.

## Overview

`agentproxy` provides:

- HTTPS request inspection via a local CA certificate.
- Payload scanning for sensitive patterns (built-in + custom regex + keywords).
- Rule management command for adding custom regex checks.
- Policy actions: alert, pattern-based block, and optional auto-block for high-risk findings.
- Local JSONL event logging with retention pruning.
- CA lifecycle commands (setup, rotate, revoke, status).
- WebSocket support (`ws://`, `wss://`) with client-to-upstream text message inspection.

## How interception works

`agentproxy` currently runs as an **explicit proxy**. Traffic is only monitored when client traffic is routed through it.

```bash
export HTTP_PROXY=http://127.0.0.1:8787
export HTTPS_PROXY=http://127.0.0.1:8787
```

Use the same proxy endpoint for HTTP(S), `ws://`, and `wss://`.

## Security defaults enforced

- Proxy bind is loopback-only (`127.0.0.1` / `localhost`).
- Strict upstream TLS verification (no insecure bypass mode).
- CA private key file mode is enforced to `0600`.
- Proxy run refuses root/elevated execution.
- Default inspection scope is LLM-provider hosts only.
- Request bodies are size-limited before buffering (`max_request_bytes`).
- Unsupported/undecodable request encodings are fail-closed (blocked + logged).
- Minimal logging by default (`preview_chars: 0`).
- Default short retention (`--retention 7d`).

## Build

```bash
go build ./cmd/agentproxy
```

## Global install

Using Go (recommended):

```bash
go install ./cmd/agentproxy
```

This installs `agentproxy` into your Go bin directory (typically `$HOME/go/bin`).

Install directly from GitHub:

```bash
go install github.com/samirkhoja/agent-proxy/cmd/agentproxy@latest
```

## Quick start

1. Create/load local CA:

```bash
./agentproxy setup-ca
```

2. Trust the CA in your OS/app trust store (see platform instructions below).

3. Start proxy:

```bash
./agentproxy run --listen 127.0.0.1:8787 --retention 7d --autoblock-high-risk --tail
```

4. Route app traffic via proxy (`HTTP_PROXY` / `HTTPS_PROXY`).

5. Inspect events:

```bash
./agentproxy events tail --follow
```

6. Add a custom regex check:

```bash
./agentproxy rules add-regex --name customer_id --regex "CUST-[0-9]{6}" --block
```

## Trusting the CA (macOS, Windows, Linux)

`agentproxy` creates a local CA at `~/.agentproxy/ca_cert.pem`. Your client/app must trust this certificate to avoid TLS errors when proxying HTTPS traffic.

macOS (System keychain, requires admin):

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$HOME/.agentproxy/ca_cert.pem"
```

Remove later:

```bash
sudo security delete-certificate -c "agentproxy Local CA" /Library/Keychains/System.keychain
```

Windows (Administrator PowerShell):

```powershell
certutil -addstore -f Root "$env:USERPROFILE\.agentproxy\ca_cert.pem"
```

Remove later:

```powershell
certutil -delstore Root "agentproxy Local CA"
```

Linux (system trust store):

Debian/Ubuntu:

```bash
sudo cp "$HOME/.agentproxy/ca_cert.pem" /usr/local/share/ca-certificates/agentproxy-ca.crt
sudo update-ca-certificates
```

RHEL/CentOS/Fedora:

```bash
sudo cp "$HOME/.agentproxy/ca_cert.pem" /etc/pki/ca-trust/source/anchors/agentproxy-ca.crt
sudo update-ca-trust extract
```

Remove later (both families):

```bash
sudo rm -f /usr/local/share/ca-certificates/agentproxy-ca.crt /etc/pki/ca-trust/source/anchors/agentproxy-ca.crt
sudo update-ca-certificates 2>/dev/null || true
sudo update-ca-trust extract 2>/dev/null || true
```

If your app uses its own certificate bundle (instead of OS trust), you must add `~/.agentproxy/ca_cert.pem` to that bundle too.

## Commands

```text
agentproxy setup-ca [--dir DIR] [--name NAME] [--overwrite]
agentproxy ca rotate [--dir DIR] [--name NAME]
agentproxy ca revoke [--dir DIR]
agentproxy ca status [--dir DIR]
agentproxy run [--listen ADDR] [--dir DIR] [--rules FILE] [--block] [--autoblock-high-risk] [--tail] [--retention 7d]
agentproxy events tail [--dir DIR] [--limit N] [--follow]
agentproxy events prune [--dir DIR] [--older-than 7d]
agentproxy rules add-regex [--dir DIR|--file FILE] --name NAME --regex REGEX [--risk low|medium|high] [--block] [--replace]
agentproxy rules list [--dir DIR|--file FILE]
agentproxy report [--dir DIR] [--since 24h]
agentproxy version
```

Build-time version example:

```bash
go build -ldflags "-X agentproxy/internal/app.Version=v0.1.0" ./cmd/agentproxy
```

## Console highlighting

`agentproxy events tail` now color-codes risk output when writing to an interactive terminal:

- `block` / `HIGH` risk: red
- `alert` / `MEDIUM` risk: yellow
- `allow` / `LOW` risk: green
- `skip`: cyan

Set `NO_COLOR=1` to disable colors.

## WebSocket behavior

- Upgrade/tunnel support is enabled for `ws://` and `wss://` through the same proxy endpoint.
- Client-to-upstream text messages are inspected with the same detector and risk policy as HTTP request bodies.
- On block, the current websocket connection is terminated and a `WS` block event is logged.
- Server-to-client websocket messages are pass-through.

## Rules file

Pass a JSON file via `--rules`. If `--rules` is omitted and `~/.agentproxy/rules.json` exists, `agentproxy run` uses it automatically.

You can also manage custom regex rules from CLI:

```bash
./agentproxy rules add-regex --name customer_id --regex "CUST-[0-9]{6}" --risk high --block
./agentproxy rules list
```

Risk levels are configured with `risk_levels` in rules JSON and can be set per custom regex with `--risk`. Valid values are `low`, `medium`, and `high`.

Example:

```json
{
  "keywords": ["confidential", "project-aurora"],
  "custom_patterns": [
    {"name": "employee_id", "regex": "EMP[0-9]{6}"}
  ],
  "block_patterns": ["ssn", "credit_card", "openai_key"],
  "risk_levels": {
    "openai_key": "high",
    "employee_id": "medium"
  },
  "max_body_bytes": 1048576,
  "max_request_bytes": 8388608,
  "preview_chars": 0,
  "redact_preview": true,
  "entropy_enabled": true,
  "entropy_min_len": 24,
  "entropy_min_score": 3.8,
  "include_hosts": [
    "openai.com",
    "openai.azure.com",
    "anthropic.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "bedrock",
    "cohere.ai"
  ],
  "exclude_hosts": ["localhost"]
}
```

## Data storage

Events are appended to:

- `~/.agentproxy/events.jsonl`

Each event stores metadata and findings (query string removed from URL). Keep retention short and prune regularly.
