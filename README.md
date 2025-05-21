# Deepsleuth — read the fine print

<p>
  <img src="https://raw.githubusercontent.com/DeepSleuth/deepsleuth/main/docs/deepsleuth-logo.svg" width="420" alt="Deepsleuth logo" title="Deepsleuth — read the fine print">
</p>

[![CI](https://github.com/DeepSleuth/deepsleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/DeepSleuth/deepsleuth/actions/workflows/ci.yml)

**Deepsleuth** is a deterministic, no-LLM security scanner for MCP servers.
It audits what a server *says* — and, more importantly, what it *does*.

Most MCP scanners read only the *declared manifest* (`tools/list` names,
descriptions, schemas). They never launch the server, never call a tool, never
read a response, never read the implementation source, and never reason across
calls — so whole classes of attack are structurally invisible to them.

**Deepsleuth sees those.** It is a single frontend-agnostic detection **core**
with two frontends:

- **Frontend A — inline MCP gateway / proxy (the headline artifact).** A
  transparent proxy that is an MCP *server* to the agent and an MCP *client* to one
  downstream server. It audits tool descriptions at startup, enforces a **gate**
  before every `tools/call`, and scans every response before returning it. Includes
  a headless `proxy-eval` mode for offline scoring.
- **Frontend B — batch / sandbox scanner.** A pre-flight auditor that launches a
  server in a Docker sandbox, actively elicits behavior with synthesized calls +
  planted canaries, and produces findings. Also the offline scoring harness.

Both frontends run the **same** detectors over the same `Context` — a detector is
written once and works in both.

### No LLM. Ever.
Fully deterministic: parsing, static AST + taint/dataflow, normalized regex/token
heuristics, unicode/encoding/entropy analysis, structural diffing, and sandboxed
dynamic execution with instrumentation. **Same input → byte-identical findings.**
Offline (no network egress except to the Docker daemon). No threat feeds.

---

## Install

Python 3.11+. No required third-party packages — the scanner speaks MCP over stdio
itself, so it installs in externally-managed (PEP 668) environments.

```bash
pip install git+https://github.com/DeepSleuth/deepsleuth.git   # zero required dependencies
deepsleuth --help
# or straight from the source tree:
python -m deepsleuth --help
```

Deepsleuth is itself an MCP server, so agents can scan with it directly:

```json
{"mcpServers": {"deepsleuth": {"command": "python", "args": ["-m", "deepsleuth.mcp_server"]}}}
```

Tools: `list_detectors`, `check_listing`, `scan_target`.

For the dynamic layer (Frontend B and `proxy-eval`) you need the **Docker CLI +
daemon**. Without Docker the scanner **degrades gracefully**: static/manifest
detectors still run and the skipped dynamic coverage is reported (never a crash).

