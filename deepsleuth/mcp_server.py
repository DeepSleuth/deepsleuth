"""deepsleuth AS a standalone MCP server (the scanner *is* an MCP).

Run:
    python3 -m deepsleuth.mcp_server

Wire it into an MCP client / agent config like any other MCP server:

    { "mcpServers": {
        "deepsleuth": {
            "command": "python",
            "args": ["-m", "deepsleuth.mcp_server"],
            "cwd": "/path/to/mcp-scanner"
        } } }

Tools exposed (the scanner's own capabilities, callable by an agent):

  * list_detectors()            -- the full detector registry.
  * check_listing(tools_json)  -- analyze a SUPPLIED tool listing (a JSON
                                   array of {name, description, inputSchema},
                                   or an object with a "tools" key) with the
                                   listing-phase detectors, without launching
                                   anything. Paste another server's
                                   tools/list output here to screen it for
                                   poisoned descriptions/schemas.
  * scan_target(target, dynamic, timeout)
                                -- full scan of a target (server dir, mcp.json,
                                   or launch command). Static layers by
                                   default; dynamic=True additionally launches
                                   the target inside the Docker sandbox
                                   (never unsandboxed -- untrusted targets are
                                   always sandboxed).

Same detection core, same deterministic findings, no LLM. This module only
adds the MCP stdio server loop; it does not modify any other scanner code.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from .context import ScanContext, contract_from_listing
from .models import Finding, Target
from .mcpclient import read_message, write_message
from .runner import registry_summary, run_phase
from .scanner import scan
from .target_loader import load_targets

SERVER_INFO = {"name": "deepsleuth", "version": "1.0.4"}

TOOLS = [
    {
        "name": "list_detectors",
        "description": "List every detector in the deepsleuth registry: "
                       "id, category, evidence location, phase, and required "
                       "capability layers.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "check_listing",
        "description": "Analyze a supplied MCP tool listing with the "
                       "listing-phase detectors (description/schema poisoning, "
                       "shadowing, obfuscation, ...) WITHOUT launching the "
                       "server. Pass another server's tools/list output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tools_json": {
                    "type": "string",
                    "description": "A JSON array of tool entries "
                                   "({name, description, inputSchema}), or an "
                                   "object with a 'tools' key."},
                "server_name": {
                    "type": "string",
                    "description": "Label for the supplied listing "
                                   "(default: 'supplied-listing')."},
            },
            "required": ["tools_json"],
        },
    },
    {
        "name": "scan_target",
        "description": "Scan an MCP server target with the full detection "
                       "core: source analysis, package manifests, and "
                       "(optionally, dynamic=True) live execution inside the "
                       "Docker sandbox. Returns the findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Server directory, mcp.json path, or raw "
                                   "stdio launch command."},
                "dynamic": {
                    "type": "boolean",
                    "description": "Also run the dynamic layer (Docker "
                                   "sandbox required; the target always runs "
                                   "sandboxed). Default: false."},
                "timeout": {"type": "integer",
                            "description": "Per-call timeout seconds "
                                           "(default 30)."},
            },
            "required": ["target"],
        },
    },
]


# ---------------------------------------------------------------------------
# tool implementations (pure functions; the same core the CLI uses)

def _fmt_findings(findings: List[Finding],
                   skipped: Optional[List[str]] = None) -> str:
    if not findings:
        lines = ["no findings (clean)"]
    else:
        actionable = [f for f in findings
                       if f.severity in ("medium", "high", "critical")
                       and f.confidence in ("medium", "high")]
        lines = [f"findings: {len(findings)} total, "
                 f"{len(actionable)} actionable "
                 f"(severity>=medium AND confidence>=medium)"]
        for f in findings:
            lines.append(
                f"- {f.category}/{f.evidence_location} "
                f"{f.severity}-{f.confidence} "
                f"target={f.server_name or f.target_id} tool={f.tool_name!r}: "
                f"{f.rationale}")
    if skipped:
        lines.append("")
        lines.append("coverage notes:")
        for s in skipped:
            lines.append(f"- {s}")
    return "\n".join(lines)


def _tool_list_detectors() -> str:
    rows = registry_summary()
    lines = [f"{len(rows)} detectors registered:"]
    for r in rows:
        lines.append(f"- {r['id']} [{r['category']}/{r['evidence_location']}] "
                     f"phase={r['phase']} requires={r['requires'] or '-'}")
    return "\n".join(lines)


def _tool_check_listing(tools_json: str,
                        server_name: str = "supplied-listing") -> str:
    try:
        data = json.loads(tools_json)
    except json.JSONDecodeError as exc:
        return f"error: tools_json is not valid JSON: {exc}"
    if isinstance(data, dict) and isinstance(data.get("tools"), list):
        data = data["tools"]
    if not isinstance(data, list):
        return ("error: expected a JSON array of tool entries (or an object "
                "with a 'tools' key)")
    ctx = ScanContext(target=Target(target_id=f"listing:{server_name}",
                                    server_name=server_name))
    ctx.tools = [contract_from_listing(t, "tool") for t in data
                 if isinstance(t, dict)]
    ctx.layers = {"manifest"}
    if not ctx.tools:
        return "error: no tool entries found in the supplied listing"
    findings = run_phase(ctx, "listing")
    header = (f"analyzed {len(ctx.tools)} tool(s) from the supplied listing "
              f"(static manifest analysis only -- no source, no execution):")
    return header + "\n" + _fmt_findings(findings)


def _tool_scan_target(target: str, dynamic: bool = False,
                      timeout: int = 30) -> str:
    targets = load_targets(target)
    if not targets:
        return f"error: no target could be loaded from {target!r}"
    findings, ctxs = scan(targets, do_dynamic=bool(dynamic), timeout=timeout)
    skipped: List[str] = []
    for c in ctxs:
        skipped.extend(c.skipped)
    header = (f"scanned {len(targets)} target(s): "
              f"{', '.join(t.target_id for t in targets)}")
    return header + "\n" + _fmt_findings(findings, skipped)


HANDLERS = {
    "list_detectors": _tool_list_detectors,
    "check_listing": _tool_check_listing,
    "scan_target": _tool_scan_target,
}


# ---------------------------------------------------------------------------
# the MCP stdio server loop

def _reply(rid: Any, result: Dict[str, Any]) -> None:
    write_message(sys.stdout.buffer, {"jsonrpc": "2.0", "id": rid,
                                      "result": result})


def _reply_error(rid: Any, code: int, message: str) -> None:
    write_message(sys.stdout.buffer, {"jsonrpc": "2.0", "id": rid,
                                      "error": {"code": code,
                                                "message": message}})


def serve() -> int:
    for raw in iter(sys.stdin.buffer.readline, b""):
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            continue
        method, rid = msg.get("method"), msg.get("id")
        if method == "initialize":
            _reply(rid, {"protocolVersion": "2024-11-05",
                         "capabilities": {"tools": {}},
                         "serverInfo": SERVER_INFO})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _reply(rid, {"tools": TOOLS})
        elif method in ("resources/list", "prompts/list"):
            key = "resources" if "resources" in method else "prompts"
            _reply(rid, {key: []})
        elif method == "tools/call":
            params = msg.get("params") or {}
            name, args = params.get("name"), params.get("arguments") or {}
            fn = HANDLERS.get(name)
            if fn is None:
                _reply_error(rid, -32601, f"unknown tool {name!r}")
                continue
            try:
                text = fn(**args) if args else fn()
                is_error = text.startswith("error:")
                _reply(rid, {"content": [{"type": "text", "text": text}],
                            "isError": is_error})
            except TypeError as exc:
                _reply_error(rid, -32002, f"bad arguments for {name!r}: {exc}")
            except Exception as exc:  # never let one call kill the server
                _reply(rid, {"content": [{"type": "text",
                                         "text": f"error: tool {name!r} "
                                                 f"failed: {type(exc).__name__}: "
                                                 f"{exc}"}],
                            "isError": True})
        elif rid is not None:
            _reply_error(rid, -32601, f"not implemented: {method}")
    return 0


if __name__ == "__main__":
    sys.exit(serve())
