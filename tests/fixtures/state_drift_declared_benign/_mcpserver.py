"""Tiny self-contained MCP stdio server harness for INERT test fixtures.

Stdlib-only and dependency-free so a fixture can be launched directly or inside the
Docker sandbox. It speaks the same newline-delimited JSON-RPC framing as
``deepsleuth.mcpclient``. Fixtures register tools with an ``@mcp.tool(...)``
decorator whose *shape* the AST detectors recognize (``last_attr == 'tool'``,
``description=``/``annotations=`` kwargs), so the same file is both a runnable
server and analyzable source.

These are the author's own sanity fixtures — NOT the evaluation. Every dangerous
operation is guarded by ``INERT`` (default on) so nothing harmful ever executes.
"""
from __future__ import annotations

import inspect
import json
import sys
from typing import Any, Callable, Dict, List, Optional

INERT = True  # fixture safety switch: dangerous sinks are never actually executed


def _schema_from_sig(fn: Callable) -> Dict[str, Any]:
    props: Dict[str, Any] = {}
    required: List[str] = []
    for pname, p in inspect.signature(fn).parameters.items():
        if pname in ("self", "cls", "ctx", "context"):
            continue
        props[pname] = {"type": "string"}
        if p.default is inspect._empty:
            required.append(pname)
    return {"type": "object", "properties": props, "required": required}


class MCP:
    def __init__(self, name: str, version: str = "0.0.1"):
        self.name = name
        self.version = version
        self._tools: List[Dict[str, Any]] = []
        self._handlers: Dict[str, Callable] = {}

    def tool(self, name: Optional[str] = None, description: Optional[str] = None,
             annotations: Optional[Dict[str, Any]] = None, **_kw):
        def deco(fn: Callable) -> Callable:
            tname = name or fn.__name__
            desc = description if description is not None else (fn.__doc__ or "")
            entry = {"name": tname, "description": desc,
                     "inputSchema": _schema_from_sig(fn)}
            if annotations:
                entry["annotations"] = dict(annotations)
            self._tools.append(entry)
            self._handlers[tname] = fn
            return fn
        return deco

    # --- stdio serve loop ---
    def _write(self, obj: Dict[str, Any]) -> None:
        sys.stdout.buffer.write(json.dumps(obj, separators=(",", ":")).encode() + b"\n")
        sys.stdout.buffer.flush()

    def run(self) -> None:
        for raw in iter(sys.stdin.buffer.readline, b""):
            line = raw.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            method = msg.get("method")
            rid = msg.get("id")
            if method == "initialize":
                self._write({"jsonrpc": "2.0", "id": rid, "result": {
                    "protocolVersion": msg.get("params", {}).get("protocolVersion",
                                                                  "2024-11-05"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": self.name, "version": self.version}}})
            elif method == "notifications/initialized":
                continue
            elif method == "tools/list":
                self._write({"jsonrpc": "2.0", "id": rid,
                             "result": {"tools": self._tools}})
            elif method in ("resources/list", "prompts/list"):
                key = "resources" if "resources" in method else "prompts"
                self._write({"jsonrpc": "2.0", "id": rid, "result": {key: []}})
            elif method == "tools/call":
                params = msg.get("params") or {}
                name = params.get("name")
                args = params.get("arguments") or {}
                fn = self._handlers.get(name)
                if fn is None:
                    self._write({"jsonrpc": "2.0", "id": rid,
                                 "error": {"code": -32601, "message": "unknown tool"}})
                    continue
                try:
                    text = fn(**args)
                except Exception as exc:  # inert fixtures should not raise
                    text = f"error: {exc}"
                self._write({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": str(text)}],
                    "isError": False}})
            elif rid is not None:
                self._write({"jsonrpc": "2.0", "id": rid,
                             "error": {"code": -32601, "message": "not implemented"}})
