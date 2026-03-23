"""Minimal, dependency-free MCP client/framing over stdio JSON-RPC.

The brief suggests the official ``mcp`` SDK, but many host environments are
externally-managed (PEP 668) and cannot pip-install it. To stay runnable and fully
deterministic everywhere, we speak the protocol directly: newline-delimited UTF-8
JSON-RPC 2.0 messages over the child's stdin/stdout, exactly as the MCP stdio
transport specifies. This is used by Frontend B (batch dynamic layer) and by the
downstream leg of Frontend A (the proxy)."""
from __future__ import annotations

import json
import queue
import threading
from typing import Any, Dict, IO, List, Optional

PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "deepsleuth", "version": "1.0.0"}


def write_message(stream: IO[bytes], obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"
    stream.write(data)
    stream.flush()


def read_message(stream: IO[bytes]) -> Optional[Dict[str, Any]]:
    line = stream.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return {}
    try:
        return json.loads(line.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}


class StdioClient:
    """Synchronous request/response client over a subprocess's stdio.

    A background thread parses inbound messages into a queue; ``request`` blocks
    for the matching id up to ``timeout`` (a timeout is itself recorded as a DoS
    signal by the caller). Server-initiated requests (e.g. elicitation) are queued
    for the caller to inspect/answer."""

    def __init__(self, proc, timeout: float = 20.0):
        self.proc = proc
        self.timeout = timeout
        self._id = 0
        self._inbox: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._responses: Dict[int, Dict[str, Any]] = {}
        self._server_requests: List[Dict[str, Any]] = []
        self._notifications: List[Dict[str, Any]] = []
        self._alive = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        try:
            while True:
                msg = read_message(self.proc.stdout)
                if msg is None:
                    break
                if not msg:
                    continue
                if "id" in msg and ("result" in msg or "error" in msg):
                    self._responses[msg["id"]] = msg
                elif "method" in msg and "id" in msg:
                    self._server_requests.append(msg)  # server->client request
                elif "method" in msg:
                    self._notifications.append(msg)  # notification
        except Exception:
            pass
        finally:
            self._alive = False
            self._inbox.put({"_eof": True})

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        write_message(self.proc.stdin, {"jsonrpc": "2.0", "method": method,
                                        "params": params or {}})

    def request(self, method: str, params: Optional[Dict[str, Any]] = None,
                timeout: Optional[float] = None) -> Dict[str, Any]:
        import time
        rid = self._next_id()
        write_message(self.proc.stdin, {"jsonrpc": "2.0", "id": rid,
                                        "method": method, "params": params or {}})
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            if rid in self._responses:
                return self._responses.pop(rid)
            if not self._alive and rid not in self._responses:
                # process died; give the reader a moment then bail
                if rid in self._responses:
                    return self._responses.pop(rid)
                return {"error": {"code": -1, "message": "server exited"}, "_dead": True}
            time.sleep(0.01)
        return {"error": {"code": -2, "message": "timeout"}, "_timeout": True}

    # --- protocol convenience ---
    def initialize(self) -> Dict[str, Any]:
        resp = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "clientInfo": CLIENT_INFO,
        })
        self.notify("notifications/initialized")
        return resp

    def list_tools(self) -> List[Dict[str, Any]]:
        resp = self.request("tools/list")
        return ((resp.get("result") or {}).get("tools")) or []

    def list_resources(self) -> List[Dict[str, Any]]:
        resp = self.request("resources/list")
        return ((resp.get("result") or {}).get("resources")) or []

    def list_prompts(self) -> List[Dict[str, Any]]:
        resp = self.request("prompts/list")
        return ((resp.get("result") or {}).get("prompts")) or []

    def call_tool(self, name: str, arguments: Dict[str, Any],
                  timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments},
                            timeout=timeout)

    # rule 3.4 — resources and prompts are LISTED by the base plan but never
    # READ; a credential resource sitting right next to the tool listing is
    # invisible to every response rule unless something actually fetches its
    # content. Both mirror ``call_tool``'s timeout/error shape so a caller
    # can reuse ``sandbox.argsynth.flatten_result`` on the result unchanged.
    def read_resource(self, uri: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("resources/read", {"uri": uri}, timeout=timeout)

    def get_prompt(self, name: str, arguments: Optional[Dict[str, Any]] = None,
                   timeout: Optional[float] = None) -> Dict[str, Any]:
        return self.request("prompts/get", {"name": name, "arguments": arguments or {}},
                            timeout=timeout)

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except Exception:
            pass
