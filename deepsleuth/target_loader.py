"""Target loader.

Accepts what a user would actually supply — a server directory, an ``mcp.json``
client config, or a raw stdio launch command — and produces normalized ``Target``
objects (launch spec + discovered source + package manifests).
"""
from __future__ import annotations

import json
import os
import shlex
from typing import Dict, List, Optional

from .models import SourceFile, Target

_PY_EXT = {".py"}
_JS_EXT = {".js", ".mjs", ".cjs"}
_TS_EXT = {".ts", ".tsx"}
_MANIFEST_NAMES = {"package.json", "pyproject.toml", "setup.py", "setup.cfg"}
# ``dist`` is intentionally NOT skipped: it is where unpacked npm packages
# ship their (only) source, so skipping it would ingest zero files.
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
              "build", ".mypy_cache", ".pytest_cache", "site-packages"}
_MAX_FILE_BYTES = 2_000_000
_MAX_SOURCE_FILES = 400


def _lang_for(path: str) -> Optional[str]:
    ext = os.path.splitext(path)[1].lower()
    if ext in _PY_EXT:
        return "python"
    if ext in _JS_EXT:
        return "javascript"
    if ext in _TS_EXT:
        return "typescript"
    return None


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(_MAX_FILE_BYTES)
    except OSError:
        return ""


def _collect_dir(root: str) -> (List[SourceFile], Dict[str, str], str):  # type: ignore
    sources: List[SourceFile] = []
    manifests: Dict[str, str] = {}
    runtime = "unknown"
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if fn in _MANIFEST_NAMES:
                manifests[full] = _read(full)
                if fn == "package.json":
                    runtime = "node"
                elif runtime == "unknown" and fn in ("pyproject.toml", "setup.py"):
                    runtime = "python"
            lang = _lang_for(fn)
            if lang and len(sources) < _MAX_SOURCE_FILES:
                sources.append(SourceFile(path=full, language=lang, text=_read(full)))
                if lang == "python" and runtime == "unknown":
                    runtime = "python"
    return sources, manifests, runtime


def _target_from_launch(target_id: str, name: Optional[str], command: str,
                        args: List[str], env: Dict[str, str],
                        cwd: Optional[str], harvest_cwd: bool = True) -> Target:
    t = Target(
        target_id=target_id,
        command=command,
        args=list(args or []),
        env=dict(env or {}),
        cwd=cwd,
        server_name=name,
    )
    # Harvest source from what the command names, not from the directory it
    # happens to run in: a code entry file resolves to its own directory, a
    # relative directory argument (``node .``) names itself, and an absolute
    # directory argument is assumed to be a data workdir (a filesystem
    # server's allowed root), not source. The cwd is only a fallback for
    # config-file entries (where it is the config's own directory); a raw
    # command with no local entry point harvests nothing rather than
    # whatever folder the operator happened to scan from.
    root: Optional[str] = None
    cands = [command] + [a for a in (args or []) if isinstance(a, str)]
    for cand in cands:
        if not cand:
            continue
        if os.path.isabs(cand):
            paths = [cand]
        elif cwd:
            paths = [os.path.join(cwd, cand)]
        else:
            paths = [cand]
        for p in paths:
            if os.path.isfile(p) and _lang_for(p):
                root = os.path.dirname(os.path.abspath(p))
                break
            # a relative dir argument (``node .``) names the source root; an
            # ABSOLUTE dir argument is a data workdir (a filesystem server's
            # allowed root), not source.
            if os.path.isdir(p) and not os.path.isabs(cand):
                root = os.path.abspath(p)
                break
        if root:
            break
    if root is None and harvest_cwd and cwd and os.path.isdir(cwd):
        root = cwd
    if root:
        t.root_dir = os.path.abspath(root)
        srcs, mans, runtime = _collect_dir(t.root_dir)
        t.source_files = srcs
        t.package_manifests = mans
        t.runtime = runtime if runtime != "unknown" else _runtime_from_command(command, args)
    else:
        t.runtime = _runtime_from_command(command, args)
    return t


def _runtime_from_command(command: str, args: List[str]) -> str:
    blob = " ".join([command or ""] + [a for a in (args or []) if isinstance(a, str)]).lower()
    if any(k in blob for k in ("python", "uv ", "uvx", "pipx", ".py")):
        return "python"
    if any(k in blob for k in ("node", "npx", "npm", "bun", ".js", ".mjs", ".ts")):
        return "node"
    return "unknown"


def _parse_mcp_json(path: str) -> List[Target]:
    text = _read(path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    servers = data.get("mcpServers") or data.get("servers") or {}
    base_dir = os.path.dirname(os.path.abspath(path))
    targets: List[Target] = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        command = spec.get("command")
        if not command:
            # http/url based server — record identity but no local launch
            targets.append(Target(target_id=name, server_name=name,
                                  runtime="unknown"))
            continue
        cwd = spec.get("cwd") or base_dir
        tgt = _target_from_launch(
            target_id=name, name=name, command=command,
            args=spec.get("args", []), env=spec.get("env", {}), cwd=cwd,
        )
        tgt.config_entry = str(name)   # v6-W4: configured key, for the handshake check
        targets.append(tgt)
    return targets


def load_targets(spec: str) -> List[Target]:
    """Load one or more targets from a path or a raw launch command string."""
    spec = spec.strip()
    # 1) mcp.json file
    if os.path.isfile(spec) and spec.endswith(".json"):
        found = _parse_mcp_json(spec)
        if found:
            return found
    # 2) directory: look for an mcp.json / .mcp.json, else treat as source dir
    if os.path.isdir(spec):
        for cand in ("mcp.json", ".mcp.json", ".mcp/config.json"):
            p = os.path.join(spec, cand)
            if os.path.isfile(p):
                found = _parse_mcp_json(p)
                if found:
                    for t in found:
                        if not t.root_dir:
                            t.root_dir = os.path.abspath(spec)
                    return found
        # source-only directory
        srcs, mans, runtime = _collect_dir(spec)
        t = Target(
            target_id=os.path.basename(os.path.abspath(spec)) or "target",
            root_dir=os.path.abspath(spec),
            source_files=srcs,
            package_manifests=mans,
            runtime=runtime,
        )
        cmd, args = _guess_launch(t)
        t.command, t.args = cmd, args
        return [t]
    # 3) a single source file
    if os.path.isfile(spec):
        lang = _lang_for(spec)
        t = Target(
            target_id=os.path.basename(spec),
            root_dir=os.path.dirname(os.path.abspath(spec)),
        )
        if lang:
            t.source_files = [SourceFile(path=os.path.abspath(spec), language=lang,
                                         text=_read(spec))]
            t.runtime = "python" if lang == "python" else "node"
        return [t]
    # 4) a raw launch command string, e.g. "python server.py" or "npx foo"
    parts = shlex.split(spec)
    if parts:
        return [_target_from_launch(
            target_id=parts[0], name=None, command=parts[0], args=parts[1:],
            env={}, cwd=os.getcwd(), harvest_cwd=False,
        )]
    return []


def load_reference_listing(path: str):
    """A tool list to compare against WITHOUT launching a second
    server: a JSON array of tool entries (``name``/``description``/
    ``inputSchema``), or an object with a ``tools`` key (an MCP
    ``tools/list`` result, optionally wrapped in ``result``). Returns a
    manifest-only ``ScanContext`` for the cross-server pass, or ``None``
    when the file does not parse into a tool list."""
    from .context import ScanContext, contract_from_listing
    text = _read(path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    name: Optional[str] = None
    tools = None
    if isinstance(data, dict):
        info = data.get("serverInfo") if isinstance(data.get("serverInfo"), dict) else {}
        name = data.get("name") or data.get("server_name") or info.get("name")
        inner = data.get("result") if isinstance(data.get("result"), dict) else data
        tools = inner.get("tools") if isinstance(inner, dict) else None
    elif isinstance(data, list):
        tools = data
    if not isinstance(tools, list):
        return None
    tid = f"reference:{os.path.basename(path)}"
    ctx = ScanContext(target=Target(target_id=tid, server_name=str(name) if name else tid))
    ctx.tools = [contract_from_listing(t, "tool") for t in tools if isinstance(t, dict)]
    ctx.layers.add("manifest")
    return ctx


def _guess_launch(t: Target) -> "tuple[Optional[str], List[str]]":
    """Best-effort (command, args) for a source-only directory (used by the dynamic
    layer; safe because it only runs inside the sandbox, or unsandboxed only for
    trusted fixtures). ``python3`` exists in both the slim base image and locally."""
    if not t.root_dir:
        return None, []
    if t.runtime == "python":
        for cand in ("server.py", "main.py", "__main__.py", "app.py"):
            if os.path.isfile(os.path.join(t.root_dir, cand)):
                return "python3", [os.path.join(t.root_dir, cand)]
    if t.runtime == "node":
        for cand in ("index.js", "server.js", "main.js"):
            if os.path.isfile(os.path.join(t.root_dir, cand)):
                return "node", [os.path.join(t.root_dir, cand)]
    return None, []
