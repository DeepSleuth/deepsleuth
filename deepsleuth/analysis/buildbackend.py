"""Static analysis of a LOCAL (in-tree) PEP 517 build backend.

``pyproject.toml`` can declare ``[build-system] backend-path = [...]`` plus a
``build-backend = "module[:object]"``: the build front-end then imports that
module FROM THE REPOSITORY and calls its hooks (``build_wheel``,
``get_requires_for_build_wheel``, ...) at install time -- code that runs before
the server is ever launched, outside any tool sandbox, with the installing
user's credentials. The v1 scan only noted that ``backend-path`` exists. This
module reads the backend's SOURCE (never executes it) and reports what it does:

* ``credentials`` -- a read/open/join that reaches a credential-shaped path
  (``~/.ssh``, ``.aws/credentials``, ``.netrc``, ``.env`` ...), including a
  path assembled from constants (``os.path.join(home, ".ssh", "id_rsa")``,
  ``Path.home() / ".aws" / "credentials"``);
* ``network`` -- a call that sends or fetches over the network
  (``urllib.request.urlopen``, ``requests.*``, ``socket.*``, ``smtplib`` ...);
* ``exec`` -- an exec sink with no honest build reason: ``eval``/``exec``,
  ``os.system``/``os.popen``/``os.exec*``, ``subprocess`` with ``shell=True``
  or with a shell / downloader as argv[0];
* ``obfuscation`` -- a decode (base64 / zlib / rot13) in a module that also
  reaches an exec sink.

A backend that only BUILDS -- delegating to ``setuptools.build_meta``, writing
metadata, calling ``subprocess.run(["gcc", ...])`` with a constant argv --
produces no fact and stays at the pre-existing low note. Same-directory
imports of the backend are followed (two hops, cycle-safe).
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .pyast import dotted_name, parse_module

CREDENTIAL_PATH = re.compile(
    r"(\.ssh(?:/|$)|id_rsa|id_ed25519|id_ecdsa|authorized_keys|\.aws(?:/|$)|"
    r"\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials|\.docker/config\.json|"
    r"\.kube(?:/|$)|/etc/passwd|/etc/shadow|(?:^|/)\.env\b|\.gnupg|"
    r"\.config/gcloud|\.azure(?:/|$))", re.IGNORECASE)

_NET_ROOTS = {"requests", "httpx", "aiohttp", "urllib3"}
_NET_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen",
                "urlretrieve", "Session", "Client", "ClientSession", "PoolManager"}
_NET_LAST = {"urlopen", "urlretrieve", "create_connection", "HTTPConnection",
             "HTTPSConnection", "SMTP", "SMTP_SSL", "FTP", "FTP_TLS", "Telnet"}
_SHELL_BINARIES = {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "pwsh",
                   "curl", "wget", "nc", "ncat", "netcat"}
_EXEC_BUILTINS = {"eval", "exec"}
_OS_EXEC = {"system", "popen", "execv", "execve", "execl", "execle", "execlp", "execvp",
            "execvpe", "spawnl", "spawnv", "spawnlp", "spawnvp", "startfile"}
_DECODERS = {"b64decode", "b32decode", "a85decode", "unhexlify", "decompress", "rot13",
             "fromhex"}


@dataclass
class BackendFacts:
    credentials: List[Dict] = field(default_factory=list)
    network: List[Dict] = field(default_factory=list)
    exec: List[Dict] = field(default_factory=list)
    obfuscation: List[Dict] = field(default_factory=list)

    def empty(self) -> bool:
        return not (self.credentials or self.network or self.exec or self.obfuscation)

    def merge(self, other: "BackendFacts", module: str) -> None:
        for name in ("credentials", "network", "exec", "obfuscation"):
            for rec in getattr(other, name):
                rec = dict(rec)
                rec.setdefault("module", module)
                getattr(self, name).append(rec)


def _str_consts(node: ast.AST) -> List[str]:
    """Every string constant inside a Path-building expression chain."""
    out: List[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
    return out


def _docstring_ids(tree: ast.AST) -> set:
    ids = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(n, "body", None) or []
            if body and isinstance(body[0], ast.Expr) and isinstance(
                    getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                ids.add(id(body[0].value))
    return ids


def _snippet(src_lines: List[str], node: ast.AST) -> str:
    ln = getattr(node, "lineno", 0)
    if 1 <= ln <= len(src_lines):
        return src_lines[ln - 1].strip()[:160]
    return ""


def analyze_backend_source(text: str) -> BackendFacts:
    facts = BackendFacts()
    tree = parse_module(text)
    if tree is None:
        return facts
    lines = text.splitlines()
    docs = _docstring_ids(tree)
    decodes = False
    exec_hit = False

    for node in ast.walk(tree):
        # -- credential-shaped path -------------------------------------------
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and id(node) not in docs:
            if CREDENTIAL_PATH.search(node.value) and len(node.value) < 200:
                facts.credentials.append({"line": getattr(node, "lineno", 0),
                                          "code": _snippet(lines, node),
                                          "path": node.value[:80]})
        elif isinstance(node, ast.Call):
            name = dotted_name(node.func) or ""
            last = name.rsplit(".", 1)[-1]
            if last in ("join", "joinpath", "Path", "PurePath", "expanduser", "open"):
                joined = "/".join(c.strip("/") for c in _str_consts(node) if c)
                if joined and CREDENTIAL_PATH.search(joined) and not any(
                        r["line"] == getattr(node, "lineno", 0) for r in facts.credentials):
                    facts.credentials.append({"line": getattr(node, "lineno", 0),
                                              "code": _snippet(lines, node),
                                              "path": joined[:80]})
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            joined = "/".join(c.strip("/") for c in _str_consts(node) if c)
            if joined and CREDENTIAL_PATH.search(joined) and not any(
                    r["line"] == getattr(node, "lineno", 0) for r in facts.credentials):
                facts.credentials.append({"line": getattr(node, "lineno", 0),
                                          "code": _snippet(lines, node), "path": joined[:80]})

        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func) or ""
        parts = name.split(".")
        root, last = parts[0], parts[-1]

        # -- network ------------------------------------------------------------
        is_net = (last in _NET_LAST
                  or (root in _NET_ROOTS and last in _NET_METHODS)
                  or name in ("socket.socket", "socket.create_connection"))
        if is_net:
            facts.network.append({"line": getattr(node, "lineno", 0),
                                  "code": _snippet(lines, node), "call": name})

        # -- exec sinks ---------------------------------------------------------
        sink = ""
        if name in _EXEC_BUILTINS:
            sink = name
        elif root == "os" and last in _OS_EXEC:
            sink = name
        elif root == "pty" and last == "spawn":
            sink = name
        elif root == "subprocess" or name in ("check_output", "check_call", "Popen"):
            shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                             and k.value.value is True for k in node.keywords)
            argv0 = ""
            if node.args:
                a0 = node.args[0]
                if isinstance(a0, (ast.List, ast.Tuple)) and a0.elts and isinstance(
                        a0.elts[0], ast.Constant) and isinstance(a0.elts[0].value, str):
                    argv0 = os.path.basename(a0.elts[0].value).lower()
                elif isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                    argv0 = os.path.basename(a0.value.split()[0]).lower() if a0.value.split() else ""
            if shell_true or argv0 in _SHELL_BINARIES:
                sink = name or "subprocess"
        if sink:
            exec_hit = True
            facts.exec.append({"line": getattr(node, "lineno", 0),
                               "code": _snippet(lines, node), "call": sink})
        if last in _DECODERS:
            decodes = True
            facts.obfuscation.append({"line": getattr(node, "lineno", 0),
                                      "code": _snippet(lines, node), "call": name})
    # a decode alone is ordinary (metadata, wheel hashing); it is an
    # obfuscation signal only in a module that also reaches an exec sink
    if not (decodes and exec_hit):
        facts.obfuscation = []
    return facts


# ---- pyproject [build-system] parsing --------------------------------------


def parse_build_system(text: str) -> Dict[str, object]:
    """``{"backend": str|None, "backend_path": [str]}`` from a pyproject.toml
    text (tomllib when available, a tolerant regex fallback otherwise)."""
    backend: Optional[str] = None
    paths: List[str] = []
    try:
        import tomllib  # py3.11+
        data = tomllib.loads(text)
        bs = data.get("build-system") or {}
        if isinstance(bs, dict):
            b = bs.get("build-backend")
            backend = b if isinstance(b, str) else None
            bp = bs.get("backend-path")
            if isinstance(bp, list):
                paths = [p for p in bp if isinstance(p, str)]
        return {"backend": backend, "backend_path": paths}
    except Exception:
        pass
    m = re.search(r'(?m)^\s*build-backend\s*=\s*["\']([^"\']+)["\']', text)
    if m:
        backend = m.group(1)
    m = re.search(r'backend-path\s*=\s*\[([^\]]*)\]', text)
    if m:
        paths = re.findall(r'["\']([^"\']*)["\']', m.group(1))
    return {"backend": backend, "backend_path": paths}


def backend_module_candidates(manifest_dir: str, backend: str, backend_path: List[str]
                              ) -> List[str]:
    """Filesystem candidates for the backend module: ``a.b:obj`` ->
    ``<dir>/a/b.py`` / ``<dir>/a/b/__init__.py`` for each backend-path dir
    (an empty backend-path means the project root)."""
    mod = (backend or "").split(":", 1)[0].strip()
    if not mod:
        return []
    rel = mod.replace(".", os.sep)
    dirs = backend_path or ["."]
    out: List[str] = []
    for d in dirs:
        base = os.path.normpath(os.path.join(manifest_dir, d))
        out.append(os.path.join(base, rel + ".py"))
        out.append(os.path.join(base, rel, "__init__.py"))
    return out
