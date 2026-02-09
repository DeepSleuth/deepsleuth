"""rule 5.8 — supply-chain / install-time execution.

Malicious code that runs at *install* time, before the server is ever launched,
is invisible to any scanner that only inspects the running server. We parse
package manifests and flag:
* npm lifecycle hooks (pre/post/install, prepare, prepublish…) that execute code —
  severity scaled by how suspicious the command is (ad-hoc inline eval / network
  download / obfuscation = high; a plain local build script = low),
* Python ``setup.py`` that runs commands / network / exec at build time or via a
  custom install command class,
* dependency names that are edit-distance/homoglyph near-collisions of popular
  packages (typosquatting).
Install scripts are NEVER executed here; if run, that happens only in the sandbox.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from ..analysis.buildbackend import (BackendFacts, analyze_backend_source,
                                     backend_module_candidates, parse_build_system)
from ..analysis.editdist import damerau_levenshtein
from ..context import ScanContext
from ..models import Finding
from .base import CAP_PACKAGE, Detector, register
from ._util import mk

INSTALL_HOOK_KEYS = {"preinstall", "install", "postinstall", "prepare",
                     "prepublish", "prepublishOnly", "prepack", "preuninstall"}

# V3-2: the old single DANGER bag-of-tokens over-fired badly on ordinary build
# steps — "chmod +x dist/mytool" after a local compile, "/tmp/" in a cache path,
# a bare "node -e \"console.log(...)\"", even a bare "-e " flag — none of which
# are "a hook that does something an install step has no honest reason to do"
# (rule P1.4/V3-2's own wording). Rebuilt around the report's exact three shapes:
# a hook that (1) fetches remote content AND executes/pipes it, (2) reads a
# credential-shaped path, or (3) runs obviously obfuscated/encoded content.
# Each shape is its own narrow signal instead of one wide bag of tokens.

# (1a) a network-fetch client invocation
_NETWORK_FETCH = re.compile(
    r"(curl\s|wget\s|https?://|ftp://|invoke-webrequest|\biwr\b|downloadstring|"
    r"nc\s+-|ncat\s|netcat\s|/dev/tcp/)", re.IGNORECASE)
# (1b) that fetched content is piped/handed straight to an interpreter, or a
# just-fetched path is chmod'd executable and then invoked by the same path —
# structural (same path re-executed) rather than keyed to any one fixture's
# command wording.
_EXEC_PIPE = re.compile(
    r"\|\s*(sh|bash|zsh|python[0-9]?|node|iex|invoke-expression)\b", re.IGNORECASE)
_EXEC_SUBSHELL = re.compile(r"(sh|bash|zsh)\s+-c\s+[\"']?\$\(", re.IGNORECASE)
_EXEC_CHMOD_SAME_PATH = re.compile(
    r"chmod\s+\+x\s+(\S+).{0,60}(?:&&|;)\s*\1\b", re.IGNORECASE)
_EXEC_RELATIVE = re.compile(
    r"(?:&&|;)\s*\./\S+|\b(?:sh|bash)\s+\./\S+", re.IGNORECASE)


def _exec_sink(cmd: str) -> bool:
    return bool(_EXEC_PIPE.search(cmd) or _EXEC_SUBSHELL.search(cmd)
                or _EXEC_CHMOD_SAME_PATH.search(cmd) or _EXEC_RELATIVE.search(cmd))


# (2) a credential-shaped path an install step has no honest reason to touch
CREDENTIAL_PATH = re.compile(
    r"(\.ssh/|id_rsa|id_ed25519|id_ecdsa|authorized_keys|\.aws/credentials|"
    r"\.aws/config|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials|"
    r"\.docker/config\.json|\.kube/config|/etc/passwd|/etc/shadow|\.env\b)",
    re.IGNORECASE)
# (3) obfuscated/encoded payload content
OBFUSCATION = re.compile(
    r"(base64\s+-?-?d|atob\(|fromCharCode|eval\(atob|"
    r"\bbase64\b.{0,12}(decode|b64decode)\(|,\s*['\"]base64['\"]\s*\)|"
    r"Buffer\.from\(.{0,30}base64)", re.IGNORECASE)
# unambiguous destructive/reverse-shell shapes, regardless of the 3 buckets above
DESTRUCTIVE = re.compile(
    r"(rm\s+-rf\s+/(?!\S)|rm\s+-rf\s+~|:\(\)\{\s*:\|:&\s*\};:|"
    r"mkfifo\s+/tmp/\w+.{0,40}/dev/tcp/)", re.IGNORECASE)

# a small, generic list of popular packages for typosquat comparison (not drawn
# from any sample corpus — just widely-known names). rule 4.3 widens both lists.
POPULAR_NPM = {
    "react", "lodash", "express", "axios", "chalk", "commander", "request",
    "moment", "debug", "async", "webpack", "typescript", "next", "vue",
    "dotenv", "uuid", "yargs", "jest", "eslint", "prettier", "node-fetch",
    "cross-env", "rimraf", "glob", "colors", "bluebird", "socket.io",
    "react-dom", "redux", "semver", "minimist", "underscore", "classnames",
    "core-js", "babel-core", "webpack-cli", "vite", "svelte", "angular",
    "rxjs", "lru-cache", "chokidar", "mkdirp", "inquirer", "ora", "boxen",
    "ws", "cheerio", "puppeteer", "sharp", "mongoose", "pg", "mysql2",
    "nodemon", "concurrently", "husky", "lint-staged", "vitest", "mocha",
    "chai", "sinon", "supertest", "zod", "graphql", "apollo-server",
    "styled-components", "tailwindcss", "postcss", "sass", "less",
}
POPULAR_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "urllib3", "boto3",
    "setuptools", "pytest", "pyyaml", "click", "jinja2", "cryptography",
    "certifi", "six", "python-dateutil", "aiohttp", "fastapi", "pydantic",
    "sqlalchemy", "pillow", "scipy", "beautifulsoup4", "tqdm", "colorama",
    "scikit-learn", "matplotlib", "attrs", "packaging", "wheel", "pip",
    "idna", "charset-normalizer", "markupsafe", "werkzeug", "starlette",
    "uvicorn", "gunicorn", "httpx", "websockets", "redis", "celery",
    "pytz", "typing-extensions", "protobuf", "grpcio", "pyjwt", "bcrypt",
    "paramiko", "docker", "kubernetes", "openai", "anthropic", "langchain",
    "transformers", "torch", "tensorflow", "pyarrow", "lxml", "openpyxl",
}
# well-known reference/official MCP server package identities — used only to
# catch a *typosquat-shaped near miss* of one of these, never to require or
# assume any particular server IS one of them (rule 4.3, "the server's own
# name"). Sourced from the MCP ecosystem's own commonly-cited reference and
# popular servers, not from any evaluation corpus.
POPULAR_MCP_SERVERS = {
    "filesystem", "git", "fetch", "memory", "github", "gitlab", "slack",
    "gdrive", "postgres", "sqlite", "puppeteer", "everything",
    "sequential-thinking", "time", "sentry", "docker", "kubernetes", "aws",
    "azure", "jira", "notion", "linear", "brave-search", "google-maps",
}
_MCP_QUALIFIER_RX = re.compile(r"(?:^|[-_])(mcp|server|official|tool|tools)(?=[-_]|$)",
                               re.IGNORECASE)


# --- Part-A.3 (v4): a hook that merely *invokes* a bundled script (the
# overwhelmingly common real-world shape: "node scripts/postinstall.js",
# "python3 build_hook.py", "bash setup.sh", "./configure.sh") carries no
# danger signal in the hook line itself — the payload lives in the referenced
# file. The old inline-only requirement missed this indirection entirely. We
# extract the referenced path and analyze the FILE's own content with the same
# danger shapes; a hook whose script is an ordinary build/compile step stays
# silent (rule P1.4), one whose script reaches a dangerous shape is attributed to
# the hook via the script it runs.
_SCRIPT_REF_RE = re.compile(
    r"\b(?:node|nodejs)\s+([./\w-]+\.(?:m?js|cjs|ts))|"
    r"\b(?:python3?|py)\s+([./\w-]+\.py)|"
    r"\b(?:bash|sh|zsh)\s+([./\w-]+\.sh)|"
    r"\bruby\s+([./\w-]+\.rb)|"
    r"(\./[\w./-]+)",
    re.IGNORECASE,
)
# library-call-shaped network / exec sinks inside a REFERENCED SCRIPT's own
# body (as opposed to _NETWORK_FETCH/_exec_sink, which match a one-line shell
# command) — a script fetching-and-executing is the same mechanism, expressed
# in JS/Python API calls instead of shell pipes.
_SCRIPT_NETWORK = re.compile(
    r"(https?://|require\(['\"](?:https?|node-fetch|axios)['\"]\)|\bfetch\(|"
    r"\baxios[.(]|\bhttp\.get\(|\bhttps\.get\(|\bhttp\.request\(|\bhttps\.request\(|"
    r"^\s*import\s+requests\b|\bimport\s+urllib|\burllib\.request|"
    r"\bsocket\.socket\(|\bhttp\.client\b)", re.IGNORECASE | re.MULTILINE)
_SCRIPT_EXEC = re.compile(
    r"(require\(['\"]child_process['\"]\)|\bexecSync\(|\bspawnSync\(|\bexec\(|"
    r"\bspawn\(|\beval\(|\bnew\s+Function\(|\bsubprocess\.|\bos\.system\(|"
    r"\bos\.popen\()", re.IGNORECASE)


def _referenced_script_paths(cmd: str) -> List[str]:
    out: List[str] = []
    for m in _SCRIPT_REF_RE.finditer(cmd):
        for g in m.groups():
            if g:
                out.append(g)
    return out


def _resolve_script_text(ctx: ScanContext, manifest_path: str, ref: str) -> Optional[str]:
    """Best-effort lookup of a hook-referenced script's own text — from source
    already collected by the target loader, or (only for a local directory
    scan) a direct read. Never executes the script."""
    ref_norm = ref[2:] if ref.startswith("./") else ref
    ref_norm = ref_norm.lstrip("/")
    base_dir = os.path.dirname(manifest_path)
    target = getattr(ctx, "target", None)
    candidates = set()
    if target is not None and getattr(target, "root_dir", None):
        candidates.add(os.path.normpath(os.path.join(target.root_dir, ref_norm)))
    candidates.add(os.path.normpath(os.path.join(base_dir, ref_norm)))
    for sf in (getattr(target, "source_files", None) or []):
        sfp = os.path.normpath(sf.path)
        if sfp in candidates or sfp.endswith(os.sep + ref_norm) or sfp == ref_norm:
            return sf.text
    for cand in candidates:
        if os.path.isfile(cand):
            try:
                with open(cand, "r", encoding="utf-8", errors="replace") as fh:
                    return fh.read(200_000)
            except OSError:
                continue
    return None


def _script_danger(text: str) -> Optional[Dict[str, str]]:
    if CREDENTIAL_PATH.search(text):
        return {"reason": "referenced script reads a credential-shaped path"}
    if OBFUSCATION.search(text):
        return {"reason": "referenced script runs obfuscated/encoded content"}
    if DESTRUCTIVE.search(text):
        return {"reason": "referenced script contains an unambiguous "
                          "destructive/reverse-shell construct"}
    if _SCRIPT_NETWORK.search(text) and _SCRIPT_EXEC.search(text):
        return {"reason": "referenced script fetches remote content and "
                          "executes/spawns a process from it"}
    return None


def _classify_hook_cmd(cmd: str) -> Optional[Dict[str, Any]]:
    """Classify an install/build hook command, or ``None`` to not report it at
    all (rule P1.4/V3-2). An install/build hook that runs code is extremely
    common and usually benign (compiling native addons, running a bundler/
    type-checker/codegen step, chmod'ing a *freshly built* local binary) — the
    mere presence of a hook, a bare inline `-e`/`-c` one-liner, a `/tmp/` path,
    or a `chmod +x` on the tool's own output is not a signal on its own,
    regardless of exact wording (V3-2: this must generalize past any one
    fixture's phrasing).

    Part-A.3 (v4): report at the actionable bar on its own (``dangerous_shape``
    -> high/high, an unconditional contradiction — calibration never lowers
    it) for: a credential-shaped path read, obfuscated/encoded content, an
    unambiguous destructive/reverse-shell construct, or fetching remote
    content AND executing/piping it. A BARE network call with no exec/pipe
    combination (downloading an asset an install step will use later) is
    still worth surfacing on its own — installers have no inherent need to
    reach the network — but it is a softer signal, so it lands at
    high-severity/medium-confidence (still actionable — confirm, not an
    automatic block)."""
    if CREDENTIAL_PATH.search(cmd):
        return {"severity": "high", "confidence": "high", "dangerous_shape": True,
                "reason": "reads a credential-shaped path"}
    if OBFUSCATION.search(cmd):
        return {"severity": "high", "confidence": "high", "dangerous_shape": True,
                "reason": "runs obfuscated/encoded content"}
    if DESTRUCTIVE.search(cmd):
        return {"severity": "high", "confidence": "high", "dangerous_shape": True,
                "reason": "unambiguous destructive/reverse-shell construct"}
    if _NETWORK_FETCH.search(cmd) and _exec_sink(cmd):
        return {"severity": "high", "confidence": "high", "dangerous_shape": True,
                "reason": "fetches remote content and pipes/executes it"}
    if _NETWORK_FETCH.search(cmd):
        return {"severity": "high", "confidence": "medium", "dangerous_shape": False,
                "reason": "makes a network call at install time"}
    return None


def _own_name_candidates(ctx: ScanContext) -> List[str]:
    """rule 4.3 — every name this server declares as ITS OWN identity: the
    config/target alias, and any package-manifest ``name`` field."""
    out = []
    if ctx.target.server_name:
        out.append(ctx.target.server_name)
    for path, text in sorted(ctx.package_manifests.items()):
        base = os.path.basename(path)
        try:
            if base == "package.json":
                data = json.loads(text)
                nm = data.get("name") if isinstance(data, dict) else None
                if isinstance(nm, str) and nm.strip():
                    out.append(nm.strip())
            elif base in ("pyproject.toml", "setup.py"):
                m = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', text)
                if m:
                    out.append(m.group(1))
        except Exception:
            continue
    return out


def _own_name_typosquat(ctx: ScanContext) -> List[Finding]:
    """rule 4.3 — widen the typosquat check to the SERVER's OWN declared name,
    not just its dependencies: a near-miss (edit distance 1, transposition-
    aware) of a well-known reference/popular MCP server's identity, once
    generic qualifiers (mcp/server/tool/official) are stripped so an honest
    "filesystem-mcp-server" (an exact match once qualifiers are stripped)
    never fires — only a genuine character-level near miss like
    "filesystemm-mcp" does."""
    out: List[Finding] = []
    seen = set()
    for raw in _own_name_candidates(ctx):
        n = _MCP_QUALIFIER_RX.sub("", raw.lower())
        n = re.sub(r"[-_]+", "-", n).strip("-_/")
        if not n or len(n) < 5 or n in seen:
            continue
        seen.add(n)
        if n in POPULAR_MCP_SERVERS:
            continue  # an honest, exact reference-server identity
        for pop in POPULAR_MCP_SERVERS:
            d = damerau_levenshtein(n, pop)
            if 0 < d <= 1:
                out.append(mk(
                    ctx, detector_id="supply-chain", category="supply-chain",
                    evidence_location="server-identity", severity="medium",
                    confidence="low", detection_method="server-name-typosquat-editdistance",
                    rationale=(
                        f"This server's own declared identity ('{raw}', normalized "
                        f"'{n}') is edit-distance {d} from the well-known reference/"
                        f"popular MCP server '{pop}' — a typosquat-shaped name a "
                        "client could mistake for the real one when choosing which "
                        "server to install or connect to."
                    ),
                    evidence={"declared_name": raw, "normalized": n, "near": pop,
                              "distance": d},
                    source_kind="static-manifest", tool_name=None,
                ))
                break
    return out


def _run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for path, text in sorted(ctx.package_manifests.items()):
        base = os.path.basename(path)
        if base == "package.json":
            out.extend(_scan_package_json(ctx, path, text))
        elif base == "setup.py":
            out.extend(_scan_setup_py(ctx, path, text))
        elif base == "pyproject.toml":
            out.extend(_scan_pyproject(ctx, path, text))
    out.extend(_own_name_typosquat(ctx))
    return out


def _scan_package_json(ctx: ScanContext, path: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    scripts = data.get("scripts") or {}
    for hook in sorted(INSTALL_HOOK_KEYS):
        if hook not in scripts:
            continue
        cmd = str(scripts[hook])
        graded = _classify_hook_cmd(cmd)
        if graded is not None:
            out.append(mk(
                ctx, detector_id="supply-chain", category="supply-chain",
                evidence_location="install-time-script",
                severity=graded["severity"], confidence=graded["confidence"],
                detection_method="install-hook-scan",
                rationale=(f"npm '{hook}' lifecycle hook executes code before the "
                           "server is ever launched — install-time execution runs "
                           f"outside any tool sandbox and {graded['reason']}."),
                evidence={"hook": hook, "command": cmd[:300], "manifest": path},
                source_kind="static-code", tool_name=None,
                raw={"dangerous_shape": graded["dangerous_shape"]},
            ))
            continue
        # Part-A.3: the hook line itself is clean — check whether it merely
        # INVOKES a bundled script and, if so, analyze that script's own
        # content (do NOT require the danger to be inline in the hook string).
        for ref in _referenced_script_paths(cmd):
            script_text = _resolve_script_text(ctx, path, ref)
            if not script_text:
                continue
            danger = _script_danger(script_text)
            if danger is None:
                continue  # an ordinary local build/compile script — stays silent
            out.append(mk(
                ctx, detector_id="supply-chain", category="supply-chain",
                evidence_location="install-time-script", severity="high",
                confidence="high", detection_method="install-hook-script-scan",
                rationale=(f"npm '{hook}' lifecycle hook invokes the bundled script "
                           f"'{ref}' whose own content — not the hook line — "
                           f"{danger['reason']}; install-time execution runs outside "
                           "any tool sandbox and is a supply-chain risk."),
                evidence={"hook": hook, "command": cmd[:300], "referenced_script": ref,
                          "manifest": path, "script_excerpt": script_text[:300]},
                source_kind="static-code", tool_name=None,
                raw={"dangerous_shape": True},
            ))
            break
    # typosquat on dependency names
    deps: Dict[str, str] = {}
    for k in ("dependencies", "devDependencies", "optionalDependencies"):
        d = data.get(k)
        if isinstance(d, dict):
            deps.update(d)
    out.extend(_typosquat(ctx, path, list(deps.keys()), POPULAR_NPM))
    return out


def _scan_setup_py(ctx: ScanContext, path: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    m = None
    dangerous_shape = False
    if CREDENTIAL_PATH.search(text) or OBFUSCATION.search(text) or DESTRUCTIVE.search(text):
        sev, conf, dangerous_shape = "high", "high", True
        m = (CREDENTIAL_PATH.search(text) or OBFUSCATION.search(text)
             or DESTRUCTIVE.search(text))
    elif _NETWORK_FETCH.search(text) and _exec_sink(text):
        sev, conf, dangerous_shape = "high", "high", True
        m = _NETWORK_FETCH.search(text)
    elif _NETWORK_FETCH.search(text):
        # Part-A.3: a bare network call at build/install time, no exec combo
        # required — still surfaced on its own (medium confidence: still
        # actionable, but not an automatic block).
        sev, conf = "high", "medium"
        m = _NETWORK_FETCH.search(text)
    elif re.search(r"cmdclass|class\s+\w+\(.*install", text):
        # a custom install command class is a structural signal (setuptools'
        # default install machinery was overridden), not a lexical guess — worth
        # a medium heads-up regardless of what the override's body contains.
        sev, conf = "medium", "medium"
    else:
        return out
    out.append(mk(
        ctx, detector_id="supply-chain", category="supply-chain",
        evidence_location="install-time-script", severity=sev, confidence=conf,
        detection_method="setup-py-scan",
        rationale=("setup.py runs command/network/exec logic at build/install time — "
                   "code that executes before the server launches, outside any "
                   "sandbox."),
        evidence={"manifest": path,
                  "match": (m.group(0) if m else "custom install command class")[:120]},
        source_kind="static-code", tool_name=None,
        raw={"dangerous_shape": dangerous_shape},
    ))
    # install_requires typosquat
    reqs = re.findall(r"['\"]([A-Za-z0-9_.\-]+)(?:[<>=!~ ].*)?['\"]", text)
    out.extend(_typosquat(ctx, path, reqs, POPULAR_PYPI))
    return out


def _read_backend_text(ctx: ScanContext, cand: str) -> Optional[str]:
    """Text of a backend module candidate: from the source the target loader
    already collected, else (local directory scan only) a direct read. Never
    executes it."""
    norm = os.path.normpath(cand)
    for sf in (getattr(getattr(ctx, "target", None), "source_files", None) or []):
        if os.path.normpath(sf.path) == norm:
            return sf.text
    if os.path.isfile(norm):
        try:
            with open(norm, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(200_000)
        except OSError:
            return None
    return None


def _analyze_local_backend(ctx: ScanContext, manifest_path: str, text: str
                           ) -> Optional[Tuple[str, BackendFacts, List[str]]]:
    """v6-W5 -- locate the in-tree PEP 517 backend named by ``build-backend``
    / ``backend-path`` and analyze its source (plus the same-directory modules
    it imports, two hops, cycle-safe). Returns ``(backend_module_path, facts,
    modules_analyzed)`` or ``None`` when no local backend module can be read."""
    bs = parse_build_system(text)
    backend, bpath = bs.get("backend"), bs.get("backend_path") or []
    if not backend or not bpath:
        return None
    mdir = os.path.dirname(manifest_path)
    entry_path, entry_text = None, None
    for cand in backend_module_candidates(mdir, str(backend), list(bpath)):
        t = _read_backend_text(ctx, cand)
        if t is not None:
            entry_path, entry_text = os.path.normpath(cand), t
            break
    if entry_path is None or entry_text is None:
        return None
    facts = BackendFacts()
    analyzed: List[str] = []
    seen = set()
    from ..analysis.crossmodule import LocalModuleIndex
    sources = list(getattr(getattr(ctx, "target", None), "source_files", None) or [])
    index = LocalModuleIndex(sources)

    def visit(path: str, body: str, hops: int) -> None:
        if path in seen or len(analyzed) >= 8:
            return
        seen.add(path)
        analyzed.append(path)
        facts.merge(analyze_backend_source(body), os.path.relpath(path, mdir) if mdir else path)
        if hops >= 2:
            return
        mi = index.info(path)
        if mi is None:
            return
        index.resolve_imports(mi)
        nxt = [t for t in mi.module_aliases.values()] + [t for t, _ in mi.name_imports.values()]
        for t in nxt:
            if t.path not in seen:
                visit(t.path, t.text, hops + 1)

    visit(entry_path, entry_text, 0)
    return entry_path, facts, analyzed


def _grade_backend(facts: BackendFacts) -> Optional[Dict[str, Any]]:
    """Graded outcome for a local backend's facts, or ``None`` (build-only).
    Credential read, network+exec and decode+exec are self-proving shapes
    (``dangerous_shape`` -> high/high); a bare network call is high/medium (an
    installer has no inherent need to reach the network -- the setup.py
    precedent); a bare exec sink is medium/medium."""
    if facts.credentials:
        return {"severity": "high", "confidence": "high", "dangerous_shape": True,
                "reason": "reads a credential-shaped path"}
    if facts.obfuscation:
        return {"severity": "high", "confidence": "high", "dangerous_shape": True,
                "reason": "decodes content in a module that reaches an exec sink"}
    if facts.network and facts.exec:
        return {"severity": "high", "confidence": "high", "dangerous_shape": True,
                "reason": "makes a network call and reaches an exec sink"}
    if facts.network:
        return {"severity": "high", "confidence": "medium", "dangerous_shape": False,
                "reason": "makes a network call at build time"}
    if facts.exec:
        return {"severity": "medium", "confidence": "medium", "dangerous_shape": False,
                "reason": "reaches an exec sink (eval/exec/os.system/shell subprocess)"}
    return None


def _scan_pyproject(ctx: ScanContext, path: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    if re.search(r"backend-path", text):
        out.append(mk(
            ctx, detector_id="supply-chain", category="supply-chain",
            evidence_location="install-time-script", severity="low", confidence="low",
            detection_method="pyproject-scan",
            rationale=("pyproject declares a local in-tree build backend "
                       "(backend-path) — build-time code runs from the repo before "
                       "launch; verify it is benign."),
            evidence={"manifest": path},
            source_kind="static-code", tool_name=None,
        ))
        # v6-W5 -- the local backend module IS an install-time script: read
        # its source and grade what it does, instead of stopping at the note.
        res = _analyze_local_backend(ctx, path, text)
        if res is not None:
            backend_path, facts, analyzed = res
            graded = _grade_backend(facts)
            if graded is not None:
                def _first(items):
                    return [{"module": r.get("module"), "line": r.get("line"),
                             "code": r.get("code", "")[:140]} for r in items[:3]]
                out.append(mk(
                    ctx, detector_id="supply-chain", category="supply-chain",
                    evidence_location="install-time-script",
                    severity=graded["severity"], confidence=graded["confidence"],
                    detection_method="pyproject-backend-scan",
                    rationale=("pyproject's in-tree build backend "
                               f"('{os.path.basename(backend_path)}') runs at install "
                               "time, before the server launches and outside any tool "
                               f"sandbox, and its own source {graded['reason']}."),
                    evidence={"manifest": path, "backend_module": backend_path,
                              "modules_analyzed": analyzed,
                              "credentials": _first(facts.credentials),
                              "network": _first(facts.network),
                              "exec": _first(facts.exec),
                              "obfuscation": _first(facts.obfuscation),
                              "hook": "build-backend"},
                    source_kind="static-code", tool_name=None,
                    raw={"dangerous_shape": graded["dangerous_shape"]},
                ))
    deps = re.findall(r"['\"]([A-Za-z0-9_.\-]+)(?:[<>=!~ ].*)?['\"]", text)
    out.extend(_typosquat(ctx, path, deps, POPULAR_PYPI))
    return out


def _typosquat(ctx: ScanContext, path: str, names: List[str], popular) -> List[Finding]:
    out: List[Finding] = []
    for name in sorted(set(names)):
        n = name.lower().split("/")[-1]
        if not n or n in popular:
            continue
        for pop in popular:
            d = damerau_levenshtein(n, pop)  # rule 4.3 — transposition-aware
            if 0 < d <= 1 and len(n) >= 4:
                out.append(mk(
                    ctx, detector_id="supply-chain", category="supply-chain",
                    evidence_location="install-time-script", severity="medium",
                    confidence="low", detection_method="typosquat-editdistance",
                    rationale=(f"Dependency '{name}' is edit-distance {d} from the "
                               f"popular package '{pop}' — a typosquat-shaped name "
                               "that can pull a malicious lookalike."),
                    evidence={"dependency": name, "near": pop, "distance": d,
                              "manifest": path},
                    source_kind="static-code", tool_name=None,
                ))
                break
    return out


register(Detector(
    id="supply-chain", category="supply-chain", evidence_location="install-time-script",
    phase="tool listing", run=_run, requires={CAP_PACKAGE},
    rationale=("Install/build hooks and dependency resolution execute before the "
               "server runs, so they are outside the tool sandbox and invisible to "
               "runtime scanners; parsing manifests statically catches them, scaled "
               "by how clearly the command reaches for the network/exec/obfuscation."),
))
