"""Frontend B — batch / sandbox scanner and offline scoring harness (rule 4.1–4.4).

Builds the static Context from a Target, runs the static/source/package detectors,
then (unless disabled or Docker is absent) launches the server in the Docker
sandbox, drives a deterministic call plan through a real MCP client, captures every
response, re-lists tools to diff, and runs the dynamic detectors. Everything feeds
the *same* core detectors used by the proxy.
"""
from __future__ import annotations

import os
import re
import time
from typing import List, Optional, Tuple

from .analysis.pyast import _collect_module_globals, parse_module
from .context import (
    CallRecord,
    ScanContext,
    bind_source_to_listing,
    build_source_facts,
    contract_from_listing,
    contracts_from_source,
)
from .mcpclient import StdioClient
from .models import Finding, Target
from .runner import run_all, run_phase
from .sandbox.argsynth import build_call_plan, decoy_markers, flatten_result
from .sandbox.docker_sandbox import prepare_launch, spawn


def build_static_context(target: Target) -> ScanContext:
    ctx = ScanContext(target=target)
    ctx.package_manifests = dict(target.package_manifests)
    # parse python modules for source-wide detectors
    for sf in target.source_files:
        if sf.language == "python":
            tree = parse_module(sf.text)
            if tree is not None:
                ctx.source_modules.append((sf.path, tree, sf.text,
                                           _collect_module_globals(tree)))
    source_facts = build_source_facts(target.source_files)
    ctx._source_facts = source_facts  # type: ignore[attr-defined]
    # static listing derived from source (used when no live listing available)
    ctx.tools = contracts_from_source(source_facts)
    if ctx.tools:
        ctx.layers.add("manifest")
    if source_facts or ctx.source_modules:
        ctx.layers.add("source")
    if ctx.package_manifests:
        ctx.layers.add("package")
    return ctx


def _run_dynamic(ctx: ScanContext, target: Target, timeout: int,
                 allow_unsandboxed: bool) -> None:
    launch, notes = prepare_launch(target, allow_unsandboxed=allow_unsandboxed,
                                   timeout=timeout)
    ctx.skipped.extend(notes)
    if launch is None:
        return
    ctx.skipped.extend(launch.notes)
    proc = None
    try:
        proc = spawn(launch, target)
        client = StdioClient(proc, timeout=float(timeout))
        init = client.initialize()
        server_info = ((init.get("result") or {}).get("serverInfo")) if isinstance(init, dict) else None
        if server_info:
            ctx.server_info = server_info
        ctx.layers.add("dynamic")

        tools_raw = client.list_tools()
        resources_raw = client.list_resources()
        prompts_raw = client.list_prompts()

        live_tools = [contract_from_listing(t, "tool") for t in tools_raw]
        if live_tools:
            ctx.tools = live_tools  # live listing supersedes source-derived
        ctx.resources = [contract_from_listing(r, "resource") for r in resources_raw]
        ctx.prompts = [contract_from_listing(p, "prompt") for p in prompts_raw]

        # re-bind source facts onto the live contracts (contract-vs-behavior)
        source_facts = getattr(ctx, "_source_facts", {})
        bind_source_to_listing(ctx.all_contracts(), source_facts)

        ctx.state.register_file_markers(decoy_markers())

        # drive the deterministic call plan (2 passes for cross-call + rug-pull)
        # rules 3.2/3.3: source_facts feeds harvested candidate values + widened
        # enum/path variants as a small capped extra tail.
        plan = build_call_plan(tools_raw, passes=2, source_facts=source_facts)
        seq = 0
        for name, args in plan:
            ctx.state.note_call_args(seq, name, args)
            result = client.call_tool(name, args, timeout=float(timeout))
            text, is_err, obj = flatten_result(result)
            if result.get("_timeout"):
                ctx.skipped.append(f"tool '{name}' timed out (possible DoS)")
            ctx.calls.append(CallRecord(seq=seq, tool_name=name, arguments=args,
                                        response_text=text, response_obj=obj,
                                        is_error=is_err))
            seq += 1

        # rule 3.4 — read every resource and prompt; a credential resource
        # sitting right next to the tool listing (MCPSecBench's two
        # credential resources, "listed and never read") is otherwise
        # invisible. Appended to ``ctx.calls`` as synthetic call records so
        # the SAME response rules (injection/leak/oversharing) scan them for
        # free, with no separate detector code needed.
        for r in resources_raw:
            uri = r.get("uri") if isinstance(r, dict) else None
            if not uri:
                continue
            result = client.read_resource(uri, timeout=float(timeout))
            text, is_err, obj = flatten_result(result)
            label = f"resource:{r.get('name') or uri}"
            ctx.calls.append(CallRecord(seq=seq, tool_name=label, arguments={"uri": uri},
                                        response_text=text, response_obj=obj,
                                        is_error=is_err))
            seq += 1
        for p in prompts_raw:
            pname = p.get("name") if isinstance(p, dict) else None
            if not pname:
                continue
            result = client.get_prompt(pname, timeout=float(timeout))
            text, is_err, obj = flatten_result(result)
            ctx.calls.append(CallRecord(seq=seq, tool_name=f"prompt:{pname}", arguments={},
                                        response_text=text, response_obj=obj,
                                        is_error=is_err))
            seq += 1

        # re-list tools and stash for rug-pull diff
        tools_raw2 = client.list_tools()
        ctx.tools_relisted = [contract_from_listing(t, "tool") for t in tools_raw2]

        client.close()
    except Exception as exc:
        ctx.skipped.append(f"dynamic layer error: {type(exc).__name__}: {exc}")
    finally:
        if proc is not None:
            try:
                proc.terminate()
                time.sleep(0.1)
                proc.kill()
            except Exception:
                pass


def scan_target(target: Target, *, do_dynamic: bool = True, timeout: int = 30,
                allow_unsandboxed: bool = False) -> Tuple[List[Finding], ScanContext]:
    ctx = build_static_context(target)
    if target.command and not target.root_dir and not target.source_files:
        # a raw launch command that names no local source: without this note
        # the report would look like a clean bill of health when in fact the
        # static layer had nothing to chew on (first seen on bare ``npx``
        # targets scanned from an unrelated working directory).
        ctx.skipped.append(
            "no local source analyzed for this command target: the launch "
            "command names no local entry script, so only manifest checks "
            "and the dynamic layer apply — point the scanner at the "
            "server's directory (or its unpacked package) to scan source")
    if do_dynamic:
        _run_dynamic(ctx, target, timeout, allow_unsandboxed)
    else:
        ctx.skipped.append("dynamic layer disabled (--no-dynamic): static-only scan")
    findings = run_all(ctx)
    return findings, ctx


# v3-4.1 — a module "declares a server" when it constructs an MCP server
# object at module level (the SDK's own constructor shapes, Python or JS):
# the structural marker of a separate server entry point, as opposed to a
# helper module that merely defines tools for someone else's server.
_SERVER_CTOR_RE = re.compile(
    r"(?m)^\s*\w+\s*=\s*(?:await\s+)?(?:[\w.]+\.)?(?:FastMCP|MCP|Server|McpServer|FastMCPServer)\s*\("
    r"|\bnew\s+(?:[\w.]+\.)?(?:McpServer|Server|FastMCP)\s*\(")


def _server_module_groups(ctx: ScanContext) -> List[ScanContext]:
    """When ONE target directory holds SEVERAL server entry
    modules (each constructs its own server object and registers tools),
    build one pseudo-context per server module so the cross-server pass can
    compare their listings with each other (and with every other target in
    the batch). Empty when the directory holds fewer than two such modules."""
    facts = getattr(ctx, "_source_facts", {}) or {}
    texts = {sf.path: sf.text for sf in ctx.target.source_files}
    by_module: dict = {}
    for name, sfacts in facts.items():
        by_module.setdefault(sfacts.module_path, {})[name] = sfacts
    server_modules = sorted(p for p in by_module if _SERVER_CTOR_RE.search(texts.get(p, "")))
    if len(server_modules) < 2:
        return []
    groups: List[ScanContext] = []
    root = ctx.target.root_dir
    for p in server_modules:
        label = os.path.relpath(p, root) if root and p.startswith(root) else os.path.basename(p)
        sub = ScanContext(target=Target(
            target_id=f"{ctx.target.target_id}:{label}",
            server_name=f"{ctx.target.server_name or ctx.target.target_id}:{label}",
            root_dir=root))
        sub.tools = contracts_from_source(by_module[p])
        sub.layers = {"manifest", "source"}
        groups.append(sub)
    return groups


def scan(targets: List[Target], *, do_dynamic: bool = True, timeout: int = 30,
         allow_unsandboxed: bool = False, reference_listing: Optional[str] = None,
         ) -> Tuple[List[Finding], List[ScanContext]]:
    all_findings: List[Finding] = []
    ctxs: List[ScanContext] = []
    for t in targets:
        f, ctx = scan_target(t, do_dynamic=do_dynamic, timeout=timeout,
                             allow_unsandboxed=allow_unsandboxed)
        all_findings.extend(f)
        ctxs.append(ctx)
    # rule 4.1/v3-4.1 — cross-server tool-name comparison, run whenever the scan
    # can SEE siblings: several entries in one config (several targets),
    # several server modules in one directory (per-module pseudo-contexts),
    # or a ``--reference-listing`` tool list supplied without launching a
    # second server. A no-op when only one listing is visible.
    from .detectors.crossserver import compare_tool_names
    from .runner import dedup
    from .target_loader import load_reference_listing
    compare: List[ScanContext] = []
    for ctx in ctxs:
        groups = _server_module_groups(ctx)
        compare.extend(groups if groups else [ctx])
    if reference_listing:
        ref_ctx = load_reference_listing(reference_listing)
        if ref_ctx is not None:
            compare.append(ref_ctx)
        else:
            for ctx in ctxs:
                ctx.skipped.append(
                    f"reference listing {reference_listing!r} could not be parsed "
                    "(expected a JSON array of tools or an object with a 'tools' key)")
    all_findings.extend(compare_tool_names(compare))
    return dedup(all_findings), ctxs
