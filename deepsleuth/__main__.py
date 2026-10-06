"""CLI entry point.

    python -m deepsleuth scan       <target> [--no-dynamic] [--json out] [--timeout N]
    python -m deepsleuth proxy      <target> [--policy p] [--fail-closed] [--log run.jsonl]
    python -m deepsleuth proxy-eval <target> [--json out] [--timeout N] [--policy p]
    python -m deepsleuth mcp        (or no arguments at all)

``scan`` exits 0 when clean and non-zero when a finding reaches ``--fail-severity``
(default ``high``). Both frontends emit the identical rule 6 finding shape.

BARE invocation starts the MCP stdio server (the same loop as
``python -m deepsleuth.mcp_server``): registry clients install the PyPI
package and run it with no arguments, and the server IS the product.
"""
from __future__ import annotations

import argparse
import sys
from typing import List

from .gate import Policy
from .models import SEVERITY_RANK, Finding, findings_to_json
from .reporter import human_summary, write_json
from .runner import registry_summary
from .target_loader import load_targets


def _emit(findings: List[Finding], out_path, to_stderr_summary, skipped=None,
          run_log=None) -> None:
    js = findings_to_json(findings)
    if out_path:
        write_json(findings, out_path)
    else:
        print(js)
    if to_stderr_summary:
        print(human_summary(findings, skipped=skipped), file=sys.stderr)


_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def _exit_code(findings: List[Finding], fail_severity: str) -> int:
    """The exit code, like the gate, honours confidence — a
    low-confidence finding must not fail a CI run on severity alone (the gate
    reads severity+confidence together per ARCHITECTURE.md; the CLI exit code
    is the same enforcement surface for the batch frontend and must agree)."""
    threshold = SEVERITY_RANK[fail_severity]
    worst = 0
    for f in findings:
        if _CONF_RANK.get(f.confidence, 0) < _CONF_RANK["medium"]:
            continue
        worst = max(worst, SEVERITY_RANK[f.severity])
    return 2 if worst >= threshold else 0


def cmd_scan(args) -> int:
    targets = load_targets(args.target)
    if not targets:
        print(f"no target loaded from {args.target!r}", file=sys.stderr)
        return 1
    from .scanner import scan
    findings, ctxs = scan(targets, do_dynamic=not args.no_dynamic,
                          timeout=args.timeout,
                          allow_unsandboxed=args.allow_unsandboxed,
                          reference_listing=getattr(args, "reference_listing", None))
    skipped: List[str] = []
    for c in ctxs:
        skipped.extend(c.skipped)
    _emit(findings, args.json, to_stderr_summary=not args.quiet, skipped=skipped)
    return _exit_code(findings, args.fail_severity)


def cmd_proxy_eval(args) -> int:
    targets = load_targets(args.target)
    if not targets:
        print(f"no target loaded from {args.target!r}", file=sys.stderr)
        return 1
    from .proxy import run_proxy_eval
    policy = Policy.load(args.policy) if args.policy else Policy.default()
    if args.fail_closed:
        policy.fail_closed = True
    all_findings: List[Finding] = []
    skipped: List[str] = []
    for t in targets:
        findings, ctx, _log = run_proxy_eval(
            t, timeout=args.timeout, allow_unsandboxed=args.allow_unsandboxed,
            policy=policy)
        all_findings.extend(findings)
        skipped.extend(ctx.skipped)
    _emit(all_findings, args.json, to_stderr_summary=not args.quiet, skipped=skipped)
    return _exit_code(all_findings, args.fail_severity)


def cmd_proxy(args) -> int:
    targets = load_targets(args.target)
    if not targets:
        print(f"no target loaded from {args.target!r}", file=sys.stderr)
        return 1
    if len(targets) > 1:
        print("proxy fronts exactly one downstream server (v1); using the first.",
              file=sys.stderr)
    from .proxy import InlineProxy
    policy = Policy.load(args.policy) if args.policy else Policy.default()
    proxy = InlineProxy(targets[0], policy, fail_closed=args.fail_closed,
                        log_path=args.log, sandbox_downstream=args.sandbox_downstream,
                        timeout=args.timeout)
    return proxy.run()


def cmd_detectors(_args) -> int:
    import json
    print(json.dumps(registry_summary(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="deepsleuth",
                                description="Deterministic deep-visibility MCP "
                                            "security scanner (no LLM).")
    sub = p.add_subparsers(dest="cmd", required=False)

    s = sub.add_parser("scan", help="Frontend B — batch/sandbox scanner")
    s.add_argument("target", help="server dir, mcp.json, or launch command")
    s.add_argument("--no-dynamic", action="store_true",
                   help="static-only (skip sandbox execution)")
    s.add_argument("--json", help="write findings JSON here (default: stdout)")
    s.add_argument("--timeout", type=int, default=30)
    s.add_argument("--fail-severity", default="high",
                   choices=["low", "medium", "high", "critical"])
    s.add_argument("--allow-unsandboxed", action="store_true",
                   help="run WITHOUT Docker (trusted self-authored fixtures only)")
    s.add_argument("--reference-listing", metavar="JSON",
                   help="a tool list (JSON array of {name, description, inputSchema}, "
                        "or an object with a 'tools' key) to run the cross-server "
                        "name comparison against without launching a second server")
    s.add_argument("--quiet", action="store_true", help="no stderr summary")
    s.set_defaults(func=cmd_scan)

    pe = sub.add_parser("proxy-eval",
                        help="Frontend A headless — drive a call plan through the gate")
    pe.add_argument("target")
    pe.add_argument("--json")
    pe.add_argument("--timeout", type=int, default=30)
    pe.add_argument("--policy")
    pe.add_argument("--fail-closed", action="store_true")
    pe.add_argument("--fail-severity", default="high",
                    choices=["low", "medium", "high", "critical"])
    pe.add_argument("--allow-unsandboxed", action="store_true",
                    help="run WITHOUT Docker (trusted self-authored fixtures only)")
    pe.add_argument("--quiet", action="store_true")
    pe.set_defaults(func=cmd_proxy_eval)

    px = sub.add_parser("proxy", help="Frontend A — inline MCP gateway (stdio)")
    px.add_argument("target", help="downstream mcp.json or launch command")
    px.add_argument("--policy")
    px.add_argument("--fail-closed", action="store_true")
    px.add_argument("--log", help="append gate decisions as JSONL here")
    px.add_argument("--timeout", type=int, default=30)
    px.add_argument("--sandbox-downstream", action="store_true",
                    help="launch the downstream inside the Docker sandbox "
                         "(default: launch directly — it is the trusted endpoint)")
    px.set_defaults(func=cmd_proxy)

    d = sub.add_parser("detectors", help="list the registered detectors")
    d.set_defaults(func=cmd_detectors)
    m = sub.add_parser("mcp", help="run deepsleuth itself as an MCP server (stdio)")
    m.set_defaults(func=cmd_mcp)
    return p


def cmd_mcp(_args) -> int:
    """Run deepsleuth itself as an MCP stdio server (the same loop as
    ``python -m deepsleuth.mcp_server``)."""
    from .mcp_server import serve
    return serve()


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd is None:
        # bare invocation (``uvx deepsleuth``, the registry's default pypi
        # runtime) starts the server, not a usage error
        return cmd_mcp(args)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
