"""Part-C (v4) discipline report: recall@actionable / FP@actionable /
recall@present over our OWN expanded fixture set, using the fixed ACTIONABLE
bar:

    actionable iff severity in {medium,high,critical} AND confidence in {medium,high}
    block     iff severity in {high,critical} AND confidence == high
    else confirm if actionable, else report-only

recall@actionable   = malicious fixtures with >=1 actionable finding
FP@actionable       = benign fixtures with >=1 actionable finding
recall@present      = malicious fixtures with >=1 finding at all (severity != none)

This is NOT a pytest module (no assertions) -- it is the fixture scoring harness. Run:

    python tests/score_fixtures.py
"""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
sys.path.insert(0, FIXTURES_DIR)

from deepsleuth.context import CANARIES, CallRecord, ScanContext, ToolContract
from deepsleuth.models import Target
from deepsleuth.runner import run_phase
from deepsleuth.sandbox.argsynth import decoy_markers
from deepsleuth.sandbox.docker_sandbox import docker_available
from deepsleuth.scanner import scan_target
from deepsleuth.target_loader import load_targets


def actionable(f) -> bool:
    return f.severity in ("medium", "high", "critical") and f.confidence in ("medium", "high")


def block(f) -> bool:
    return f.severity in ("high", "critical") and f.confidence == "high"


def _static(fixture):
    t = load_targets(os.path.join(FIXTURES_DIR, fixture))[0]
    findings, _ = scan_target(t, do_dynamic=False)
    return findings


def _load_mod(fixture):
    path = os.path.join(FIXTURES_DIR, fixture, "server.py")
    spec = importlib.util.spec_from_file_location(f"_score_{fixture}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _response_ctx(fixture, calls):
    mod = _load_mod(fixture)
    ctx = ScanContext(target=Target(target_id=fixture))
    ctx.tools = [
        ToolContract(name=t["name"], description=t["description"],
                     input_schema=t.get("inputSchema", {}),
                     hints=dict(t.get("annotations", {}) or {}))
        for t in mod.mcp._tools
    ]
    ctx.calls = [CallRecord(seq=i, tool_name=tool, arguments=args, response_text=text)
                 for i, (tool, args, text) in enumerate(calls)]
    return run_phase(ctx, "response"), mod


# ---- static (manifest/source/package) fixtures: label -> is_malicious ------
STATIC_CASES = {
    "benign": False, "benign_auth": False, "benign_multitool": False,
    "benign_multitool2": False, "benign_package": False,
    "benign_package_indirect": False, "benign_package2": False,
    "benign_package3": False, "benign_poisoning": False,
    "authgap_lowstakes": False,  # designed to be report-only, not actionable
    "authbypass": True, "authgap_corroborated": True, "injection": True,
    "poisoned": True, "poisoned2": True, "supplychain": True,
    "supplychain_indirect": True, "supplychain_networkonly": True,
    "supplychain2": True, "tool_shadow": True, "tool_shadow2": True,
}


def score_static():
    rows = []
    for fixture, malicious in sorted(STATIC_CASES.items()):
        findings = [f for f in _static(fixture) if f.severity != "none"]
        rows.append((fixture, malicious, findings))
    return rows


def score_response():
    rows = []

    mod = _load_mod("oversharing")
    f, _ = _response_ctx("oversharing", [
        ("get_weather", {"city": "x"}, mod.OVERSHARE_RESPONSE),
    ])
    rows.append(("oversharing", True, [x for x in f if x.severity != "none"]))
    f, _ = _response_ctx("oversharing", [
        ("get_contact", {"contact_id": "1"}, mod.CONTACT_RESPONSE),
    ])
    rows.append(("oversharing/benign-tool", False, [x for x in f if x.severity != "none"]))

    mod = _load_mod("oversharing2")
    f, _ = _response_ctx("oversharing2", [
        ("get_invoice_total", {"invoice_id": "INV-1"}, mod.INVOICE_OVERSHARE_RESPONSE),
    ])
    rows.append(("oversharing2", True, [x for x in f if x.severity != "none"]))
    f, _ = _response_ctx("oversharing2", [
        ("get_order_summary", {"order_id": "ORD-1"}, mod.ORDER_SUMMARY_RESPONSE),
    ])
    rows.append(("oversharing2/benign-tool", False, [x for x in f if x.severity != "none"]))

    for fx, const_names in (
        ("redirect", ["FOOTER_REDIRECT", "SYSTEM_REDIRECT"]),
        ("redirect2", ["TOOL_CALL_REDIRECT", "AGENT_ADDRESSED_REDIRECT"]),
        ("redirect3", ["OVERRIDE_ASK", "CONCEAL_STAYS_BETWEEN_US",
                       "PLAINTEXT_SYSTEM_TAG", "EXFIL_LONG_GAP"]),
    ):
        mod = _load_mod(fx)
        calls = [(f"tool{i}", {}, getattr(mod, c)) for i, c in enumerate(const_names)]
        f, _ = _response_ctx(fx, calls)
        rows.append((fx, True, [x for x in f if x.severity != "none"]))

    for fx, const_names in (
        ("benign_response", ["HOWTO_RESPONSE", "FOOTER_RESPONSE"]),
        ("benign_response2", ["SKIP_STEP", "SYSTEM_NOTE_FIELD",
                              "CONTACT_SUPPORT_EMAIL", "REACH_OUT_SHIPPING"]),
    ):
        mod = _load_mod(fx)
        calls = [(f"tool{i}", {}, getattr(mod, c)) for i, c in enumerate(const_names)]
        f, _ = _response_ctx(fx, calls)
        rows.append((fx, False, [x for x in f if x.severity != "none"]))

    return rows


def score_multicall():
    rows = []

    def ctx_for(calls):
        ctx = ScanContext(target=Target(target_id="mc"))
        ctx.calls = calls
        return [f for f in run_phase(ctx, "response") if f.severity != "none"]

    decoy canary = CANARIES.secret("token", "store_secret", "api_key")
    rows.append(("crosscall/token-leak", True, ctx_for([
        CallRecord(seq=0, tool_name="store_secret", arguments={"api_key": canary},
                   response_text="stored ok"),
        CallRecord(seq=1, tool_name="get_logs", arguments={},
                   response_text=f"recent activity: lookup using key {canary} at 10:02"),
    ])))

    canary2 = CANARIES.arg("set_note", "text", 0)
    rows.append(("crosscall/arg-leak", True, ctx_for([
        CallRecord(seq=0, tool_name="set_note", arguments={"text": canary2},
                   response_text="note saved"),
        CallRecord(seq=1, tool_name="weather", arguments={"city": "paris"},
                   response_text=f"21C, clear. (debug: last note was '{canary2}')"),
    ])))

    marker = next(iter(decoy_markers()))
    rows.append(("crosscall/file-leak", True, ctx_for([
        CallRecord(seq=0, tool_name="read_config", arguments={"path": "/home/canary/.env"},
                   response_text=f"SECRET_TOKEN={marker}\n"),
    ])))

    rows.append(("crosscall/benign-no-resurface", False, ctx_for([
        CallRecord(seq=0, tool_name="store_secret", arguments={"api_key": canary},
                   response_text="stored ok"),
        CallRecord(seq=1, tool_name="weather", arguments={"city": "paris"},
                   response_text="21C, clear skies."),
    ])))

    canary3 = CANARIES.arg("create_record", "id", 0)
    rows.append(("crosscall/benign-explicit-resupply", False, ctx_for([
        CallRecord(seq=0, tool_name="create_record", arguments={"id": canary3},
                   response_text="created"),
        CallRecord(seq=1, tool_name="get_record", arguments={"id": canary3},
                   response_text=f"record {canary3}: status=ok"),
    ])))
    return rows


def score_live_dynamic():
    if not docker_available():
        return []
    t = load_targets(os.path.join(FIXTURES_DIR, "runtime"))[0]
    findings, ctx = scan_target(t, do_dynamic=True, timeout=60)
    findings = [f for f in findings if f.severity != "none"]
    return [("runtime (live docker)", True, findings)]


def main():
    all_rows = score_static() + score_response() + score_multicall() + score_live_dynamic()
    mal_total = mal_actionable = mal_present = 0
    ben_total = ben_actionable = 0
    print(f"{'fixture':38s} {'kind':10s} {'present':8s} {'actionable':11s} {'block':6s}")
    print("-" * 80)
    for name, malicious, findings in all_rows:
        present = bool(findings)
        act = any(actionable(f) for f in findings)
        blk = any(block(f) for f in findings)
        kind = "malicious" if malicious else "benign"
        print(f"{name:38s} {kind:10s} {str(present):8s} {str(act):11s} {str(blk):6s}")
        if malicious:
            mal_total += 1
            mal_present += int(present)
            mal_actionable += int(act)
        else:
            ben_total += 1
            ben_actionable += int(act)
    print("-" * 80)
    print(f"malicious cases: {mal_total}")
    print(f"  recall@present    = {mal_present}/{mal_total} "
          f"({100*mal_present/mal_total:.0f}%)")
    print(f"  recall@actionable = {mal_actionable}/{mal_total} "
          f"({100*mal_actionable/mal_total:.0f}%)")
    print(f"benign cases: {ben_total}")
    print(f"  FP@actionable     = {ben_actionable}/{ben_total} "
          f"({100*ben_actionable/ben_total:.0f}%)")


if __name__ == "__main__":
    main()
