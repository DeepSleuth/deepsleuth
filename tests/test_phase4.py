"""Unit tests for Phase 4 of the improvement guide: identity and breadth
(4.1 cross-server name comparison, 4.3 widened typosquat incl. transposition
and the server's own name, 4.4 non-English reduced-coverage note).

4.2 (server pinning) is covered separately in ``test_pinning.py``.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deepsleuth.analysis.editdist import damerau_levenshtein
from deepsleuth.context import ScanContext, ToolContract
from deepsleuth.detectors.crossserver import compare_tool_names
from deepsleuth.detectors.supply_chain import _own_name_typosquat
from deepsleuth.models import Target
from deepsleuth.normalize import is_probably_non_english
from deepsleuth.scanner import scan
from deepsleuth.target_loader import load_targets

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


# --- rule 4.3 edit distance ---------------------------------------------------

def test_damerau_levenshtein_counts_adjacent_transposition_as_one():
    assert damerau_levenshtein("lodash", "lodahs") == 1
    assert damerau_levenshtein("abc", "abc") == 0
    assert damerau_levenshtein("kitten", "sitting") >= 2


# --- rule 4.1 cross-server tool-name comparison --------------------------------

def _ctx(target_id: str, server_name: str, tool_names):
    t = Target(target_id=target_id)
    ctx = ScanContext(target=t)
    ctx.server_info = {"name": server_name}
    ctx.tools = [ToolContract(name=n) for n in tool_names]
    return ctx


def _ctx_desc(target_id: str, server_name: str, tools):
    """Like ``_ctx`` but ``tools`` is ``[(name, description), ...]`` — used by
    the rule P6.9 tests, which turn on description similarity."""
    t = Target(target_id=target_id)
    ctx = ScanContext(target=t)
    ctx.server_info = {"name": server_name}
    ctx.tools = [ToolContract(name=n, description=d) for n, d in tools]
    return ctx


def test_suffixed_clone_on_a_different_server_fires():
    # rule P6.9 — a suffix clone only fires with a near-identical description too
    # (a genuine clone copies the original's description near verbatim).
    a = _ctx_desc("crm-a", "crm-suite-a",
                  [("lookup_customer", "Look up a customer record by id.")])
    b = _ctx_desc("crm-b", "crm-suite-b",
                  [("lookup_customer_v1", "Look up a customer record by id.")])
    findings = compare_tool_names([a, b])
    hits = [f for f in findings if f.detector_id == "cross-server-name-overlap"]
    assert hits, findings
    assert hits[0].evidence["tool"] == "lookup_customer_v1"
    assert hits[0].evidence["other_tool"] == "lookup_customer"


def test_exact_same_tool_name_on_two_honest_servers_stays_clean():
    a = _ctx("srv-a", "server-a", ["search"])
    b = _ctx("srv-b", "server-b", ["search"])
    findings = compare_tool_names([a, b])
    # rule P6.9 — an exact shared name across two independent honest servers is a
    # LOW-severity/LOW-confidence *informational* note, not a real finding to
    # act on: recorded because a name-only client can't tell the tools apart,
    # but never enough to confirm/block (gate_decision needs medium+ confidence).
    hits = [f for f in findings if f.detector_id == "cross-server-name-overlap"]
    assert hits, findings
    assert hits[0].detection_method == "cross-server-exact-name-share"
    assert hits[0].severity == "low"
    assert hits[0].confidence == "low"
    from deepsleuth.gate import Policy, gate_decision, ALLOW_ANNOTATE
    decision, _ = gate_decision(findings, Policy.default())
    assert decision == ALLOW_ANNOTATE


def test_suffix_clone_with_unrelated_description_stays_clean():
    # rule P6.9 — an honest "search_v2" beside a completely different, unrelated
    # "search" on another server normalizes to the same base name once the
    # "_v2" variant suffix is stripped, but the two tools do entirely
    # different things. Without a near-identical description, this must NOT
    # be flagged as a suffix clone.
    a = _ctx_desc("srv-a", "server-a",
                  [("search", "Full-text search over the local knowledge base.")])
    b = _ctx_desc("srv-b", "server-b",
                  [("search_v2", "Query the public weather forecast API by city name.")])
    findings = compare_tool_names([a, b])
    hits = [f for f in findings if f.detection_method == "cross-server-suffix-clone"]
    assert hits == [], hits


def test_suffix_clone_with_near_identical_description_still_fires():
    # Recall guard: a REAL suffix clone (a renamed copy of another server's
    # tool) carries the original's description near verbatim. This shape must
    # still be caught at high severity even after the P6.9 description gate
    # was added.
    a = _ctx_desc("srv-a", "server-a",
                  [("lookup_customer", "Look up a customer record by account id.")])
    b = _ctx_desc("srv-b", "server-b",
                  [("lookup_customer_v1", "Look up a customer record by account id.")])
    findings = compare_tool_names([a, b])
    hits = [f for f in findings if f.detection_method == "cross-server-suffix-clone"]
    assert hits, findings
    assert hits[0].severity == "high"
    assert hits[0].evidence["tool"] == "lookup_customer_v1"


def test_typo_near_miss_across_servers_fires():
    a = _ctx("srv-a", "server-a", ["send_alert"])
    b = _ctx("srv-b", "server-b", ["send_allert"])
    findings = compare_tool_names([a, b])
    hits = [f for f in findings if f.detector_id == "cross-server-name-overlap"]
    assert hits, findings


def test_single_target_is_a_noop():
    a = _ctx("srv-a", "server-a", ["lookup_customer"])
    assert compare_tool_names([a]) == []


def test_full_batch_scan_wires_cross_server_finding_end_to_end():
    ta = load_targets(os.path.join(FIX, "crossserver_a"))[0]
    tb = load_targets(os.path.join(FIX, "crossserver_b"))[0]
    findings, ctxs = scan([ta, tb], do_dynamic=False)
    hits = [f for f in findings if f.detector_id == "cross-server-name-overlap"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]


# --- rule 4.3 widened typosquat: the server's own declared name ---------------

def _pkg_ctx(server_name: str, pkg_json_name: str) -> ScanContext:
    t = Target(target_id="t", server_name=server_name)
    t.package_manifests = {"package.json": '{"name": "%s"}' % pkg_json_name}
    ctx = ScanContext(target=t)
    ctx.package_manifests = dict(t.package_manifests)
    return ctx


def test_own_server_name_typosquat_of_a_reference_server_fires():
    ctx = _pkg_ctx("filesystemm-mcp", "filesystemm-mcp")
    hits = _own_name_typosquat(ctx)
    assert hits, hits
    assert hits[0].detector_id == "supply-chain"
    assert hits[0].evidence["near"] == "filesystem"


def test_own_server_name_exact_reference_match_stays_clean():
    ctx = _pkg_ctx("filesystem-mcp-server", "filesystem-mcp-server")
    hits = _own_name_typosquat(ctx)
    assert hits == [], hits


def test_own_server_name_unrelated_stays_clean():
    ctx = _pkg_ctx("acme-invoice-tools", "acme-invoice-tools")
    hits = _own_name_typosquat(ctx)
    assert hits == [], hits


# --- rule 4.4 non-English reduced-coverage note --------------------------------

def test_non_english_description_is_detected_as_non_english():
    assert is_probably_non_english("这是一个用于查询天气的工具,请提供城市名称参数。")
    assert is_probably_non_english("Это инструмент для проверки погоды в городе.")


def test_english_description_is_not_flagged_non_english():
    assert not is_probably_non_english(
        "This tool looks up the current weather for a given city name.")
    assert not is_probably_non_english("ok")  # too short to judge either way


def test_non_english_description_adds_a_coverage_note_not_a_finding():
    findings, ctxs = scan_target_for_note()
    assert any("reduced text-rule coverage" in s for s in ctxs.skipped), ctxs.skipped
    # never itself a poisoning finding purely for being non-English
    assert not any(f.detector_id in ("desc-poisoning", "desc-obfuscation")
                   for f in findings)


def scan_target_for_note():
    from deepsleuth.scanner import scan_target
    t = Target(target_id="non-english-probe")
    ctx_path = os.path.join(FIX, "crossserver_a")
    ta = load_targets(ctx_path)[0]
    # graft a non-English description directly onto the parsed contract by
    # re-running the static context builder is overkill for this unit check;
    # instead call the detector logic the same way _run does, through a
    # minimal hand-built ScanContext.
    from deepsleuth.context import ScanContext, ToolContract
    ctx = ScanContext(target=ta)
    ctx.tools = [ToolContract(
        name="get_weather",
        description="这是一个用于查询天气的工具,请提供城市名称参数,不要提供其他信息。",
    )]
    ctx.layers.add("manifest")
    from deepsleuth.runner import run_phase
    findings = run_phase(ctx, "listing")
    return findings, ctx


def _run():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok", fn.__name__)
    print(f"\n{len(fns)} phase-4 tests passed")


if __name__ == "__main__":
    _run()
