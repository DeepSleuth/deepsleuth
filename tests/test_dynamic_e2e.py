"""Live, Docker-backed end-to-end proof of Part-A.1/A.2 (v4): a real server
process, launched for real, called twice through the real MCP stdio protocol,
scanned by the real detector + calibration pipeline -- not a hand-built
``ScanContext``. This is the strongest evidence that the multi-call protocol
actually plants a recognizable canary and scans every later response for it
(Part-A.1), and that response-delivered injection is caught end-to-end
(Part-A.2).

Per the hard constraint ("degrade gracefully: if Docker is unavailable, still
run all static/manifest detectors ... never crash"), this test SKIPS (does not
fail) when Docker is not available in the environment -- it is an additional
proof on top of the Docker-independent tests in ``test_multicall.py`` and
``test_response_detectors.py``, not a replacement for them.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

from deepsleuth.sandbox.docker_sandbox import docker_available
from deepsleuth.scanner import scan_target
from deepsleuth.target_loader import load_targets


def _actionable(f) -> bool:
    return f.severity in ("medium", "high", "critical") and f.confidence in ("medium", "high")


def test_live_dynamic_scan_catches_crosscall_leak_and_response_injection():
    if not docker_available():
        print("SKIP (docker not available in this environment)")
        return
    t = load_targets(os.path.join(FIXTURES_DIR, "runtime"))[0]
    findings, ctx = scan_target(t, do_dynamic=True, timeout=60)
    findings = [f for f in findings if f.severity != "none"]
    assert not any("dynamic layer error" in n for n in ctx.skipped), ctx.skipped
    assert "dynamic" in ctx.layers, ctx.skipped

    leaks = [f for f in findings if f.detector_id == "response-leak"
             and f.category == "data-exfiltration"]
    assert leaks, "expected a live cross-call leak finding"
    assert _actionable(leaks[0])
    assert leaks[0].evidence["surfaced_in_tool"] == "read_status"
    assert leaks[0].evidence["planted_in_tool"] == "save_note"

    inj = [f for f in findings if f.detector_id == "response-injection"]
    assert inj, "expected a live response-injection finding"
    assert _actionable(inj[0])
    assert inj[0].tool_name == "help_topic"


def test_burst_call_plan_trips_a_call_counter_gated_rug_pull():
    """rule P3.1: a 2-pass round-robin plan alone calls ``get_forecast`` once per
    pass, interleaved with ``reset_challenge`` between passes — its counter
    (gated at >=3) would never trip. ``build_call_plan``'s burst phase must
    call every tool several times IN A ROW, with reset-like tools deferred to
    the very end, so the gate actually trips within the burst and the
    poisoned response is caught live."""
    if not docker_available():
        print("SKIP (docker not available in this environment)")
        return
    t = load_targets(os.path.join(FIXTURES_DIR, "rugpull_burst"))[0]
    findings, ctx = scan_target(t, do_dynamic=True, timeout=60)
    findings = [f for f in findings if f.severity != "none"]
    assert not any("dynamic layer error" in n for n in ctx.skipped), ctx.skipped
    assert "dynamic" in ctx.layers, ctx.skipped

    inj = [f for f in findings if f.detector_id == "response-injection"
           and f.tool_name == "get_forecast"]
    assert inj, ("expected the burst-triggered rug pull to surface as a live "
                 "response-injection finding; findings were: "
                 f"{[(f.detector_id, f.tool_name) for f in findings]}")
    assert _actionable(inj[0])


def _run():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok", fn.__name__)
    print(f"\n{len(fns)} dynamic e2e tests passed")


if __name__ == "__main__":
    _run()
