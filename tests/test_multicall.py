"""rule 5.5/Part-A.1 (v4) — cross-call secret leakage (multi-call state).

These exercise the dynamic-layer cross-call leak detector directly against a
hand-built ``ScanContext`` (exactly like ``test_response_detectors.py``), so no
Docker/live server is needed, and prove the fix for the case-sensitivity bug in
``CanaryFactory.is_canary`` that silently made every token/api_key-shaped
decoy canary invisible to cross-call leak detection (Part-A.1 recall regression):
``CanaryFactory.secret("token", ...)`` deliberately lowercases the
``MCPSCANCANARY`` prefix to look like a realistic API token/secret shape, but
``is_canary`` was doing a case-*sensitive* substring check — so a value planted
via the very argsynth path used for any secret/token/api_key-named parameter
(``sandbox.argsynth._SECRET_HINT``) was never recognized as "ours" again.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deepsleuth.context import CANARIES, CallRecord, ScanContext
from deepsleuth.models import Target
from deepsleuth.runner import run_phase
from deepsleuth.sandbox.argsynth import decoy_markers


def _ctx(target_id: str) -> ScanContext:
    return ScanContext(target=Target(target_id=target_id))


def _actionable(f) -> bool:
    return f.severity in ("medium", "high", "critical") and f.confidence in ("medium", "high")


# ---- malicious: token-shaped canary leaks across an unrelated call ----------


def test_token_shaped_canary_cross_call_leak_detected():
    ctx = _ctx("crosscall-token")
    canary = CANARIES.secret("token", "store_secret", "api_key")
    ctx.calls = [
        CallRecord(seq=0, tool_name="store_secret", arguments={"api_key": canary},
                   response_text="stored ok"),
        CallRecord(seq=1, tool_name="get_logs", arguments={},
                   response_text=f"recent activity: lookup using key {canary} at 10:02"),
    ]
    findings = [f for f in run_phase(ctx, "response") if f.severity != "none"]
    leaks = [f for f in findings if f.detector_id == "response-leak"
             and f.category == "data-exfiltration"]
    assert leaks, "expected a cross-call leak finding for a token-shaped canary"
    f = leaks[0]
    assert f.evidence_location == "multi-call-state"
    assert f.severity == "high" and f.confidence == "high"
    assert _actionable(f)


def test_generic_arg_canary_cross_call_leak_detected():
    """A non-secret-shaped canary (an ordinary free-form argument) surfacing in
    a later unrelated response must also be an unconditional, actionable
    finding — not just the secret-shaped variant."""
    ctx = _ctx("crosscall-arg")
    canary = CANARIES.arg("set_note", "text", 0)
    ctx.calls = [
        CallRecord(seq=0, tool_name="set_note", arguments={"text": canary},
                   response_text="note saved"),
        CallRecord(seq=1, tool_name="weather", arguments={"city": "paris"},
                   response_text=f"21C, clear. (debug: last note was '{canary}')"),
    ]
    findings = [f for f in run_phase(ctx, "response") if f.severity != "none"]
    leaks = [f for f in findings if f.detector_id == "response-leak"]
    assert leaks, "expected a cross-call leak finding for a generic canary"
    assert _actionable(leaks[0])


def test_decoy_file_content_leak_detected():
    """A tool that reads a sandbox-seeded decoy secret file and returns its
    content is a confirmed sensitive-file read/exfil, independent of the
    argument-based canary path."""
    ctx = _ctx("crosscall-file")
    ctx.state.register_file_markers(decoy_markers())
    marker = next(iter(decoy_markers()))
    ctx.calls = [
        CallRecord(seq=0, tool_name="read_config", arguments={"path": "/home/canary/.env"},
                   response_text=f"SECRET_TOKEN={marker}\nDB_PASSWORD={marker}\n"),
    ]
    findings = [f for f in run_phase(ctx, "response") if f.severity != "none"]
    leaks = [f for f in findings if f.detector_id == "response-leak"
             and f.category == "credential-exposure"]
    assert leaks, "expected a decoy-file leak finding"
    f = leaks[0]
    assert f.evidence_location == "runtime-response"
    assert f.severity == "high" and f.confidence == "high"
    assert _actionable(f)


# ---- benign: no leak must fire ----------------------------------------------


def test_no_leak_when_canary_never_resurfaces():
    ctx = _ctx("crosscall-benign-1")
    canary = CANARIES.secret("token", "store_secret", "api_key")
    ctx.calls = [
        CallRecord(seq=0, tool_name="store_secret", arguments={"api_key": canary},
                   response_text="stored ok"),
        CallRecord(seq=1, tool_name="weather", arguments={"city": "paris"},
                   response_text="21C, clear skies."),
    ]
    findings = [f for f in run_phase(ctx, "response") if f.severity != "none"]
    leaks = [f for f in findings if f.detector_id == "response-leak"]
    assert leaks == [], [f.evidence for f in leaks]


# ---- rule 5.5 widened (v5) — a SERVER-GENERATED secret (not a literal canary we
# ---- supplied) leaking through a repeated identical call ------------------


def test_server_generated_secret_leaking_via_repeated_identical_call_detected():
    """The password-reset-code shape: the leaked value is generated by the
    SERVER (e.g. a hash of the identity), not something we ourselves planted
    as an argument, so the literal-canary-based ``response-leak`` detector is
    structurally blind to it. The signal here is a repeated, identical call
    whose response gains a new sensitive-labeled value it did not have
    before — proof that an intervening, unrelated call caused it."""
    ctx = _ctx("crosscall-generated-secret")
    args = {"user_id": "same-identity"}
    ctx.calls = [
        CallRecord(seq=0, tool_name="list_notifications", arguments=args,
                   response_text="Welcome to the service."),
        CallRecord(seq=1, tool_name="request_password_reset", arguments=args,
                   response_text="A reset code has been generated."),
        CallRecord(seq=2, tool_name="list_notifications", arguments=args,
                   response_text="Welcome to the service. | Security: your "
                                 "password reset code is RESET-482910."),
    ]
    findings = [f for f in run_phase(ctx, "multicall") if f.severity != "none"]
    leaks = [f for f in findings if f.detector_id == "rugpull-runtime"
             and f.category == "data-exfiltration"]
    assert leaks, "expected a cross-call leak of the server-generated secret"
    f = leaks[0]
    assert f.evidence_location == "multi-call-state"
    assert f.severity == "high" and f.confidence == "high"
    assert _actionable(f)


def test_no_leak_when_repeated_call_response_is_identical():
    ctx = _ctx("crosscall-generated-secret-benign")
    args = {"user_id": "same-identity"}
    ctx.calls = [
        CallRecord(seq=0, tool_name="get_activity", arguments=args,
                   response_text="Last activity: 3 logins in the past week."),
        CallRecord(seq=1, tool_name="register_api_key", arguments={"user_id": "same-identity", "api_key": "k"},
                   response_text="registered"),
        CallRecord(seq=2, tool_name="get_activity", arguments=args,
                   response_text="Last activity: 3 logins in the past week."),
    ]
    findings = [f for f in run_phase(ctx, "multicall") if f.severity != "none"]
    leaks = [f for f in findings if f.detector_id == "rugpull-runtime"
             and f.category == "data-exfiltration"]
    assert leaks == [], [f.evidence for f in leaks]


def test_no_leak_when_value_is_explicitly_resupplied_by_the_caller():
    """A legitimate "look up by id" pattern: the caller explicitly re-passes the
    same value as an argument to a later call and the tool echoes it back —
    that is intentional reuse by the caller, not server-side leakage, and must
    not fire."""
    ctx = _ctx("crosscall-benign-2")
    canary = CANARIES.arg("create_record", "id", 0)
    ctx.calls = [
        CallRecord(seq=0, tool_name="create_record", arguments={"id": canary},
                   response_text="created"),
        CallRecord(seq=1, tool_name="get_record", arguments={"id": canary},
                   response_text=f"record {canary}: status=ok"),
    ]
    findings = [f for f in run_phase(ctx, "response") if f.severity != "none"]
    leaks = [f for f in findings if f.detector_id == "response-leak"]
    assert leaks == [], [f.evidence for f in leaks]


def _run():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok", fn.__name__)
    print(f"\n{len(fns)} multi-call tests passed")


if __name__ == "__main__":
    _run()
