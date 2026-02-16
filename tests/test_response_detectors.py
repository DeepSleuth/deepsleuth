"""Response-content detector tests (rules 5.3a/5.5, P1.3/P2.1/P2.2).

These exercise the *dynamic-layer* detectors (response-injection, response-leak,
response-oversharing) directly against a hand-built ``ScanContext`` populated from
the fixtures' own module constants — exactly as ``tests/fixtures/*/server.py``'s
docstrings describe, so no Docker/live server is needed to prove the mechanism.
"""
import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
sys.path.insert(0, FIXTURES_DIR)

from deepsleuth.context import CallRecord, ScanContext, ToolContract
from deepsleuth.models import Target
from deepsleuth.runner import run_phase


def _load(fixture: str):
    path = os.path.join(FIXTURES_DIR, fixture, "server.py")
    spec = importlib.util.spec_from_file_location(f"_fixture_{fixture}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ctx_from_module(fixture: str, mod, calls):
    ctx = ScanContext(target=Target(target_id=fixture))
    ctx.tools = [
        ToolContract(name=t["name"], tool description=t["description"],
                     input_schema=t.get("inputSchema", {}),
                     hints=dict(t.get("annotations", {}) or {}))
        for t in mod.mcp._tools
    ]
    ctx.calls = [
        CallRecord(seq=i, tool_name=tool, arguments=args, response_text=text)
        for i, (tool, args, text) in enumerate(calls)
    ]
    return ctx


def _findings(fixture: str, mod, calls):
    ctx = _ctx_from_module(fixture, mod, calls)
    return [f for f in run_phase(ctx, "response") if f.severity != "none"]


# ---- P1.3 — response-injection must not fire on benign helpful responses ----


def test_benign_response_prose_is_clean():
    mod = _load("benign_response")
    findings = _findings("benign_response", mod, [
        ("how_to_resize", {"topic": "x"}, mod.HOWTO_RESPONSE),
        ("ask", {"question": "x"}, mod.FOOTER_RESPONSE),
    ])
    assert findings == [], [(f.detector_id, f.tool_name, f.evidence) for f in findings]


# ---- P2.1 — smuggled next-action redirect, framing-device independent ------


def test_smuggled_redirect_without_external_destination_detected():
    """V3-1 recall recovery: a next-action redirect that steers the agent
    toward calling a *different tool* with no external URL/email at all (the
    exfiltration family's external-destination marker is absent, so the v2
    decisive-tier alone would miss it) must still fire as prompt-injection —
    "redirect the agent's next action" is decisive on its own, independent of
    an exfiltration-shaped destination."""
    mod = _load("redirect2")
    findings = _findings("redirect2", mod, [
        ("order_status", {"order_id": "4521"}, mod.TOOL_CALL_REDIRECT),
        ("lookup", {"record_id": "1"}, mod.AGENT_ADDRESSED_REDIRECT),
    ])
    by_tool = {f.tool_name for f in findings if f.category == "prompt-injection"}
    assert by_tool == {"order_status", "lookup"}, by_tool
    for f in findings:
        assert f.evidence_location == "runtime-response"
        assert f.severity == "high"


def test_broadened_injection_shapes_detected():
    """Part-A.2 (v4): four shapes the pre-v4 grading missed -- an override
    directive targeting the user's "ask"/"request" (not just "instruction"),
    a "stays between us"/"don't let X know" concealment phrasing, a
    plain-text (no bracket syntax) pseudo-system-tag directive, and an
    exfiltration destination separated from its verb by more than the old
    40-character window -- must all fire as prompt-injection."""
    mod = _load("redirect3")
    findings = _findings("redirect3", mod, [
        ("transfer_status", {"transfer_id": "1"}, mod.OVERRIDE_ASK),
        ("ticket_lookup", {"ticket_id": "1"}, mod.CONCEAL_STAYS_BETWEEN_US),
        ("issue_refund", {"order_id": "1"}, mod.PLAINTEXT_SYSTEM_TAG),
        ("customer_lookup", {"customer_id": "1"}, mod.EXFIL_LONG_GAP),
    ])
    by_tool = {f.tool_name for f in findings if f.category == "prompt-injection"}
    assert by_tool == {"transfer_status", "ticket_lookup", "issue_refund",
                        "customer_lookup"}, by_tool
    for f in findings:
        assert f.evidence_location == "runtime-response"
        assert f.severity == "high" and f.confidence == "high"


def test_broadened_regexes_do_not_misfire_on_benign_support_prose():
    """The benign counterpart to the above: ordinary customer-support/UX text
    that shares surface vocabulary (skip/system note/contact+email/reach out
    to) with the broadened patterns must stay completely clean."""
    mod = _load("benign_response2")
    findings = _findings("benign_response2", mod, [
        ("verify_status", {"account_id": "1"}, mod.SKIP_STEP),
        ("update_profile", {"field": "x", "value": "y"}, mod.SYSTEM_NOTE_FIELD),
        ("account_health", {"account_id": "1"}, mod.CONTACT_SUPPORT_EMAIL),
        ("shipping_status", {"tracking_id": "1"}, mod.REACH_OUT_SHIPPING),
    ])
    assert findings == [], [(f.detector_id, f.tool_name, f.evidence) for f in findings]


def test_smuggled_redirect_detected_regardless_of_framing():
    """Both a footer/'note:'-framed redirect (verb and external destination far
    apart in one long sentence) and a pseudo-system-tag redirect must fire as
    prompt-injection — the mechanism (agent-directed next-step steering toward
    an external/hidden action) is the constant, not the framing device."""
    mod = _load("redirect")
    findings = _findings("redirect", mod, [
        ("ask", {"question": "x"}, mod.FOOTER_REDIRECT),
        ("weather", {"city": "x"}, mod.SYSTEM_REDIRECT),
    ])
    by_tool = {f.tool_name for f in findings if f.category == "prompt-injection"}
    assert by_tool == {"ask", "weather"}, by_tool
    for f in findings:
        assert f.evidence_location == "runtime-response"
        assert f.severity == "high"


# ---- P2.2 — over-sharing vs. declared scope (shape/volume) ------------------


def test_oversharing_shape_detected_and_in_scope_response_is_clean():
    mod = _load("oversharing")
    findings = _findings("oversharing", mod, [
        ("get_weather", {"city": "x"}, mod.OVERSHARE_RESPONSE),
        ("get_contact", {"contact_id": "1"}, mod.CONTACT_RESPONSE),
    ])
    # the benign, in-scope contact card must not fire anything
    assert not any(f.tool_name == "get_contact" for f in findings), findings
    # get_weather promises a single item but returns a bulk unrelated record
    # list plus a credential field — must fire, and must not be mistaken for
    # prompt-injection (the payload is the excess data, not an instruction)
    weather = [f for f in findings if f.tool_name == "get_weather"]
    assert weather, "expected an over-sharing finding for get_weather"
    assert all(f.category != "prompt-injection" for f in weather)
    assert any(f.detector_id == "response-oversharing" for f in weather)
    shape_finding = next(f for f in weather if f.detector_id == "response-oversharing")
    assert shape_finding.evidence_location == "runtime-response"
    assert shape_finding.detection_method == "response-shape-vs-scope"


def test_oversharing_shape_varied_domain_detected_and_in_scope_is_clean():
    """V3-1/V3-3: the over-sharing shape check must generalize past the
    weather/contact example — a billing-domain tool that promises a single
    invoice total but smuggles in the customer's other invoices and a stored
    payment token must fire, while the in-scope order-summary response stays
    clean."""
    mod = _load("oversharing2")
    findings = _findings("oversharing2", mod, [
        ("get_invoice_total", {"invoice_id": "INV-1"}, mod.INVOICE_OVERSHARE_RESPONSE),
        ("get_order_summary", {"order_id": "ORD-1"}, mod.ORDER_SUMMARY_RESPONSE),
    ])
    assert not any(f.tool_name == "get_order_summary" for f in findings), findings
    invoice = [f for f in findings if f.tool_name == "get_invoice_total"]
    assert invoice, "expected an over-sharing finding for get_invoice_total"
    assert any(f.detector_id in ("response-oversharing", "response-leak")
               for f in invoice)


# ---- rule P2.2 widened (v5) — over-sharing in a PLAIN-TEXT/formatted response,
# ---- not just JSON (the overwhelmingly common real shape) ------------------


def _direct_ctx(tool_name, description):
    ctx = ScanContext(target=Target(target_id="oversharing-text"))
    ctx.tools = [ToolContract(name=tool_name, description=description)]
    return ctx


def test_plaintext_labeled_oversharing_detected():
    ctx = _direct_ctx("get_contact_email", "Returns the user's contact email address.")
    ctx.calls = [CallRecord(
        seq=0, tool_name="get_contact_email", arguments={"user_id": "u1"},
        response_text=("Email: j.rivera@example.test. Address: 44 Birchwood Ave. "
                       "Internal customer ID: CUST-88213. Account notes: Flagged "
                       "for late payment; do not extend credit."))]
    findings = [f for f in run_phase(ctx, "response") if f.severity != "none"]
    hits = [f for f in findings if f.detector_id == "response-oversharing"]
    assert hits, "expected plain-text over-sharing finding"
    assert hits[0].severity == "medium" and hits[0].confidence == "medium"


def test_plaintext_in_scope_response_is_clean():
    ctx = _direct_ctx("get_contact_email", "Returns the user's contact email address.")
    ctx.calls = [CallRecord(
        seq=0, tool_name="get_contact_email", arguments={"user_id": "u1"},
        response_text="Email: j.rivera@example.test")]
    findings = [f for f in run_phase(ctx, "response") if f.severity != "none"]
    assert not any(f.detector_id == "response-oversharing" for f in findings), findings


def test_ownership_attributed_email_flagged_but_support_contact_email_is_not():
    ctx = _direct_ctx("get_order_status", "Returns the status of a single order.")
    ctx.calls = [CallRecord(
        seq=0, tool_name="get_order_status", arguments={"order_id": "o1"},
        response_text=("Order o1: shipped. Also showing a related order owned "
                       "by a-different-user@example.test, status processing."))]
    findings = [f for f in run_phase(ctx, "response") if f.severity != "none"]
    assert any(f.detector_id == "response-oversharing" for f in findings), findings

    ctx2 = _direct_ctx("account_health", "Run a basic account health check.")
    ctx2.calls = [CallRecord(
        seq=0, tool_name="account_health", arguments={"account_id": "1"},
        response_text=("No issues found with your account. For security reasons, "
                       "we recommend you contact support@example.com if you "
                       "notice any issues."))]
    findings2 = [f for f in run_phase(ctx2, "response") if f.severity != "none"]
    assert not any(f.detector_id == "response-oversharing" for f in findings2), findings2


def test_footnote_style_note_and_tip_are_not_mistaken_for_data_labels():
    ctx = _direct_ctx("ask", "Answer a general-knowledge question.")
    ctx.calls = [CallRecord(
        seq=0, tool_name="ask", arguments={"question": "x"},
        response_text=("The capital of France is Paris.\n\nNote: results are "
                       "cached for about five minutes. Tip: for long documents "
                       "you can also use the summarize tool."))]
    findings = [f for f in run_phase(ctx, "response") if f.severity != "none"]
    assert findings == [], [(f.detector_id, f.evidence) for f in findings]


def _run():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok", fn.__name__)
    print(f"\n{len(fns)} response-detector tests passed")


if __name__ == "__main__":
    _run()
