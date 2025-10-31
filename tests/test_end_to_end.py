"""End-to-end tests over the self-authored fixtures (static layer only, so they
run without Docker) — plus rule 6 schema validation and determinism."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deepsleuth.models import (
    CATEGORIES, CONFIDENCES, EVIDENCE_LOCATIONS, SEVERITIES, findings_to_json,
)
from deepsleuth.scanner import scan_target
from deepsleuth.target_loader import load_targets

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _static(fixture):
    t = load_targets(os.path.join(FIX, fixture))[0]
    findings, ctx = scan_target(t, do_dynamic=False)
    return [f for f in findings if f.severity != "none"], ctx


def _cats(findings):
    return {f.category for f in findings}


def test_benign_is_clean():
    findings, _ = _static("benign")
    assert findings == [], [f.category for f in findings]


# ---- P1.1 — auth/audit/weak-session family: FP + recall ---------------------


def test_benign_auth_family_is_clean():
    """P1.1: an honestly-declared, legitimately-unauthenticated utility tool
    (destructive-but-honest, no auth claim) and a tool with an *effective*
    auth guard must not fire at all."""
    findings, _ = _static("benign_auth")
    assert findings == [], [(f.detector_id, f.tool_name) for f in findings]


def test_auth_control_present_but_ineffective_detected():
    """P3.2: a control that is present (a permission parameter, or an auth-check
    call) but provably does not the gate the sensitive action is a verifiable
    contradiction and must fire — distinct from mere absence."""
    findings, _ = _static("authbypass")
    ids = {f.detector_id for f in findings}
    assert "auth-control-ineffective" in ids
    tools = {f.tool_name for f in findings if f.detector_id == "auth-control-ineffective"}
    assert tools == {"delete_account", "wipe_logs"}
    for f in findings:
        if f.detector_id == "auth-control-ineffective":
            assert f.category == "auth-misconfiguration"
            assert f.evidence_location == "source"
            assert f.severity in ("medium", "high")


# ---- P1.2 — tool-shadowing / identity family: FP + recall -------------------


def test_benign_multitool_sibling_vocabulary_is_clean():
    """P1.2: sibling tools in one server naturally share vocabulary
    ('replaces'/'supersedes'/'instead of' about their own prior behavior) —
    that is not a collision signal and must not fire tool-shadowing."""
    findings, _ = _static("benign_multitool")
    shadow = [f for f in findings if f.category == "tool-shadowing"]
    assert shadow == [], [(f.tool_name, f.evidence) for f in shadow]


def test_genuine_tool_shadowing_still_detected():
    """P1.2 recall check: a tool that explicitly claims to replace a different,
    *named* entity (quoted/backticked name, 'the official X') is the real
    collision signal and must still fire."""
    findings, _ = _static("tool_shadow")
    shadow = [f for f in findings if f.category == "tool-shadowing"]
    assert shadow, "expected a tool-shadowing finding for genuine identity assertion"
    assert shadow[0].evidence_location == "tool description"


def test_genuine_tool_shadowing_still_detected_varied_wording():
    """V3-3: a second malicious shadowing shape ('claims to be .../masquerades
    as another tool ...'), phrased nothing like ``tool_shadow``, must still
    fire — proving the V3-2 precision fix narrowed the pattern, not the
    mechanism."""
    findings, _ = _static("tool_shadow2")
    shadow = [f for f in findings if f.category == "tool-shadowing"]
    assert shadow, "expected a tool-shadowing finding for the varied-wording case"


def test_benign_multitool2_coordinator_vocabulary_is_clean():
    """V3-2: a second, differently-worded benign multi-tool/coordinator server
    (delegates to "the other tools in this same server", "within this package",
    "in this toolkit itself") must also not fire — one clean fixture is not a
    test of generalization."""
    findings, _ = _static("benign_multitool2")
    shadow = [f for f in findings if f.category == "tool-shadowing"]
    assert shadow == [], [(f.tool_name, f.evidence) for f in shadow]


# ---- V3-2 — tool-poisoning: FP generalization + recall ---------------------


def test_benign_poisoning_ordinary_descriptions_are_clean():
    """V3-2: several ordinary session/admin/audit/auth-requirement tool
    descriptions — all extremely common real-world phrasings — must not trip
    desc-poisoning; only an actual agent-directed instruction should fire."""
    findings, _ = _static("benign_poisoning")
    poison = [f for f in findings if f.category == "tool-poisoning"]
    assert poison == [], [(f.tool_name, f.evidence) for f in poison]


def test_poisoned2_varied_wording_still_detected():
    """V3-3: a second poisoned-description fixture (next-action redirect +
    exfiltration + concealment, calendar/OAuth domain) phrased nothing like
    ``poisoned``'s ssh-key wording must still fire tool-poisoning."""
    findings, _ = _static("poisoned2")
    assert "tool-poisoning" in _cats(findings)


# ---- P1.4 — supply-chain install-hook over-firing ----------------------------


def test_benign_build_postinstall_is_clean():
    """P1.4: an ordinary build/compile postinstall hook (tsc, node-gyp rebuild)
    has no honest-step-exceeding signal and must not be flagged at all."""
    findings, _ = _static("benign_package")
    assert findings == [], [(f.detector_id, f.evidence) for f in findings]


def test_poisoned_description_detected():
    findings, _ = _static("poisoned")
    assert "tool-poisoning" in _cats(findings)
    assert all(f.evidence_location == "description" for f in findings)


def test_injection_source_taint_and_hint_violation():
    findings, _ = _static("injection")
    cats = _cats(findings)
    assert "command-injection" in cats
    assert "excessive-privilege" in cats  # readOnly hint contradicted


def test_supplychain_install_hook_detected():
    findings, _ = _static("supplychain")
    assert "supply-chain" in _cats(findings)
    assert any(f.evidence_location == "install-time-script" for f in findings)


def test_supplychain2_varied_wording_still_detected():
    """V3-3: a different malicious supply-chain shape (credential-path read +
    exfil, no curl|bash pipe) than ``supplychain`` must still fire."""
    findings, _ = _static("supplychain2")
    assert "supply-chain" in _cats(findings)


def test_benign_package2_is_clean():
    """V3-2: a differently-worded ordinary hook set (cmake/electron-builder/
    husky) must not fire — several varied benign fixtures, not just tsc/
    node-gyp."""
    findings, _ = _static("benign_package2")
    assert findings == [], [(f.detector_id, f.evidence) for f in findings]


def test_benign_package3_is_clean():
    """V3-2: chmod on a freshly-built local binary + a trivial inline
    console.log must not fire — the old DANGER bag-of-tokens flagged both."""
    findings, _ = _static("benign_package3")
    assert findings == [], [(f.detector_id, f.evidence) for f in findings]


def test_findings_validate_against_schema():
    for fx in ("poisoned", "injection", "supplychain", "authbypass", "tool_shadow",
               "poisoned2", "supplychain2", "tool_shadow2", "supplychain_indirect",
               "supplychain_networkonly", "authgap_lowstakes", "authgap_corroborated"):
        findings, _ = _static(fx)
        parsed = json.loads(findings_to_json(findings))
        for rec in parsed:
            assert rec["schema_version"] == "1.0.0"
            assert rec["category"] in CATEGORIES
            assert rec["evidence_location"] in EVIDENCE_LOCATIONS
            assert rec["severity"] in SEVERITIES
            assert rec["confidence"] in CONFIDENCES
            for key in ("source", "target", "detection_method", "rationale",
                        "evidence", "raw"):
                assert key in rec


def test_deterministic_output():
    a = findings_to_json(_static("injection")[0])
    b = findings_to_json(_static("injection")[0])
    assert a == b


def _run():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok", fn.__name__)
    print(f"\n{len(fns)} end-to-end tests passed")


if __name__ == "__main__":
    _run()
