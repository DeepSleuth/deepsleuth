"""Unit tests for the the gate decision policy (rule 4.7) — pure, no live client."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deepsleuth.gate import (
    ALLOW, BLOCK, CONFIRM, WITHHOLD, ANNOTATE, PASS,
    Policy, gate_decision, resolve_confirm, startup_action, response_action,
)
from deepsleuth.models import Finding


def _f(sev):
    return Finding(category="tool-poisoning", evidence_location="tool description",
                   severity=sev, detection_method="t", confidence="high",
                   rationale="r", target_id="x")


def test_clean_allows():
    assert gate_decision([], Policy.default())[0] == ALLOW


def test_high_blocks_by_default():
    assert gate_decision([_f("high")], Policy.default())[0] == BLOCK


def test_low_medium_confirms():
    assert gate_decision([_f("low")], Policy.default())[0] == CONFIRM
    assert gate_decision([_f("medium")], Policy.default())[0] == CONFIRM


def test_policy_can_downgrade_high_to_confirm():
    pol = Policy.default(); pol.block_high = False
    assert gate_decision([_f("critical")], pol)[0] == CONFIRM


def test_confirm_without_elicitation_falls_closed_to_block():
    d, _ = resolve_confirm(CONFIRM, Policy.default(), elicitation_supported=False)
    assert d == BLOCK


def test_confirm_with_approval_allows_and_denial_blocks():
    assert resolve_confirm(CONFIRM, Policy.default(), elicitation_supported=True,
                           approved=True)[0] == ALLOW
    assert resolve_confirm(CONFIRM, Policy.default(), elicitation_supported=True,
                           approved=False)[0] == BLOCK


def test_fail_closed_turns_unresolved_confirm_into_block():
    pol = Policy.default(); pol.fail_closed = True
    d, _ = resolve_confirm(CONFIRM, pol, elicitation_supported=True, approved=None)
    assert d == BLOCK


def test_startup_withhold_and_annotate():
    assert startup_action([_f("high")], Policy.default())[0] == WITHHOLD
    assert startup_action([_f("low")], Policy.default())[0] == ANNOTATE
    assert startup_action([], Policy.default())[0] == PASS


def test_response_block_and_annotate():
    assert response_action([_f("high")], Policy.default())[0] == BLOCK
    assert response_action([_f("medium")], Policy.default())[0] == ANNOTATE


def test_policy_flat_yaml_parse():
    import tempfile
    p = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    p.write("block_high: false\nwithhold_threshold: critical\n# comment\n")
    p.close()
    pol = Policy.load(p.name)
    assert pol.block_high is False and pol.withhold_threshold == "critical"
    os.unlink(p.name)


def _run():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok", fn.__name__)
    print(f"\n{len(fns)} gate tests passed")


if __name__ == "__main__":
    _run()
