"""§v5-8PT — Python descriptions held indirectly (the ``js_indirect_desc``
mirror): a tool registered with ``description=<imported constant>`` must have
that text resolved and analyzed exactly like a literal at the registration
site. Before the fix the static extractor returned a blank description for
these shapes, so ``desc-poisoning`` never saw the instruction; the JS side had
resolved this since v5.8 while the Python side silently did not.

Malicious: a constant imported by name, an attribute of an imported module.
Benign twin: same indirection, honest text — resolution must not manufacture
findings, and the tools must carry their REAL descriptions (not blanks).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deepsleuth.scanner import scan_target
from deepsleuth.target_loader import load_targets

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _static(fixture):
    t = load_targets(os.path.join(FIX, fixture))[0]
    findings, ctx = scan_target(t, do_dynamic=False)
    return [f for f in findings if f.severity != "none"], ctx


def _by_tool(findings, detector_id=None):
    out = {}
    for f in findings:
        if detector_id is None or f.detector_id == detector_id:
            out.setdefault(f.tool_name, []).append(f)
    return out


def test_imported_poisoned_description_is_resolved_and_caught():
    """Malicious: ``from _descs import SEARCH_DESC`` and ``_descs.FETCH_DESC``."""
    findings, ctx = _static("py_indirect_desc")
    desc = _by_tool(findings, "desc-poisoning")
    expect = {"search_docs": "override_instructions", "fetch_page": "concealment"}
    for tool, family in expect.items():
        assert tool in desc, (tool, sorted(desc))
        f = desc[tool][0]
        assert (f.severity, f.confidence) == ("high", "high"), (tool, f.severity, f.confidence)
        assert family in f.evidence["families"], (tool, f.evidence["families"])
    # the honest literal control stays clean
    assert "list_docs" not in _by_tool(findings, "desc-poisoning")


def test_imported_honest_descriptions_resolve_and_stay_clean():
    findings, ctx = _static("py_indirect_desc_benign")
    assert findings == [], [(f.detector_id, f.tool_name, f.severity) for f in findings]
    descs = {c.name: c.description for c in ctx.tools}
    # resolution proof: the imported text (not a blank) is the contract
    assert descs["search_docs"].startswith("Search the document index. Results are limited")
    assert descs["fetch_page"] == "Fetch a page and return its text content."
    assert descs["list_docs"] == "List the recent documents."