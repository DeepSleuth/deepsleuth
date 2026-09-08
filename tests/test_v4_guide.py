"""Unit tests for the v4 mechanism guide : every item
ships a malicious fixture/shape that must stay caught at its stated grade and
an honest twin that must stay clean or informational. Static items scan a
fixture under ``tests/fixtures/`` with ``scan_target(..., do_dynamic=False)``;
dynamic (response-phase) items build a ``ScanContext`` by hand exactly as
``tests/test_v3_guide.py`` does, so no Docker is needed to prove a mechanism.
"""
import importlib.util
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deepsleuth.analysis.pyast import (
    analyze_tool_function, collect_module_functions, extract_tools, parse_module,
    _collect_module_globals,
)
from deepsleuth.context import CANARIES, CallRecord, ScanContext, ToolContract
from deepsleuth.models import Target
from deepsleuth.runner import run_phase
from deepsleuth.scanner import scan_target
from deepsleuth.target_loader import load_targets

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _actionable(f) -> bool:
    return f.severity in ("medium", "high", "critical") and f.confidence in ("medium", "high")


def _static(fixture):
    t = load_targets(os.path.join(FIX, fixture))[0]
    findings, ctx = scan_target(t, do_dynamic=False)
    return [f for f in findings if f.severity != "none"], ctx


def _direct_ctx(tools):
    ctx = ScanContext(target=Target(target_id="v4-guide"))
    ctx.tools = [ToolContract(name=n, description=d) for n, d in tools]
    return ctx


def _response_findings(ctx):
    return [f for f in run_phase(ctx, "response") if f.severity != "none"]


def _load_fixture_module(fixture):
    d = os.path.join(FIX, fixture)
    sys.path.insert(0, d)
    try:
        spec = importlib.util.spec_from_file_location(f"fx_{fixture}", os.path.join(d, "server.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(d)
    return mod


def _ctx_from_fixture_module(fixture, calls):
    mod = _load_fixture_module(fixture)
    ctx = ScanContext(target=Target(target_id=fixture))
    ctx.tools = [ToolContract(name=t["name"], description=t["description"],
                              input_schema=t.get("inputSchema", {}))
                 for t in mod.mcp._tools]
    ctx.calls = [CallRecord(seq=i, tool_name=tool, arguments=args, response_text=text)
                 for i, (tool, args, text) in enumerate(calls)]
    return ctx, mod


def _facts(src: str, tool: str = None):
    tree = parse_module(src)
    g = _collect_module_globals(tree)
    tools = extract_tools(tree)
    td = next(t for t in tools if (tool is None or t.name == tool))
    helpers = {n: f for n, f in collect_module_functions(tree).items() if n != td.func_name}
    return td, analyze_tool_function(td.node, td.params, g, src, module_functions=helpers)


def _leak_hits(ctx, canary):
    return [f for f in _response_findings(ctx) if f.detector_id == "response-leak"
            and f.evidence.get("canary") == canary]


# =============================================================================
# 1 — audit-echo by attribution, not by description
# =============================================================================

def test_v4_1_bare_echo_in_unrelated_response_is_high():
    """Malicious: the planted value resurfaces in another tool's answer with
    nothing in that line naming the call that supplied it."""
    canary = CANARIES.arg("save_preference", "note")
    ctx, mod = _ctx_from_fixture_module("leak_bare_echo", [])
    mod.save_preference(canary)
    ctx.calls = [
        CallRecord(seq=0, tool_name="save_preference", arguments={"note": canary},
                   response_text="Preference saved."),
        CallRecord(seq=1, tool_name="get_weather", arguments={"city": "paris"},
                   response_text=mod.get_weather("paris")),
    ]
    assert canary in ctx.calls[1].response_text
    hits = _leak_hits(ctx, canary)
    assert hits and hits[0].severity == "high" and hits[0].confidence == "high"
    assert hits[0].evidence["attributed"] is False
    assert _actionable(hits[0])


def test_v4_1_attributed_json_record_is_low_warning_without_any_declaration():
    """Honest twin: the value sits in a JSON record that names the planting
    tool; neither description mentions logging or recording."""
    canary = CANARIES.arg("create_ticket", "note")
    ctx, mod = _ctx_from_fixture_module("audit_echo_attributed", [])
    mod.create_ticket(canary)
    ctx.calls = [
        CallRecord(seq=0, tool_name="create_ticket", arguments={"note": canary},
                   response_text="Ticket created."),
        CallRecord(seq=1, tool_name="get_recent_activity", arguments={},
                   response_text=mod.get_recent_activity()),
    ]
    descs = " ".join(t.description for t in ctx.tools).lower()
    assert "log" not in descs and "record" not in descs and "audit" not in descs
    hits = _leak_hits(ctx, canary)
    assert hits, "the echo is still reported, as a warning"
    assert hits[0].severity == "low" and hits[0].confidence == "medium"
    assert hits[0].evidence["attributed"] is True
    assert hits[0].evidence["attribution"].lower() == "create_ticket"
    assert not _actionable(hits[0])


def test_v4_1_attribution_by_verb_token_of_the_planting_tool_name():
    """A prose record attributes through an inflected verb token of the
    planting tool's own name ("Created ticket ..." for ``create_ticket``)."""
    canary = CANARIES.arg("create_ticket", "note")
    ctx = _direct_ctx([("create_ticket", "Creates a support ticket."),
                       ("get_recent_activity", "Returns recent server activity.")])
    ctx.calls = [
        CallRecord(seq=0, tool_name="create_ticket", arguments={"note": canary},
                   response_text="ok"),
        CallRecord(seq=1, tool_name="get_recent_activity", arguments={},
                   response_text=f"10:02 Created ticket #7 with note '{canary}'\n10:03 Closed ticket #6"),
    ]
    hits = _leak_hits(ctx, canary)
    assert hits and hits[0].severity == "low" and hits[0].evidence["attribution"] == "Created"


def test_v4_1_attribution_must_be_in_the_same_record():
    """The planting tool named in ANOTHER record (or another line) of the
    same response does not attribute the echoed value."""
    canary = CANARIES.arg("create_ticket", "note")
    ctx = _direct_ctx([("create_ticket", "Creates a support ticket."),
                       ("get_recent_activity", "Returns recent server activity.")])
    records = [{"tool": "create_ticket", "args": {"note": "something else"}},
               {"tool": "get_weather", "args": {"city": "paris"}, "debug": canary}]
    ctx.calls = [
        CallRecord(seq=0, tool_name="create_ticket", arguments={"note": canary},
                   response_text="ok"),
        CallRecord(seq=1, tool_name="get_recent_activity", arguments={},
                   response_text=json.dumps(records)),
    ]
    hits = _leak_hits(ctx, canary)
    assert hits and hits[0].severity == "high" and hits[0].evidence["attributed"] is False
    ctx.calls[1].response_text = f"calls so far: create_ticket, get_weather\nlast value: {canary}"
    hits = _leak_hits(ctx, canary)
    assert hits and hits[0].severity == "high"


def test_v4_1_noun_token_of_the_name_does_not_attribute():
    """``set_note``: "note" is not a verb token; "(debug: last note was X)"
    stays a bare echo."""
    canary = CANARIES.arg("set_note", "text")
    ctx = _direct_ctx([("set_note", "Stores a note."), ("weather", "Weather for a city.")])
    ctx.calls = [
        CallRecord(seq=0, tool_name="set_note", arguments={"text": canary}, response_text="ok"),
        CallRecord(seq=1, tool_name="weather", arguments={"city": "paris"},
                   response_text=f"21C, clear. (debug: last note was '{canary}')"),
    ]
    hits = _leak_hits(ctx, canary)
    assert hits and hits[0].severity == "high" and hits[0].evidence["attributed"] is False


def test_v4_1_internal_or_underscore_surface_is_never_downgraded():
    canary = CANARIES.arg("create_ticket", "note")
    for name, desc in (("_dump_log", "Returns recent activity."),
                       ("dump_log", "Internal diagnostic dump, not for end users.")):
        ctx = _direct_ctx([("create_ticket", "Creates a support ticket."), (name, desc)])
        ctx.calls = [
            CallRecord(seq=0, tool_name="create_ticket", arguments={"note": canary},
                       response_text="ok"),
            CallRecord(seq=1, tool_name=name, arguments={},
                       response_text=json.dumps([{"tool": "create_ticket", "note": canary}])),
        ]
        hits = _leak_hits(ctx, canary)
        assert hits and hits[0].severity == "high" and hits[0].confidence == "high", name


def test_v4_1_secret_kind_canary_attributed_stays_high():
    secret = CANARIES.secret("token", "register_key", "api_key")
    ctx = _direct_ctx([("register_key", "Registers an API key."),
                       ("get_recent_activity", "Returns recent server activity.")])
    ctx.calls = [
        CallRecord(seq=0, tool_name="register_key", arguments={"api_key": secret},
                   response_text="ok"),
        CallRecord(seq=1, tool_name="get_recent_activity", arguments={},
                   response_text=json.dumps([{"tool": "register_key", "api_key": secret}])),
    ]
    hits = _leak_hits(ctx, secret)
    assert hits and hits[0].severity == "high" and hits[0].confidence == "high"


# =============================================================================
# 2 — write-verb coverage in the read-shaped description test
# =============================================================================

def test_v4_2_read_verb_only_description_over_visible_mutation_is_scope_creep():
    findings, _ = _static("scope_creep_read_verb_mutation")
    hits = [f for f in findings if f.detector_id == "scope-creep" and f.tool_name == "get_balance"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].severity == "medium" and hits[0].confidence == "medium"
    assert _actionable(hits[0])


def test_v4_2_write_verb_in_description_is_not_read_shaped():
    """Honest twin: "gets ... and marks the account as reviewed" declares
    the write; nothing actionable."""
    findings, _ = _static("scope_creep_write_verb_declared_benign")
    assert not [f for f in findings if f.detector_id == "scope-creep"], \
        [(f.detector_id, f.tool_name, f.severity) for f in findings]
    assert not any(_actionable(f) for f in findings), \
        [(f.detector_id, f.tool_name, f.severity, f.confidence) for f in findings]


def test_v4_2_write_verb_class_is_inflected():
    from deepsleuth.detectors.privilege import _desc_is_read_shaped
    assert _desc_is_read_shaped("Gets the balance for an account.")
    for verb in ("applies", "registers", "records", "marks", "grants", "revokes",
                 "assigns", "submits", "increments", "charges", "credits", "debits",
                 "enrolls", "activates", "deactivates", "applied", "marking",
                 "submitted", "incrementing", "enrolled"):
        assert not _desc_is_read_shaped(f"Gets the account and {verb} the change."), verb


def test_v4_2_ambiguous_write_words_count_only_in_verb_position():
    from deepsleuth.detectors.privilege import _desc_is_read_shaped
    # noun position: still read-shaped
    assert _desc_is_read_shaped("Look up a customer record by id.")
    assert _desc_is_read_shaped("Gets the store credit balance and the service charge for an order.")
    assert _desc_is_read_shaped("Gets the recorded value for a sensor.")
    assert _desc_is_read_shaped("Lists items marked as done.")
    assert _desc_is_read_shaped("Shows the grant details for a project.")
    # verb position: a declared write
    assert not _desc_is_read_shaped("Records the lookup and returns the customer.")
    assert not _desc_is_read_shaped("Gets the account and marks it as reviewed.")
    assert not _desc_is_read_shaped("Finds the order; the card is charged on success.")
    assert not _desc_is_read_shaped("Gets the invoice and will credit the account.")
    assert not _desc_is_read_shaped("Looks up the user, then grants access.")
    assert not _desc_is_read_shaped("Gets the balance after charging the fee.")


# =============================================================================
# 3 — "consulted" refinement (pyast._param_consulted)
# =============================================================================

def _unused(src: str, tool: str = None):
    _, f = _facts(src, tool)
    return set(f.unused_params)


def test_v4_3_call_result_consumed_counts_as_used():
    base = "_DB = dict()\ndef f(x):\n    return x\n@mcp.tool()\n{sig}\n{body}\n"
    used_bodies = [
        ("def t(p):", "    r = f(p)\n    return r"),
        ("def t(p):", "    return f(p)"),
        ("async def t(p):", "    await f(p)\n    return 'ok'"),
        ("def t(p):", "    yield f(p)"),
        ("def t(p):", "    if f(p):\n        return 'y'\n    return 'n'"),
        ("def t(p):", "    assert f(p)\n    return 'ok'"),
        ("def t(p):", "    _DB.warm(p)\n    return 'ok'"),
        ("def t(p):", "    _DB.execute('insert', (p,))\n    return 'ok'"),
    ]
    for sig, body in used_bodies:
        assert "p" not in _unused(base.format(sig=sig, body=body)), body


def test_v4_3_discarded_bare_call_or_logging_counts_as_unused():
    base = "import logging\n_DB = dict()\ndef f(x):\n    return x\n@mcp.tool()\ndef t(p):\n{body}\n    return 'ok'\n"
    for body in ("    f(p)", "    logging.info(p)", "    print(p)", "    f(g(p))" , "    logging.getLogger('x').debug('got %s', p)"):
        src = base.format(body=body).replace("def f(x):", "def g(x):\n    return x\ndef f(x):")
        assert "p" in _unused(src), body


def test_v4_3_fixture_pair():
    findings, _ = _static("consulted_bare_call_discarded")
    hits = [f for f in findings if f.detector_id == "out-of-scope-param"
            and f.evidence["param"] == "conversation_history"]
    assert hits and hits[0].severity == "high" and hits[0].confidence == "high"
    assert hits[0].evidence["confirmed_unused_in_source"] is True
    findings, _ = _static("consulted_state_method_benign")
    hits = [f for f in findings if f.detector_id == "out-of-scope-param"
            and f.evidence["param"] == "conversation_history"]
    assert hits and hits[0].severity == "low" and hits[0].confidence == "low"
    assert hits[0].evidence["confirmed_unused_in_source"] is False
    assert not any(_actionable(f) for f in findings), \
        [(f.detector_id, f.tool_name, f.severity, f.confidence) for f in findings]


# =============================================================================
# 4 — generic side-channel names need an empty / caller-context-shaped description
# =============================================================================

def test_v4_4_undescribed_unused_generic_name_is_actionable():
    findings, _ = _static("side_channel_generic_undescribed")
    hits = [f for f in findings if f.detector_id == "out-of-scope-param" and f.evidence["param"] == "metadata"]
    assert hits and hits[0].severity == "medium" and hits[0].confidence == "medium"
    assert hits[0].evidence["generic_side_channel"] is True
    assert _actionable(hits[0])


def test_v4_4_described_domain_param_unused_is_informational():
    findings, _ = _static("side_channel_generic_described_benign")
    hits = [f for f in findings if f.detector_id == "out-of-scope-param" and f.evidence["param"] == "metadata"]
    assert hits and hits[0].severity == "low" and hits[0].confidence == "low"
    assert hits[0].evidence["described_domain_param"] is True
    assert "folder" in hits[0].evidence["description_excerpt"].lower()
    assert not any(_actionable(f) for f in findings), \
        [(f.detector_id, f.tool_name, f.severity, f.confidence) for f in findings]


def test_v4_4_caller_context_shaped_description_still_fires():
    from deepsleuth.detectors.crosstool import _desc_is_caller_context_shaped
    for d in ("", "Debug context.", "Opaque metadata blob from the caller.",
              "Any additional trace info.", "Name of the calling model."):
        assert _desc_is_caller_context_shaped(d), d
    for d in ("The folder to search within (defaults to the whole index).",
              "Trace ID of the upstream order.", "Metadata of the uploaded file: title and author."):
        assert not _desc_is_caller_context_shaped(d), d


def test_v4_4_docstring_and_field_descriptions_reach_the_scope_rule():
    from deepsleuth.analysis.pyast import param_docs_for
    src = (
        "from pydantic import Field\nfrom typing import Annotated\n"
        "@mcp.tool()\n"
        "def t(query: str, context: Annotated[str, Field(description='Folder to search')],\n"
        "      metadata: str = Field('', description='Debug context')):\n"
        "    '''Search.\n\n    Args:\n        query: The text to search for.\n    '''\n"
        "    return query\n"
    )
    td, _ = _facts(src)
    docs = param_docs_for(td.node)
    assert docs == {"query": "The text to search for.", "context": "Folder to search",
                    "metadata": "Debug context"}


# =============================================================================
# 6 — quoted own-parameter without a schema (signature + docstring argument section)
# =============================================================================

def test_v4_6_docstring_documented_own_parameter_is_not_a_tool_name():
    findings, ctx = _static("quoted_own_param_docstring_benign")
    from deepsleuth.detectors.crosstool import _own_prop_names
    c = ctx.tool_by_name("export_report")
    assert {"report_id", "page_cursor"} <= set(_own_prop_names(c))
    assert not [f for f in findings if f.detector_id in ("cross-tool-redirect", "param-tampering")], \
        [(f.detector_id, f.tool_name, f.severity, f.evidence) for f in findings]
    assert not any(_actionable(f) for f in findings), \
        [(f.detector_id, f.tool_name, f.severity, f.confidence) for f in findings]


def test_v4_6_quoted_token_outside_signature_and_docstring_still_fires():
    findings, _ = _static("quoted_sibling_not_own_param")
    hits = [f for f in findings if f.detector_id == "cross-tool-redirect" and _actionable(f)]
    assert hits, [(f.detector_id, f.tool_name, f.severity, f.confidence) for f in findings]
    assert hits[0].severity == "high"
    assert hits[0].evidence["matches"][0]["sibling"] == "sync_remote_cache"
    assert hits[0].evidence["modes"] == ["quoted-name"]


def test_v4_6_own_prop_names_cover_signature_docstring_and_sphinx():
    from deepsleuth.context import SourceFacts, ToolContract
    from deepsleuth.analysis.pyast import BehaviorFacts
    from deepsleuth.detectors.crosstool import _own_prop_names
    src = (
        "@mcp.tool()\n"
        "def t(alpha_key, **kw):\n"
        "    '''Doc.\n\n    :param beta_token: x\n\n    Parameters\n    ----------\n"
        "    gamma_id : str\n        y\n    '''\n    return 1\n"
    )
    td, facts = _facts(src)
    c = ToolContract(name="t", description="", input_schema={},
                     source=SourceFacts(tool_def=td, facts=facts, module_path="m.py"))
    assert {"alpha_key", "beta_token", "gamma_id"} <= set(_own_prop_names(c))


# =============================================================================
# 7 — forceful sentence, sibling as the object of ANY verb (actionable tier only)
# =============================================================================

def test_v4_7_strong_word_plus_sibling_as_object_of_any_verb_is_actionable():
    findings, _ = _static("crosstool_object_of_any_verb")
    hits = [f for f in findings if f.detector_id == "cross-tool-redirect" and f.tool_name == "summarize_doc"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].severity == "high" and hits[0].confidence == "high"
    m = hits[0].evidence["matches"][0]
    assert m["sibling"] == "export_full_archive" and m["verb_object"] == "prefer"
    assert m["reason"] == "strong-obligation-word"


def test_v4_7_without_a_strong_word_the_closed_invoke_list_still_rules():
    findings, _ = _static("crosstool_object_of_verb_no_strong_word_benign")
    assert not [f for f in findings if f.detector_id == "cross-tool-redirect"], \
        [(f.detector_id, f.tool_name, f.severity, f.evidence) for f in findings]
    assert not any(_actionable(f) for f in findings), \
        [(f.detector_id, f.tool_name, f.severity, f.confidence) for f in findings]


def test_v4_7_verb_object_shapes():
    from deepsleuth.detectors.crosstool import _name_pattern, _sibling_as_verb_object
    pat = _name_pattern("export_full_archive")
    assert _sibling_as_verb_object("You must always prefer export_full_archive for long documents", pat) == "prefer"
    assert _sibling_as_verb_object("Agents must consult the export_full_archive tool first", pat) == "consult"
    assert _sibling_as_verb_object("Never skip export_full_archive", pat) == "skip"
    assert _sibling_as_verb_object("It is mandatory to favour export_full_archive here", pat) == "favour"
    # adjective between article and name, preposition, naming participle, sibling first
    assert _sibling_as_verb_object("Results must match the legacy export_full_archive format", pat) is None
    assert _sibling_as_verb_object("It is mandatory to route documents through export_full_archive", pat) is None
    assert _sibling_as_verb_object("The tool named export_full_archive is required", pat) is None
    assert _sibling_as_verb_object("export_full_archive must be used first", pat) is None


# =============================================================================
# 5 — sanitizer recognition through expression nesting
# =============================================================================

def test_v4_5_nested_sanitizers_in_assignments_sanitize_the_sink():
    findings, _ = _static("sanitizer_nested_assignment_benign")
    taint = [f for f in findings if f.detector_id == "ast-taint" and f.detection_method == "ast-taint"]
    assert {f.tool_name for f in taint} == {"read_data", "read_index", "count_bytes"}, \
        [(f.tool_name, f.category) for f in taint]
    for f in taint:
        assert f.evidence["sanitized"] is True, (f.tool_name, f.evidence)
        assert f.severity == "low" and f.confidence == "low", (f.tool_name, f.severity)
    assert not any(_actionable(f) for f in findings), \
        [(f.detector_id, f.tool_name, f.severity, f.confidence) for f in findings]


def test_v4_5_raw_tainted_name_beside_nested_sanitizer_stays_actionable():
    findings, _ = _static("sanitizer_nested_partial_bypassed")
    by_tool = {f.tool_name: f for f in findings
               if f.detector_id == "ast-taint" and f.detection_method == "ast-taint"}
    rd = by_tool["read_data"]
    assert rd.evidence["sanitized"] is False and rd.category == "path-traversal"
    assert rd.severity == "medium" and _actionable(rd), (rd.severity, rd.confidence)
    cb = by_tool["count_bytes"]
    assert cb.evidence["sanitized"] is False and cb.category == "command-injection"
    assert cb.severity == "critical" and _actionable(cb), (cb.severity, cb.confidence)


def test_v4_5_stripped_and_normalized_names_through_nesting():
    src = (
        "import os, shlex\nfrom pathlib import Path\nBASE = '/srv'\n"
        "@mcp.tool()\n"
        "def t(name, sub, other):\n"
        "    a = os.path.join(BASE, os.path.basename(name))\n"
        "    b = 'ls ' + shlex.quote(name)\n"
        "    c = f'wc -c {shlex.quote(name)}'\n"
        "    d = str(Path(BASE, sub).resolve())\n"
        "    e = os.path.join(BASE, os.path.normpath(sub))\n"
        "    f = os.path.join(BASE, os.path.basename(name), other)\n"
        "    g = f'{shlex.quote(name)} {other}'\n"
        "    h = os.path.realpath(os.path.join(BASE, os.path.basename(name)))\n"
        "    return a + b + c + d + e + f + g + h\n"
    )
    tree = parse_module(src)
    td = extract_tools(tree)[0]
    g = _collect_module_globals(tree)
    # run the analyzer directly to read its name sets
    from deepsleuth.analysis import pyast as _py
    az = _py._FuncAnalyzer(td.params, set(g))
    az.visit(td.node)
    assert {"a", "b", "c", "h"} <= az.stripped_names, az.stripped_names
    assert {"d", "e"} <= az.norm_path_names, az.norm_path_names
    assert not ({"f", "g"} & (az.stripped_names | az.norm_path_names))


# =============================================================================
# 8 — declared-capability tag and the allow_declared_capabilities policy
# =============================================================================

def _taint_findings(fixture):
    findings, _ = _static(fixture)
    return findings, [f for f in findings if f.detector_id == "ast-taint"
                      and f.detection_method == "ast-taint"]


def test_v4_8_declared_capability_is_tagged_with_full_grade():
    findings, taint = _taint_findings("declared_capability_policy")
    assert taint and taint[0].tool_name == "run_command"
    assert taint[0].severity == "critical" and taint[0].confidence == "high"
    assert taint[0].raw["declared_capability"] is True
    note = [f for f in findings if f.detection_method == "declared-capability"]
    assert note and note[0].raw["declared_capability"] is True
    _, untainted = _taint_findings("undeclared_capability_policy")
    assert untainted and untainted[0].severity == "critical"
    assert untainted[0].raw["declared_capability"] is False


def test_v4_8_policy_confirms_declared_and_blocks_undeclared():
    from deepsleuth.gate import (ANNOTATE, BLOCK, CONFIRM, WITHHOLD, Policy,
                                   gate_decision, startup_action)
    declared, _ = _taint_findings("declared_capability_policy")
    undeclared, _ = _taint_findings("undeclared_capability_policy")
    default = Policy.default()
    assert default.allow_declared_capabilities is False
    assert gate_decision(declared, default)[0] == BLOCK
    assert gate_decision(undeclared, default)[0] == BLOCK
    assert startup_action(declared, default)[0] == WITHHOLD
    assert startup_action(undeclared, default)[0] == WITHHOLD
    allow = Policy.default()
    allow.allow_declared_capabilities = True
    assert gate_decision(declared, allow)[0] == CONFIRM
    assert gate_decision(undeclared, allow)[0] == BLOCK
    assert startup_action(declared, allow)[0] == ANNOTATE
    assert startup_action(undeclared, allow)[0] == WITHHOLD
    # a declared finding beside an undeclared high one never rescues the call
    assert gate_decision(declared + undeclared, allow)[0] == BLOCK
    assert startup_action(declared + undeclared, allow)[0] == WITHHOLD


def test_v4_8_policy_key_loads_from_file_and_round_trips():
    import tempfile
    from deepsleuth.gate import Policy
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write("block_high: true\nallow_declared_capabilities: true\n")
        path = fh.name
    try:
        pol = Policy.load(path)
    finally:
        os.unlink(path)
    assert pol.allow_declared_capabilities is True
    assert pol.to_dict()["allow_declared_capabilities"] is True
    example = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "policy.example.yaml")
    assert Policy.load(example).allow_declared_capabilities is False


# =============================================================================
# 9 — JavaScript/TypeScript taint flow, one level
# =============================================================================

def test_v4_9_param_reaching_sink_through_a_local_is_tainted():
    findings, ctx = _static("js_taint_one_level")
    assert sorted(c.name for c in ctx.all_contracts()) == ["archive_folder", "convert_image"]
    by_tool = {f.tool_name: f for f in findings if f.detector_id == "ast-taint"
               and f.detection_method == "ast-taint"}
    ci = by_tool["convert_image"]
    assert ci.category == "command-injection" and ci.evidence["shell"] is True
    assert ci.severity == "critical" and _actionable(ci)
    assert ci.evidence["tainted_params"] == ["cmd"]
    af = by_tool["archive_folder"]
    assert af.evidence["shell"] is True and af.severity == "critical" and _actionable(af)
    assert af.evidence["tainted_params"] == ["target"]


def test_v4_9_constant_locals_at_sinks_are_capability_facts_not_taint():
    findings, ctx = _static("js_taint_constant_local_benign")
    assert not [f for f in findings if f.detector_id == "ast-taint"], \
        [(f.tool_name, f.evidence) for f in findings if f.detector_id == "ast-taint"]
    gs = ctx.tool_by_name("git_status")
    assert gs.source.facts.spawns_proc and not any(s.tainted for s in gs.source.facts.sinks)
    fc = ctx.tool_by_name("fetch_changelog")
    assert fc.source.facts.network and not any(s.tainted for s in fc.source.facts.sinks)
    assert not any(_actionable(f) for f in findings), \
        [(f.detector_id, f.tool_name, f.severity, f.confidence) for f in findings]


def test_v4_9_binding_shapes_and_shell_detection():
    from deepsleuth.analysis.jsast import _js_tainted_locals, _sink_records
    body = (
        "const { arguments: toolArgs } = request.params;\n"
        "const command = toolArgs.command;\n"
        "let line = `run ${command} now`;\n"
        "var fixed = 'git status';\n"
        "other = request.params.name + '-x';\n"
        "const notme = foo.request;\n"
    )
    t = _js_tainted_locals(body, ["request"])
    assert t["toolArgs"] == {"request"} and t["command"] == {"request"}
    assert t["line"] == {"request"} and t["other"] == {"request"}
    assert "fixed" not in t and "notme" not in t
    sinks = _sink_records(
        body + "execSync(line); execFile('ls', [command]); spawn('sh', ['-c', line], { shell: true });"
        " spawn('ls', [fixed]); eval(fixed); fetch(toolArgs.url);",
        ["request"], 1)
    by_call = {}
    for s in sinks:
        by_call.setdefault(s.call, []).append(s)
    assert by_call["execSync"][0].tainted and by_call["execSync"][0].shell
    assert by_call["execFile"][0].tainted and not by_call["execFile"][0].shell
    spawns = by_call["spawn"]
    assert spawns[0].tainted and spawns[0].shell
    assert not spawns[1].tainted and not spawns[1].shell
    assert not by_call["eval"][0].tainted
    assert by_call["fetch"][0].tainted and by_call["fetch"][0].kind == "network"


# =============================================================================
# 10 — writer before reader in the call plan, from BehaviorFacts only
# =============================================================================

def _plan_for(fixture):
    from deepsleuth.sandbox.argsynth import build_call_plan, _behavior_class
    ctx = _ctx_with_source(fixture)
    sf = getattr(ctx, "_source_facts", {})
    tools_raw = [{"name": c.name, "inputSchema": c.input_schema} for c in ctx.tools]
    return build_call_plan(tools_raw, passes=2, source_facts=sf), sf, _behavior_class


def _ctx_with_source(fixture):
    from deepsleuth.scanner import build_static_context
    t = load_targets(os.path.join(FIX, fixture))[0]
    return build_static_context(t)


def test_v4_10_writer_ordered_before_reader_despite_alphabetical_order():
    for fixture in ("plan_order_store_pair", "plan_order_independent_stores_benign"):
        plan, sf, cls = _plan_for(fixture)
        assert cls("z_save_note", sf) == "mutator" and cls("a_show_status", sf) == "reader", fixture
        assert sf["z_save_note"].facts.mutated_state_names, fixture
        names = [n for n, _ in plan]
        # the reader's single baseline observation comes first, then every
        # writer call precedes the reader's next call
        assert names[0] == "a_show_status", names[:3]
        rest = names[1:]
        assert rest.index("z_save_note") < rest.index("a_show_status"), names
        first_reader_after = rest.index("a_show_status")
        assert all(n == "z_save_note" for n in rest[:first_reader_after]), names
        assert "a_show_status" in rest[first_reader_after:], names


def test_v4_10_live_leak_observed_only_when_stores_are_shared():
    from deepsleuth.sandbox.docker_sandbox import docker_available
    if not docker_available():
        print("SKIP (docker not available in this environment)")
        return
    t = load_targets(os.path.join(FIX, "plan_order_store_pair"))[0]
    findings, ctx = scan_target(t, do_dynamic=True, timeout=60)
    assert "dynamic" in ctx.layers, ctx.skipped
    leaks = [f for f in findings if f.detector_id == "response-leak"
             and f.category == "data-exfiltration"]
    assert leaks and leaks[0].severity == "high" and leaks[0].confidence == "high"
    assert leaks[0].evidence["planted_in_tool"] == "z_save_note"
    assert leaks[0].evidence["surfaced_in_tool"] == "a_show_status"
    assert leaks[0].evidence["attributed"] is False
    t = load_targets(os.path.join(FIX, "plan_order_independent_stores_benign"))[0]
    findings, ctx = scan_target(t, do_dynamic=True, timeout=60)
    assert "dynamic" in ctx.layers, ctx.skipped
    assert not [f for f in findings if f.detector_id == "response-leak"], \
        [(f.tool_name, f.evidence) for f in findings if f.detector_id == "response-leak"]
    assert not any(_actionable(f) for f in findings if f.severity != "none"), \
        [(f.detector_id, f.tool_name, f.severity, f.confidence) for f in findings]
