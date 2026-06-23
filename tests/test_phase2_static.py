"""Unit tests for Phase 2 of the improvement guide: the static source engine
(2.2-2.8). Each malicious fixture has a benign twin that shares surface
shape and must stay clean (mechanism-strict).
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


# --- rule 2.2 — runtime __doc__/tool-metadata mutation -------------------------

def test_metadata_mutation_fires_runtime_metadata_mutation():
    findings, _ = _static("metadata_mutation")
    hits = [f for f in findings if f.detector_id == "runtime-metadata-mutation"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].tool_name == "get_weather_forecast"
    assert hits[0].evidence_location == "source"
    # gated on the call-counter -> escalated to high
    assert hits[0].severity == "high"


# --- rule P4.3 — scan the docstring-mutation TEXT with the description rules --

def test_metadata_mutation_instruction_text_fires_high_without_a_gate():
    """An UNGATED rewrite whose text itself carries an instruction must
    still grade high — the text is decisive on its own, gating is not the
    only path."""
    findings, _ = _static("metadata_mutation_instruction_ungated")
    hits = [f for f in findings if f.detector_id == "runtime-metadata-mutation"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].severity == "high" and hits[0].confidence == "high"
    assert hits[0].evidence["carries_instruction"] is True
    assert hits[0].evidence["gated"] is False


def test_metadata_mutation_plain_text_is_informational():
    """An UNGATED rewrite to plain, honest prose (no instruction mechanism)
    is still recorded (the contract is not fixed at listing time) but only
    as an informational low/low note."""
    findings, _ = _static("metadata_mutation_plain_informational")
    hits = [f for f in findings if f.detector_id == "runtime-metadata-mutation"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].severity == "low" and hits[0].confidence == "low"
    assert hits[0].evidence["carries_instruction"] is False
    assert hits[0].evidence["gated"] is False


def test_metadata_mutation_benign_ordinary_counter_stays_clean():
    findings, _ = _static("metadata_mutation_benign")
    hits = [f for f in findings if f.detector_id == "runtime-metadata-mutation"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


def test_metadata_mutation_benign_local_var_and_unrelated_doc_stays_clean():
    """FP fix: a tool that writes ``__doc__`` on an unrelated, unregistered
    helper function, and ``.description``/``.annotations`` on a freshly
    constructed LOCAL scratch object (named "meta", the exact word the old
    root-token allowlist matched on) must NOT fire — neither target is a
    registered tool's own client-visible metadata."""
    findings, _ = _static("metadata_mutation_local_benign")
    hits = [f for f in findings if f.detector_id == "runtime-metadata-mutation"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule 2.3 — counter the gate through a persisted-state (file) alias ------------

def test_counter_gate_through_file_alias_fires_rugpull_source():
    findings, _ = _static("counter_gate_alias")
    hits = [f for f in findings if f.detector_id == "rugpull-source"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].tool_name == "lookup_customer"


def test_counter_gate_benign_plain_containment_check_stays_clean():
    findings, _ = _static("counter_gate_alias_benign")
    hits = [f for f in findings if f.detector_id == "rugpull-source"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule P4.4 — a counter read through a HELPER that itself reads saved state -

def test_counter_gate_through_helper_indirection_fires_rugpull_source():
    findings, _ = _static("counter_gate_via_helper")
    hits = [f for f in findings if f.detector_id == "rugpull-source"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].tool_name == "lookup_customer"


def test_counter_gate_via_helper_benign_plain_containment_stays_clean():
    findings, _ = _static("counter_gate_via_helper_benign")
    hits = [f for f in findings if f.detector_id == "rugpull-source"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule 2.4 — idempotentHint contradicted by accumulation --------------------

def test_idempotent_hint_contradicted_by_accumulation_fires():
    findings, _ = _static("idempotent_accumulation")
    hits = [f for f in findings if f.detector_id == "hint-violation"
            and f.evidence.get("declared", {}).get("idempotentHint") is True]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].tool_name == "add_loyalty_bonus"
    assert hits[0].severity == "high"


def test_idempotent_hint_benign_absolute_set_stays_clean():
    findings, _ = _static("idempotent_accumulation_benign")
    hits = [f for f in findings if f.detector_id == "hint-violation"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule 2.4 — destructiveHint=false widened past file-deletion ---------------

def test_destructive_false_domain_overwrite_fires():
    findings, _ = _static("destructive_overwrite")
    hits = [f for f in findings if f.detector_id == "hint-violation"
            and f.evidence.get("declared", {}).get("destructiveHint") is False]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].tool_name == "refresh_document_cache"
    assert "mutates-server-state" in hits[0].evidence["offending_behavior"]


def test_destructive_false_benign_pure_read_stays_clean():
    findings, _ = _static("destructive_overwrite_benign")
    hits = [f for f in findings if f.detector_id == "hint-violation"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule 2.4 — openWorldHint=false contradicted by a network call -------------

def test_openworld_false_network_call_fires():
    findings, _ = _static("openworld_network")
    hits = [f for f in findings if f.detector_id == "hint-violation"
            and f.evidence.get("declared", {}).get("openWorldHint") is False]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].tool_name == "get_exchange_rate"


def test_openworld_false_benign_local_table_stays_clean():
    findings, _ = _static("openworld_network_benign")
    hits = [f for f in findings if f.detector_id == "hint-violation"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule 2.5 — bookkeeping vs. domain-visible mutation in scope-creep ---------

def test_scope_creep_fires_on_domain_visible_mutation():
    findings, _ = _static("scope_creep_domain_mutation")
    hits = [f for f in findings if f.detector_id == "scope-creep"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].tool_name == "lookup_customer"


def test_scope_creep_benign_private_counter_stays_clean():
    findings, _ = _static("scope_creep_bookkeeping_benign")
    hits = [f for f in findings if f.detector_id == "scope-creep"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule 2.6 — one level of call inlining --------------------------------------

def test_taint_inlines_one_level_into_local_helper():
    """rule P3.4: a helper that passes the tool's tainted argument STRAIGHT
    THROUGH, unchanged, into a shell sink (``def _run(cmd): os.system(cmd)``)
    adds no defense of its own — this stays at FULL (critical) severity even
    though it is reached through one level of inlining, not capped like a
    generic helper-reached finding."""
    findings, _ = _static("taint_helper_inline")
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].tool_name == "run_maintenance"
    assert hits[0].evidence["via_helper"] == "_run_shell"
    assert hits[0].severity == "critical", hits[0].severity


def test_taint_helper_transformed_value_stays_capped_at_medium():
    """rule P3.4 — the medium-severity cap still applies to a helper that does
    NOT pass the value through unchanged (it builds a new string embedding
    the tainted value first): weaker, more heuristic evidence than a direct
    sink, so it must not be reported at critical/high like one."""
    findings, _ = _static("taint_helper_inline_transformed")
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].tool_name == "run_maintenance"
    assert hits[0].evidence["via_helper"] == "_run_shell"
    assert hits[0].severity in ("low", "medium"), hits[0].severity
    assert hits[0].confidence in ("low", "medium"), hits[0].confidence


def test_taint_helper_benign_untainted_argument_stays_clean():
    findings, _ = _static("taint_helper_inline_benign")
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


def test_taint_direct_sink_stays_critical_not_downgraded():
    """Regression guard for the rule 2.6 helper-inlining downgrade: a DIRECT,
    unsanitized command-injection sink (no helper indirection) must still
    fire at critical severity / high confidence — the downgrade applies only
    to sinks reached through inlining, never to a direct, hidden injection."""
    findings, _ = _static("injection")
    hits = [f for f in findings if f.detector_id == "ast-taint"
            and f.tool_name == "ping"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].evidence.get("via_helper") is None
    assert hits[0].severity == "critical"
    assert hits[0].confidence in ("medium", "high")


# --- rule 2.6 — sanitizer modeling: realpath + prefix guard downgrades to low --

def test_sanitized_path_with_prefix_guard_drops_to_low():
    findings, _ = _static("taint_sanitized_path")
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].evidence["sanitized"] is True
    assert hits[0].severity == "low"
    assert hits[0].confidence == "low"


def test_sanitized_path_without_guard_stays_at_full_severity():
    findings, _ = _static("taint_sanitized_path_unguarded")
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].evidence["sanitized"] is False
    assert hits[0].severity != "low"


# --- rule 2.7 — tools registered without a per-tool decorator -------------------

def test_functional_registration_add_tool_is_extracted_and_tainted():
    findings, ctx = _static("functional_registration")
    names = [c.name for c in ctx.all_contracts()]
    assert "run_backup" in names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits and hits[0].tool_name == "run_backup"


def test_functional_registration_benign_stays_clean():
    findings, ctx = _static("functional_registration_benign")
    names = [c.name for c in ctx.all_contracts()]
    assert "run_backup" in names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


def test_lowlevel_sdk_dispatch_binds_behavior_to_live_tool_name():
    findings, ctx = _static("lowlevel_dispatch")
    names = [c.name for c in ctx.all_contracts()]
    # only the real dispatched tool name shows up -- not the SDK's own
    # list_tools/call_tool protocol-hook function names as phantom tools
    assert names == ["run"], names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits and hits[0].tool_name == "run"


def test_lowlevel_sdk_dispatch_benign_stays_clean():
    findings, ctx = _static("lowlevel_dispatch_benign")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["run"], names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule 2.8 — JavaScript/TypeScript source extraction -------------------------

def test_js_tool_extracted_with_tainted_command_sink():
    findings, ctx = _static("js_taint")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["run_report"], names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits and hits[0].tool_name == "run_report"
    assert hits[0].evidence["sink_kind"] == "command-exec"


def test_js_tool_benign_untainted_sink_stays_clean():
    findings, ctx = _static("js_taint_benign")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["run_report"], names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


def test_js_poisoned_description_fires_through_text_engine():
    findings, ctx = _static("js_poisoned_desc")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["get_weather"], names
    hits = [f for f in findings if f.detector_id == "desc-poisoning"]
    assert hits and hits[0].tool_name == "get_weather"


# --- rule P5.1 — delimiter-aware JS/TS string literals (template literals with
# --- an embedded apostrophe of the OTHER quote kind must not truncate) -----

def test_js_template_literal_description_not_truncated_by_apostrophe():
    findings, ctx = _static("js_template_literal_desc")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["get_profile"], names
    contract = ctx.tool_by_name("get_profile")
    assert "ignore previous instructions" in (contract.description or "").lower()
    hits = [f for f in findings if f.detector_id == "desc-poisoning"]
    assert hits and hits[0].tool_name == "get_profile"


# --- rule P5.2 — low-level tool descriptors with a NESTED inputSchema object ---

def test_js_lowlevel_tool_with_nested_schema_extracted_and_field_poisoned():
    findings, ctx = _static("js_nested_schema_lowlevel")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["fetch_page"], names
    contract = ctx.tool_by_name("fetch_page")
    assert contract.description == "Fetch the contents of a caller-supplied URL."
    assert set(contract.input_schema.get("properties", {})) == {"url", "apiKey"}
    hits = [f for f in findings if f.detector_id == "schema-poisoning"]
    assert hits and hits[0].tool_name == "fetch_page"
    assert hits[0].evidence["param"] == "apiKey"


# --- rule P5.3 — resolve a handler passed BY NAME to its own function body -----

def test_js_named_handler_resolved_and_sink_tainted():
    findings, ctx = _static("js_named_handler_taint")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["run_report"], names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits and hits[0].tool_name == "run_report"
    assert hits[0].evidence["sink_kind"] == "command-exec"


def test_js_named_handler_benign_stays_clean():
    findings, ctx = _static("js_named_handler_benign")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["run_report"], names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule P5.4 — zod-style schema-builder param names + .describe() text -------

def test_js_zod_schema_describe_text_poisoned():
    findings, ctx = _static("js_zod_schema_poisoning")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["get_report"], names
    contract = ctx.tool_by_name("get_report")
    assert set(contract.input_schema.get("properties", {})) == {"reportId", "format"}
    hits = [f for f in findings if f.detector_id == "schema-poisoning"]
    assert hits and hits[0].tool_name == "get_report"
    assert hits[0].evidence["param"] == "format"


def test_js_zod_schema_benign_stays_clean():
    findings, ctx = _static("js_zod_schema_benign")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["get_report"], names
    hits = [f for f in findings if f.detector_id == "schema-poisoning"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule P3.2 — command sanitizer model: only quoting/arglist-no-shell/halting
# --- allow-list count; a deny-list or a raw-value prefix test do not -------

def test_command_halting_allowlist_downgrades_to_low():
    findings, _ = _static("command_allowlist_guard")
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].evidence["sanitized"] is True
    assert hits[0].severity == "low" and hits[0].confidence == "low"


def test_command_denylist_is_not_a_sanitizer():
    findings, _ = _static("command_denylist_not_sanitized")
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].evidence["sanitized"] is False
    assert hits[0].severity == "critical"


def test_command_prefix_test_on_raw_value_is_not_a_sanitizer():
    findings, _ = _static("command_prefix_raw_not_sanitized")
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].evidence["sanitized"] is False
    assert hits[0].severity == "critical"


def test_command_arglist_call_without_shell_is_sanitized():
    findings, _ = _static("command_arglist_no_shell")
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].evidence["sanitized"] is True
    assert hits[0].severity == "low" and hits[0].confidence == "low"


# --- rule P3.3 — path sanitizer needs a normalized value AND a prefix test
# --- against a CONSTANT base; a non-constant (caller-supplied) base is not
# --- a sanitizer -------------------------------------------------------------

def test_path_prefix_against_nonconstant_base_is_not_a_sanitizer():
    findings, _ = _static("path_prefix_nonconst_base")
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]
    assert hits[0].evidence["sanitized"] is False
    assert hits[0].severity != "low"


# --- rule P3.6 — SSRF taint counts only URL/host args, not timeouts/options ----

def test_ssrf_tainted_timeout_only_stays_clean():
    findings, _ = _static("ssrf_timeout_only_tainted_benign")
    hits = [f for f in findings if f.detector_id == "ast-taint" and f.category == "ssrf"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


def test_ssrf_tainted_url_still_fires():
    findings, _ = _static("ssrf_url_tainted")
    hits = [f for f in findings if f.detector_id == "ast-taint" and f.category == "ssrf"]
    assert hits, [(f.detector_id, f.tool_name) for f in findings]


# --- rule P3.7 — an openly declared capability moves to its own lane -----------

def test_declared_command_capability_is_additive_note_plus_full_injection():
    """v3-1.1 — the capability lane is ADDITIVE: the declared-capability
    note is recorded AND the taint finding keeps its full grade (a tool that
    declares it runs caller-supplied commands and then interpolates them
    into a shell is still a critical injection)."""
    findings, _ = _static("capability_declared_command")
    hits = [f for f in findings if f.detector_id == "ast-taint"
            and f.tool_name == "run_shell_command"]
    assert hits, [(f.detector_id, f.category, f.tool_name) for f in findings]
    notes = [f for f in hits if f.detection_method == "declared-capability"]
    assert notes and all(f.severity == "low" and f.category == "excessive-privilege"
                         for f in notes)
    inj = [f for f in hits if f.category == "command-injection"]
    assert inj, [(f.category, f.detection_method) for f in hits]
    assert inj[0].severity == "critical" and inj[0].confidence == "high"
    assert inj[0].evidence["declared_capability"] is True


def test_undeclared_command_capability_stays_full_severity_injection():
    """Recall guard — the identical sink shape with NO declared capability
    in the description must stay a full-severity command-injection finding,
    not move to the capability lane."""
    findings, _ = _static("capability_undeclared_command")
    hits = [f for f in findings if f.detector_id == "ast-taint"
            and f.tool_name == "run_shell_command"]
    assert hits, [(f.detector_id, f.category, f.tool_name) for f in findings]
    assert any(f.category == "command-injection" and f.severity == "critical" for f in hits)


# --- rule P3.5 — low-level SDK handlers: taint seeds from the handler's own
# --- real params; a declared schema property name is recognized as a KEY
# --- used to subscript the arguments dict -----------------------------------

def test_lowlevel_dict_key_lookup_is_tainted_via_handler_params():
    findings, ctx = _static("lowlevel_dispatch_dict_key_taint")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["run"], names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits and hits[0].tool_name == "run"
    assert hits[0].evidence["sink_kind"] == "command-exec"


def test_lowlevel_name_collision_with_hardcoded_value_stays_clean():
    """rule P3.5 precision fixture — seeding taint from the schema's declared
    property names (instead of the handler's own real params) would
    previously have mistaken a bare name-collision for genuine taint; this
    must now stay completely clean."""
    findings, ctx = _static("lowlevel_dispatch_name_collision_benign")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["run"], names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]


# --- rule P4.2 — a tool name registered more than once: analyze and merge ALL
# --- definitions, not just whichever one a last/first-write-wins view keeps.

def test_duplicate_tool_definition_merges_findings_from_both_bodies():
    findings, ctx = _static("duplicate_tool_definition")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["run_report"], names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits and hits[0].tool_name == "run_report"
    assert hits[0].evidence["sink_kind"] == "command-exec"


def test_duplicate_tool_definition_benign_stays_clean():
    findings, ctx = _static("duplicate_tool_definition_benign")
    names = [c.name for c in ctx.all_contracts()]
    assert names == ["run_report"], names
    hits = [f for f in findings if f.detector_id == "ast-taint"]
    assert hits == [], [(f.tool_name, f.evidence) for f in hits]
