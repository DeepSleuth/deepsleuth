"""rule 5.1 — poisoned descriptions / instructions-in-metadata, and obfuscation.

Runs the normalized mechanism rule engine (analysis.textrules) over every tool /
resource / prompt description, over each schema-field description, and over names.
Fires on the *mechanism* (agent-directed imperatives, concealment, exfiltration,
preference steering, gratuitous secret references) — not on any fixed phrase — and
separately flags *obfuscation* (zero-width/bidi/homoglyph/encoded/comment) as a
concealment mechanism in its own right, regardless of what it decodes to.
"""
from __future__ import annotations

from typing import List, Tuple

from ..analysis.textrules import RuleResult, analyze_text
from ..context import (ScanContext, ToolContract, contract_descriptions,
                       listing_entry_strings, listing_path_under_schema,
                       step_down_confidence)
from ..models import Finding
from ..normalize import is_probably_non_english
from .base import CAP_MANIFEST, Detector, register
from ._util import mk

DECISIVE = {"override_instructions", "concealment", "exfiltration",
            "next_action_redirect"}


def _listing_kind(ctx: ScanContext) -> str:
    return "dynamic-runtime" if "dynamic" in ctx.layers else "static-manifest"


def _grade(rr: RuleResult) -> Tuple[bool, str, str, str]:
    """Return (fire, severity, confidence, primary_family)."""
    fams = set(rr.families)
    primary = ""
    if fams:
        # pick highest-weight family for the label
        order = ["override_instructions", "exfiltration", "next_action_redirect",
                 "concealment", "read_sensitive", "data_supersession",
                 "preference_manipulation", "agent_directive", "sensitive_reference"]
        for f in order:
            if f in fams:
                primary = f
                break
    total = rr.total
    decisive = bool(fams & DECISIVE)
    if decisive:
        return True, "high", "high", primary
    if total >= 6:
        return True, "high", "high", primary or "combined"
    if total >= 4:
        return True, "high", "medium", primary or "combined"
    if total >= 3:
        return True, "medium", "medium", primary or "combined"
    return False, "none", "low", primary


def _self_description_note(ctx: ScanContext, c: ToolContract, rr: RuleResult, kind: str,
                           evidence_location: str, detector_id: str, extra: dict) -> Finding:
    """v5-1 — an exfiltration / secret-store verb used in DESCRIPTIVE voice
    (the tool stating its own function) is reported as an informational
    note: visible, never actionable."""
    fams = sorted(rr.informational)
    cat = "tool-poisoning" if c.kind == "tool" else "agent-config-poisoning"
    evidence = {"informational_families": rr.informational, "voice": "descriptive"}
    evidence.update(extra)
    return mk(
        ctx, detector_id=detector_id, category=cat,
        evidence_location=evidence_location, severity="low", confidence="low",
        detection_method="self-description-voice",
        rationale=(f"{c.kind} '{c.name}' uses a {'/'.join(fams)} verb as the MAIN verb "
                   "of a sentence whose implicit subject is the tool itself (third-person "
                   "singular, an opening imperative, or after \"this tool\"/\"it\"), with "
                   "no agent addressee, obligation/sequence word, appended second action "
                   "or sensitive/unrequested object -- the tool describing its own "
                   "function, not an instruction to the agent. Informational: the "
                   "capability is declared, not hidden."),
        evidence=evidence, source_kind=kind, tool_name=c.name,
        raw={"informational": True, "voice": "descriptive"},
    )


def _analyze_contract_text(ctx: ScanContext, c: ToolContract) -> List[Finding]:
    findings: List[Finding] = []
    kind = _listing_kind(ctx)

    # 1) description body — v3-4.3: EVERY description this contract
    # carries (a module that registers the same tool name twice contributes
    # each definition's own description), not only the one that was kept.
    for desc_text in contract_descriptions(c):
        # v5-1 — the text IS a description: the exfiltration / secret-store
        # families separate the tool describing its own function
        # (descriptive voice -> informational) from a directive.
        rr = analyze_text(desc_text or "", voice="description", subject_name=c.name)
        fire, sev, conf, primary = _grade(rr)
        if not fire and rr.informational:
            findings.append(_self_description_note(
                ctx, c, rr, kind, "description", "desc-poisoning",
                {"description_excerpt": (desc_text or "")[:400]}))
        if fire:
            cat = "tool-poisoning" if c.kind == "tool" else "agent-config-poisoning"
            findings.append(mk(
                ctx, detector_id="desc-poisoning", category=cat,
                evidence_location="description", severity=sev,
                detection_method="normalized-mechanism-rules", confidence=conf,
                rationale=(f"{c.kind} description contains agent-directed instruction "
                           f"mechanism(s) [{primary}] that a description has no "
                           f"legitimate reason to carry."
                           + ("" if desc_text == (c.description or "") else
                              " (Found in a DUPLICATE definition's description of the "
                              "same tool name — the module registers this name more "
                              "than once, v3-4.3.)")),
                evidence={"families": rr.families,
                          "matched_snippets": rr.families,
                          "score": rr.total,
                          "description_excerpt": (desc_text or "")[:400],
                          **({"self_description_families": rr.informational}
                             if rr.informational else {})},
                source_kind=kind, tool_name=c.name,
                raw={"anomaly_flags": rr.anomaly_flags,
                     "obfuscation_flags": rr.obfuscation_flags},
            ))

        # 2) obfuscation in description (concealment of form) — independent signal
        if rr.obfuscation_flags:
            hard = {"zero-width-characters", "bidi-control-characters",
                    "homoglyph-characters", "encoded-blob-decoded"} & set(rr.obfuscation_flags)
            sev2 = "high" if hard else "medium"
            cat = "tool-poisoning" if c.kind == "tool" else "agent-config-poisoning"
            findings.append(mk(
                ctx, detector_id="desc-obfuscation", category=cat,
                evidence_location="description", severity=sev2,
                detection_method="obfuscation-scan", confidence="high" if hard else "medium",
                rationale=("Description hides content via "
                           f"{', '.join(sorted(rr.obfuscation_flags))} — concealment in "
                           "metadata the agent reads is itself a poisoning mechanism."),
                evidence={"obfuscation_flags": sorted(rr.obfuscation_flags),
                          "decoded_segments": rr.norm.decoded_segments[:5]},
                source_kind=kind, tool_name=c.name,
            ))

    # 3) schema-field descriptions + suspicious param names
    props = (c.input_schema or {}).get("properties") or {}
    if isinstance(props, dict):
        for pname, pspec in props.items():
            if not isinstance(pspec, dict):
                continue
            pdesc = pspec.get("description") or ""
            if not isinstance(pdesc, str):
                continue
            rrp = analyze_text(pdesc, voice="field", subject_name=c.name)
            firep, sevp, confp, primaryp = _grade(rrp)
            if not firep and rrp.informational:
                findings.append(_self_description_note(
                    ctx, c, rrp, kind, "schema", "schema-poisoning",
                    {"param": pname, "field_description_excerpt": pdesc[:300]}))
            if firep:
                findings.append(mk(
                    ctx, detector_id="schema-poisoning", category="tool-poisoning",
                    evidence_location="schema", severity=sevp,
                    detection_method="normalized-mechanism-rules", confidence=confp,
                    rationale=(f"Schema field '{pname}' description carries an "
                               f"agent-directed instruction mechanism [{primaryp}]."),
                    evidence={"param": pname, "families": rrp.families,
                              "field_description_excerpt": pdesc[:300]},
                    source_kind=kind, tool_name=c.name,
                ))

    # 3b) v5-6 — every OTHER string of the live listing entry: annotations,
    # titles, examples, output-schema descriptions, enum descriptions,
    # vendor/extension fields, nested input-schema descriptions, at any
    # depth. A standard description slot (a ``description`` inside the input
    # schema, a prompt argument's ``description``) keeps the full grade; a
    # hit in any other field is one confidence step lower. The JSON path is
    # the evidence.
    try:
        extra_strings = listing_entry_strings(c)
    except Exception:
        extra_strings = []  # a malformed entry never costs the description its scan
    for json_path, ftext, standard in extra_strings:
        # a ``title`` is the entry's own one-line function statement, so the
        # opening-imperative voice of a description applies to it; every
        # other field is read like a schema-field description.
        last_key = json_path.rsplit(".", 1)[-1].split("[", 1)[0]
        rrf = analyze_text(ftext, voice="description" if last_key == "title" else "field",
                           subject_name=c.name)
        firef, sevf, conff, primaryf = _grade(rrf)
        if not standard and not rrf.families:
            # an example / default / enum value may honestly carry an encoded
            # sample payload: outside a description slot only a MECHANISM
            # family (read from the text or from what a blob decodes to)
            # fires, never the bare "contains an encoded blob" score.
            firef = False
        under_schema = listing_path_under_schema(json_path)
        ev_loc = "schema" if under_schema else "description"
        cat = "tool-poisoning" if c.kind == "tool" else "agent-config-poisoning"
        if firef:
            graded = conff if standard else step_down_confidence(conff)
            findings.append(mk(
                ctx, detector_id="schema-poisoning" if under_schema else "desc-poisoning",
                category=cat, evidence_location=ev_loc, severity=sevf, confidence=graded,
                detection_method=("normalized-mechanism-rules" if standard
                                  else "listing-field-rules"),
                rationale=(f"{c.kind} '{c.name}' listing field '{json_path}' carries an "
                           f"agent-directed instruction mechanism [{primaryf}]. Every "
                           "string of a listing entry is text the agent may read, not "
                           "only its description."
                           + ("" if standard else
                              " The field is not a standard description slot, so the "
                              "hit is graded one confidence step lower than the same "
                              "text in the description would be.")),
                evidence={"json_path": json_path,
                          "field_class": "standard" if standard else "non-standard",
                          "families": rrf.families, "score": rrf.total,
                          "field_excerpt": ftext[:300]},
                source_kind=kind, tool_name=c.name,
                raw={"listing_field": json_path, "ungraded_confidence": conff},
            ))
        hidden = {"zero-width-characters", "bidi-control-characters"} & set(rrf.obfuscation_flags)
        if hidden:
            findings.append(mk(
                ctx, detector_id="desc-obfuscation", category=cat,
                evidence_location=ev_loc, severity="high",
                confidence="high" if standard else "medium",
                detection_method="obfuscation-scan",
                rationale=(f"Listing field '{json_path}' hides content via "
                           f"{', '.join(sorted(hidden))} — concealment in metadata the "
                           "agent reads is itself a poisoning mechanism."),
                evidence={"json_path": json_path, "obfuscation_flags": sorted(hidden),
                          "field_class": "standard" if standard else "non-standard"},
                source_kind=kind, tool_name=c.name,
                raw={"listing_field": json_path},
            ))

    # 4) name obfuscation
    nr = analyze_text(c.name or "")
    if nr.obfuscation_flags and ({"zero-width-characters", "bidi-control-characters",
                                  "homoglyph-characters"} & set(nr.obfuscation_flags)):
        findings.append(mk(
            ctx, detector_id="name-obfuscation", category="tool-poisoning",
            evidence_location="name", severity="high", confidence="high",
            detection_method="obfuscation-scan",
            rationale="Tool name contains unicode confusable/invisible characters — "
                      "a spoofing/impersonation mechanism.",
            evidence={"name": c.name, "obfuscation_flags": sorted(nr.obfuscation_flags)},
            source_kind=kind, tool_name=c.name,
        ))
    return findings


def _run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    noted = set()
    for c in ctx.all_contracts():
        try:
            out.extend(_analyze_contract_text(ctx, c))
            # rule 4.4 — a description not primarily in English gets a REDUCED-
            # COVERAGE note, not a silent pass and not a flagged finding: the
            # text-rule vocabulary is English-only and may miss (or, for a
            # mixed-script word, over-read) a real mechanism written in
            # another language.
            if c.name not in noted and is_probably_non_english(c.description or ""):
                noted.add(c.name)
                ctx.skipped.append(
                    f"reduced text-rule coverage: {c.kind} '{c.name}' description "
                    "is not primarily English-script text -- the description/"
                    "schema pattern rules are English-vocabulary-only."
                )
        except Exception:
            continue
    return out


register(Detector(
    id="desc-poisoning",
    category="tool-poisoning",
    evidence_location="description",
    phase="listing",
    run=_run,
    requires={CAP_MANIFEST},
    rationale=(
        "A tool/resource/prompt description is metadata the agent reads to decide "
        "what to do; agent-directed imperatives, concealment directives, "
        "exfiltration language, preference steering or gratuitous secret references "
        "in that text are the classic tool-poisoning mechanism. Detected over a "
        "unicode/encoding-normalized representation so paraphrases and obfuscation "
        "do not defeat it."
    ),
))
