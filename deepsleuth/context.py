"""The frontend-agnostic detection Context.

Both frontends feed detectors the *same* object shape. Detectors are pure
functions over a ``ScanContext``; the only difference between frontends is how the
context is populated:

* Frontend B (batch/sandbox) synthesizes calls in a Docker sandbox and fills the
  context all at once, then runs every phase.
* Frontend A (inline proxy) fills the context incrementally from real traffic and
  runs each phase at its interposition point.

Also home to the deterministic **canary** machinery and the **cross-call state
tracker** (rule 4.3, rule 5.5), which are shared by both frontends.
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .analysis.crossmodule import LocalModuleIndex, augment_facts
from .analysis.jsast import extract_js_tools
from .analysis.pyast import (
    BehaviorFacts,
    ToolDef,
    analyze_tool_function,
    collect_dict_literal_keys,
    collect_module_functions,
    collect_module_instance_methods,
    extract_tools,
    extract_tools_all,
    find_duplicate_tool_defs,
    merge_behavior_facts,
    parse_module,
    _collect_module_globals,
    _collect_str_consts,
    _collect_stub_true_functions,
)
from .models import SourceFile, Target

# --- phases -------------------------------------------------------------------
PHASE_LISTING = "tool listing"        # metadata/source/package detectors
PHASE_PRECALL = "precall"        # gate detectors, before a tools/call
PHASE_RESPONSE = "response"      # response-scan detectors
PHASE_MULTICALL = "multicall"    # cross-call / rug-pull diff detectors
ALL_PHASES = (PHASE_LISTING, PHASE_PRECALL, PHASE_RESPONSE, PHASE_MULTICALL)


# --- canaries -----------------------------------------------------------------
CANARY_PREFIX = "MCPSCANCANARY"


def _h(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


class CanaryFactory:
    """Deterministic, inert canary tokens. Never random — same input, same token
    (hard constraint rule 3.3). Some canaries are *secret-shaped* so a tool that
    exfiltrates or over-shares them is caught, and some are file-content markers
    the sandbox seeds at sensitive paths."""

    def arg(self, tool: str, param: str, idx: int = 0) -> str:
        return f"{CANARY_PREFIX}-ARG-{_h(tool, param, str(idx))}"

    def secret(self, kind: str, tool: str = "", param: str = "") -> str:
        base = _h("secret", kind, tool, param)
        # secret-shaped, but always carrying CANARY_PREFIX so our own inert
        # canaries can be excluded from credential-shape response scans.
        shapes = {
            "aws": f"AKIA{CANARY_PREFIX}{base.upper()}",
            "token": f"sk-{CANARY_PREFIX.lower()}-{base}",
            "password": f"{CANARY_PREFIX}Pw!{base}",
        }
        return shapes.get(kind, f"{CANARY_PREFIX}-SECRET-{base}")

    # markers seeded into decoy files inside the sandbox filesystem
    def file_marker(self, path_label: str) -> str:
        return f"{CANARY_PREFIX}-FILE-{_h('file', path_label)}"

    @staticmethod
    def is_canary(value: str) -> bool:
        # case-insensitive: the "token" secret shape deliberately lowercases
        # the prefix (real API tokens/keys are lowercase-shaped, e.g.
        # "sk-...") to look realistic — a case-sensitive check here silently
        # made every token-shaped canary invisible to cross-call leak
        # detection (Part-A.1 v4 recall regression), which is exactly the
        # canary shape synthesized for any secret/token/api_key-named
        # parameter (sandbox.argsynth._SECRET_HINT), i.e. a very common real
        # case.
        return isinstance(value, str) and CANARY_PREFIX.lower() in value.lower()


CANARIES = CanaryFactory()


@dataclass
class CanaryOrigin:
    value: str
    tool: str
    param: str
    seq: int
    kind: str  # arg | secret | file


class CrossCallState:
    """Tracks planted canaries across calls so a value injected into call A can be
    caught surfacing in the response of call B (rule 5.5a)."""

    def __init__(self) -> None:
        self.origins: Dict[str, CanaryOrigin] = {}  # value -> where first planted
        self.file_markers: Dict[str, str] = {}      # value -> decoy path label

    def register_file_markers(self, markers: Dict[str, str]) -> None:
        self.file_markers.update(markers)

    def note_call_args(self, seq: int, tool: str, arguments: Any) -> None:
        for value, param in _walk_strings(arguments):
            if CanaryFactory.is_canary(value) and value not in self.origins:
                kind = "secret" if "-SECRET-" in value or "AKIA" in value or value.startswith("sk-") else "arg"
                self.origins[value] = CanaryOrigin(value, tool, param, seq, kind)

    def scan_response(self, seq: int, tool: str, response_text: str,
                      this_call_args: Any) -> List[Dict[str, Any]]:
        """Return leakage records: planted canaries appearing in a response that
        did not originate from *this* call."""
        leaks: List[Dict[str, Any]] = []
        args_values = {v for v, _ in _walk_strings(this_call_args)}
        for value, origin in self.origins.items():
            if value in response_text and value not in args_values:
                leaks.append({
                    "canary": value,
                    "origin_tool": origin.tool,
                    "origin_param": origin.param,
                    "origin_seq": origin.seq,
                    "surfaced_in_tool": tool,
                    "surfaced_in_seq": seq,
                    "kind": origin.kind,
                })
        # decoy-file content surfacing = sensitive-file read/exfil
        for marker, label in self.file_markers.items():
            if marker in response_text:
                leaks.append({
                    "canary": marker,
                    "origin_tool": "<sandbox-decoy-file>",
                    "origin_param": label,
                    "origin_seq": -1,
                    "surfaced_in_tool": tool,
                    "surfaced_in_seq": seq,
                    "kind": "file",
                })
        return leaks


# --- tool contract & call records --------------------------------------------


@dataclass
class SourceFacts:
    tool_def: ToolDef
    facts: BehaviorFacts
    module_path: str


@dataclass
class ToolContract:
    name: str
    tool description: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)
    hints: Dict[str, Any] = field(default_factory=dict)
    kind: str = "tool"  # tool | resource | prompt
    source: Optional[SourceFacts] = None  # bound implementation facts, if found
    # v5-6 — the listing entry exactly as the server sent it (live
    # tools/resources/prompts list, or a reference listing). Every string in
    # it is text the agent may read; ``listing_entry_strings`` walks it.
    raw_entry: Optional[Dict[str, Any]] = None

    def declared_readonly(self) -> Optional[bool]:
        v = self.hints.get("readOnlyHint")
        return v if isinstance(v, bool) else None

    def declared_destructive(self) -> Optional[bool]:
        v = self.hints.get("destructiveHint")
        return v if isinstance(v, bool) else None


@dataclass
class CallRecord:
    seq: int
    tool_name: str
    arguments: Dict[str, Any]
    response_text: str = ""
    response_obj: Any = None
    is_error: bool = False


# --- the shared Context -------------------------------------------------------


@dataclass
class ScanContext:
    target: Target
    server_info: Optional[Dict[str, Any]] = None
    tools: List[ToolContract] = field(default_factory=list)
    resources: List[ToolContract] = field(default_factory=list)
    prompts: List[ToolContract] = field(default_factory=list)
    # for rug-pull diffing: a later re-listing
    tools_relisted: Optional[List[ToolContract]] = None
    calls: List[CallRecord] = field(default_factory=list)
    state: CrossCallState = field(default_factory=CrossCallState)
    # source material
    source_modules: List[Tuple[str, Any, str, set]] = field(default_factory=list)
    package_manifests: Dict[str, str] = field(default_factory=dict)
    # which layers actually ran
    layers: set = field(default_factory=set)  # {"manifest","source","dynamic","package"}
    skipped: List[str] = field(default_factory=list)
    # a single pending call (proxy pre-call phase)
    pending_call: Optional[CallRecord] = None

    def tool_by_name(self, name: str) -> Optional[ToolContract]:
        for t in self.tools:
            if t.name == name:
                return t
        return None

    def all_contracts(self) -> List[ToolContract]:
        return list(self.tools) + list(self.resources) + list(self.prompts)


def contract_descriptions(c: ToolContract) -> List[str]:
    """Every description text this contract carries: the primary
    one plus (when source registered the same tool name more than once) each
    other duplicate definition's own distinct description, so the description
    rules run over ALL of them, not only the definition that was kept."""
    out = [c.description or ""]
    td = c.source.tool_def if (c.source is not None and c.source.tool_def is not None) else None
    for d in (getattr(td, "alt_descriptions", None) or []):
        if d and d not in out:
            out.append(d)
    return out


# --- helpers ------------------------------------------------------------------


def _walk_strings(obj: Any, path: str = "") -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if isinstance(obj, str):
        out.append((obj, path or "<root>"))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_walk_strings(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            out.extend(_walk_strings(v, f"{path}[{i}]"))
    return out


def build_source_facts(source_files: List[SourceFile]) -> Dict[str, SourceFacts]:
    """Parse every Python source file, extract tools, and compute behavior facts.
    Returns a map tool-name -> SourceFacts (last write wins on collision)."""
    result: Dict[str, SourceFacts] = {}
    # v6-W7 — an index of the target's own Python modules, so a tool that
    # delegates to a helper in another module of the same directory is
    # analyzed together with that helper.
    mod_index = LocalModuleIndex(source_files)
    for sf in source_files:
        if sf.language in ("javascript", "typescript"):
            # rule 2.8 — JS/TS extraction: tool name/description and
            # child_process/fs/network sinks, text-scanned (no AST).
            try:
                for td, facts in extract_js_tools(sf.text):
                    result[td.name] = SourceFacts(tool_def=td, facts=facts, module_path=sf.path)
            except Exception:
                pass
            continue
        if sf.language != "python":
            continue
        tree = parse_module(sf.text)
        if tree is None:
            continue
        module_globals = _collect_module_globals(tree)
        stub_true_funcs = _collect_stub_true_functions(tree)
        module_consts = _collect_str_consts(tree)
        module_functions = collect_module_functions(tree)
        instance_methods = collect_module_instance_methods(tree)  # v3-4.5
        # v6-W7 — same-directory imports: their functions join the callee
        # registries (entry-module names win), their constants join the
        # constant environment (``_gate.NOTICE`` / ``from _gate import NOTICE``).
        entry_info = mod_index.info(sf.path)
        if entry_info is not None:
            try:
                imp_funcs, imp_methods = mod_index.registries(entry_info)
                module_functions = {**imp_funcs, **module_functions}
                instance_methods = {**imp_methods, **instance_methods}
                module_consts = mod_index.const_env(entry_info)
            except Exception:
                entry_info = None
        dict_literal_keys = collect_dict_literal_keys(tree)  # rule 3.2
        # rule 2.7 — includes tools registered without a per-tool decorator
        # (functional registration, low-level SDK list_tools/call_tool).
        tool_defs = extract_tools_all(tree)
        # rule 2.2 (FP fix) — every REGISTERED tool's own function name in this
        # module, so ``<name>.__doc__ = ...`` is only a rug-pull signal when
        # ``<name>`` actually is a registered tool (see
        # ``_looks_like_tool_metadata_target``).
        registered_tool_names = {td.func_name for td in tool_defs if td.func_name}
        for td in tool_defs:
            if td.node is None:
                # description-only (a list_tools literal with no matching
                # call_tool branch found): still worth a contract entry for
                # desc-poisoning/out-of-scope-param, just no behavior facts.
                result[td.name] = SourceFacts(
                    tool_def=td, facts=BehaviorFacts(), module_path=sf.path)
                continue
            # rule 2.6 — the tool's own function is never inlined into itself
            helper_registry = {n: f for n, f in module_functions.items() if n != td.func_name}
            try:
                # rule P3.5 — seed taint with the node's REAL parameters
                # (``td.taint_params``, e.g. a low-level handler's own
                # ``name``/``arguments``), falling back to ``td.params`` for
                # every ordinary extraction path where they are the same
                # thing; ``declared_params`` keeps ``td.params`` (the
                # DECLARED schema contract) for unused-parameter/auth
                # reasoning regardless of which one seeded taint.
                seed_params = td.taint_params or td.params
                facts = analyze_tool_function(td.node, seed_params, module_globals, sf.text,
                                              stub_true_funcs, module_consts, helper_registry,
                                              dict_literal_keys, registered_tool_names,
                                              declared_params=td.params,
                                              instance_methods=instance_methods,
                                              module_tree=tree)
            except Exception:
                facts = BehaviorFacts()
            if entry_info is not None:
                try:
                    augment_facts(facts, td.node, entry_info, mod_index)
                except Exception:
                    pass
            result[td.name] = SourceFacts(tool_def=td, facts=facts, module_path=sf.path)
        # rule P4.2 — when this module registers the SAME declared tool name
        # more than once (two separate ``@mcp.tool()``-decorated function
        # bodies), the loop above (via ``extract_tools_all``) only kept
        # facts for ONE of them. Analyze every duplicate definition and
        # merge their behavior facts (worst-case union) into that tool's
        # entry, so a dangerous definition that a last/first-write-wins view
        # would otherwise hide still surfaces.
        dup_defs = find_duplicate_tool_defs(tree)
        for name, defs in dup_defs.items():
            existing = result.get(name)
            if existing is None:
                continue
            # v3-4.3 — every duplicate definition's distinct description is
            # kept on the retained ToolDef, so the description rules run over
            # all of them, not only the definition that happened to win.
            primary = (existing.tool_def.description or "").strip()
            alts: List[str] = []
            for td in defs:
                d = (td.description or "").strip()
                if d and d != primary and d not in alts:
                    alts.append(d)
            existing.tool_def.alt_descriptions = alts
            facts_list = []
            for td in defs:
                if td.node is None:
                    continue
                helper_registry = {n: f for n, f in module_functions.items()
                                   if n != td.func_name}
                try:
                    facts_list.append(analyze_tool_function(
                        td.node, td.taint_params or td.params, module_globals, sf.text,
                        stub_true_funcs, module_consts, helper_registry,
                        dict_literal_keys, registered_tool_names, declared_params=td.params,
                        instance_methods=instance_methods, module_tree=tree))
                    if entry_info is not None:
                        augment_facts(facts_list[-1], td.node, entry_info, mod_index)
                except Exception:
                    continue
            if len(facts_list) < 2:
                continue
            result[name] = SourceFacts(tool_def=existing.tool_def,
                                       facts=merge_behavior_facts(facts_list),
                                       module_path=sf.path)
    return result


def contracts_from_source(source_facts: Dict[str, SourceFacts]) -> List[ToolContract]:
    """When no live listing is available, synthesize the declared contract from
    source (decorator kwargs + docstrings + hints)."""
    out: List[ToolContract] = []
    for name, sfacts in source_facts.items():
        td = sfacts.tool_def
        # v5-6 — the static twin of the live listing entry: the
        # registration's own keyword arguments (title, annotations, schema
        # literals, ...) under the same keys a listing would use.
        extras = getattr(td, "listing_entry", None) or {}
        raw_entry = ({"name": name, "description": td.description or "", **extras}
                     if extras else None)
        out.append(ToolContract(
            name=name,
            description=td.description or "",
            input_schema=_schema_from_params(td.params, td.schema_properties),
            hints=dict(td.hints),
            kind=td.kind,
            source=sfacts,
            raw_entry=raw_entry,
        ))
    return out


def _schema_from_params(params: List[str],
                        schema_properties: Optional[Dict[str, Dict[str, Any]]] = None
                        ) -> Dict[str, Any]:
    # rule P5.4 — a JS/TS schema-builder property (with its own description, when
    # found) takes precedence; every declared param still gets AT LEAST a
    # bare ``{"type": "string"}`` entry so schema/param-name-only checks keep
    # working exactly as before for a param with no builder-level info.
    properties: Dict[str, Any] = {}
    for p in params:
        properties[p] = dict((schema_properties or {}).get(p) or {"type": "string"})
    return {
        "type": "object",
        "properties": properties,
        "required": list(params),
    }


def bind_source_to_listing(contracts: List[ToolContract],
                           source_facts: Dict[str, SourceFacts]) -> None:
    """Attach source facts to live-listed contracts by name (rules 4.2/5.4 cross-check)."""
    for c in contracts:
        if c.name in source_facts:
            c.source = source_facts[c.name]


_HINT_KEYS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def contract_from_listing(item: Dict[str, Any], kind: str = "tool") -> ToolContract:
    """Convert a live tools/resources/prompts listing entry into a ToolContract."""
    if not isinstance(item, dict):
        return ToolContract(name=str(item), kind=kind)
    name = item.get("name") or item.get("uri") or ""
    desc = item.get("description") or item.get("title") or ""
    schema = item.get("inputSchema") or item.get("input_schema") or {}
    # a malformed entry (a non-string description, a non-object schema) must
    # not take a whole detector down with it: the typed fields fall back to
    # empty, and the raw entry (v5-6) still carries every string it holds.
    if not isinstance(name, str):
        name = str(name)
    if not isinstance(desc, str):
        desc = ""
    if not isinstance(schema, dict):
        schema = {}
    hints: Dict[str, Any] = {}
    ann = item.get("annotations") or {}
    for k in _HINT_KEYS:
        if isinstance(ann, dict) and k in ann:
            hints[k] = ann[k]
        elif k in item:
            hints[k] = item[k]
    return ToolContract(name=name, description=desc, input_schema=schema,
                        hints=hints, kind=kind, raw_entry=item)


# --- v5-6 — every string of a listing entry ----------------------------------
# The description rules used to read two places: ``description`` and the
# ``description`` of each top-level input-schema property. An agent is shown
# the whole entry: annotations, titles, examples, output-schema descriptions,
# enum descriptions, vendor/extension fields, at any nesting depth.
# ``listing_entry_strings`` yields every OTHER string value of the raw entry
# with its JSON path and whether the field is a STANDARD description slot
# (a ``description`` anywhere inside the input schema, or a prompt
# argument's ``description``) — a hit in any other field is graded one
# confidence step lower by the detectors.

_ENTRY_INPUT_SCHEMA_KEYS = ("inputSchema", "input_schema")
_ENTRY_SCHEMA_KEYS = _ENTRY_INPUT_SCHEMA_KEYS + ("outputSchema", "output_schema")
_ENTRY_IDENTITY_KEYS = ("name", "uri", "uriTemplate")
_ENTRY_MAX_STRINGS = 300
_ENTRY_MAX_DEPTH = 40
_ENTRY_MAX_CHARS = 8000


def _format_json_path(parts: Tuple[Any, ...]) -> str:
    out = ""
    for p in parts:
        if isinstance(p, int):
            out += f"[{p}]"
        else:
            out += ("." if out else "") + str(p)
    return out


def _walk_entry(obj: Any, parts: Tuple[Any, ...] = ()):
    if len(parts) > _ENTRY_MAX_DEPTH:
        return
    if isinstance(obj, str):
        yield parts, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_entry(v, parts + (str(k),))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk_entry(v, parts + (i,))


def listing_path_under_schema(json_path: str) -> bool:
    """True when the JSON path sits inside the input or output schema."""
    return json_path.split(".", 1)[0].split("[", 1)[0] in _ENTRY_SCHEMA_KEYS


def listing_entry_strings(c: "ToolContract") -> List[Tuple[str, str, bool]]:
    """``(json_path, text, standard)`` for every string value of the
    raw listing entry that the description rules do not already read: not
    the entry's identity (name/uri), not the top-level ``description`` (or
    the ``title`` that stood in for a missing one), not a top-level
    input-schema property ``description`` the schema-field scan already
    reads from ``input_schema``. Strings with no whitespace or under 12
    characters cannot carry a sentence and are skipped; a text already read
    elsewhere in the entry is reported once."""
    entry = c.raw_entry
    if not isinstance(entry, dict):
        return []
    seen = {c.description.strip() if isinstance(c.description, str) else ""}
    props = (c.input_schema or {}).get("properties") if isinstance(c.input_schema, dict) else None
    if isinstance(props, dict):
        for pspec in props.values():
            if isinstance(pspec, dict) and isinstance(pspec.get("description"), str):
                seen.add(pspec["description"].strip())
    out: List[Tuple[str, str, bool]] = []
    for parts, text in _walk_entry(entry):
        if len(out) >= _ENTRY_MAX_STRINGS:
            break
        if not parts:
            continue
        if len(parts) == 1 and parts[0] in _ENTRY_IDENTITY_KEYS + ("description",):
            continue
        t = text.strip()
        if len(t) < 12 or not any(ch.isspace() for ch in t) or t in seen:
            continue
        seen.add(t)
        standard = parts[-1] == "description" and (
            parts[0] in _ENTRY_INPUT_SCHEMA_KEYS or parts[0] == "arguments")
        out.append((_format_json_path(parts), text[:_ENTRY_MAX_CHARS], standard))
    return out


def step_down_confidence(confidence: str) -> str:
    """One confidence step lower (high -> medium -> low)."""
    return {"high": "medium", "medium": "low"}.get(confidence, "low")
