"""v6-W7 — follow same-directory imports when resolving a tool's behavior.

A tool body can delegate to a helper in another module of the same server
directory (``import _gate`` ... ``return _gate.handle(x)``); the directive
string, the poisoned return and the sinks then live in the imported module.
Rules that resolve only the entry module (or inline one level of the entry
module's own helpers) never see them, and the dynamic call plan cannot reach
behavior that is gated on call count.

``LocalModuleIndex`` indexes the Python files the target loader collected.
For a tool defined in module ``M`` it:

* resolves ``import x`` / ``import x as y`` / ``from x import f [as g]`` /
  ``from . import x`` / ``from .x import f`` where ``x`` is a ``x.py`` (or an
  ``x/__init__.py`` package) in the SAME directory -- never anything outside
  the scanned target;
* builds the callee registries the taint inliner already understands
  (``module_functions`` for bare names, ``instance_methods`` for
  ``alias.func(...)``), so a tainted argument that reaches a sink inside an
  imported function is a source->sink finding exactly like a same-module
  helper;
* walks the call graph from the tool body (one to two import hops, plus the
  helper chains inside each reached module; cycle-safe and size-capped) and
  analyzes every reachable function with the SAME content rules as the tool
  itself: returned string literals (with W6's constant folding), assembled
  chr-chains and whole-environment returns are attributed to the tool.
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from . import constfold
from .envdump import find_environ_dumps, module_environ_names
from .pyast import (BehaviorFacts, _ConstEnv, _collect_str_consts, _make_call_resolver,
                    collect_module_functions, counter_gate_threshold,
                    extract_returned_string_literals,
                    parse_module)

MAX_IMPORT_HOPS = 2
MAX_REACHED_FUNCTIONS = 48


@dataclass
class ModuleInfo:
    path: str
    tree: ast.AST
    text: str
    consts: Dict[str, Any]
    functions: Dict[str, ast.AST]
    # local name -> ModuleInfo (``import x [as y]``)
    module_aliases: Dict[str, "ModuleInfo"] = field(default_factory=dict)
    # local name -> (ModuleInfo, original name) (``from x import f [as g]``)
    name_imports: Dict[str, Tuple["ModuleInfo", str]] = field(default_factory=dict)
    imports_resolved: bool = False


@dataclass
class Reached:
    module: ModuleInfo
    name: str
    node: ast.AST
    hops: int
    imported: bool       # reached through a cross-module import
    via: str             # "module::function" breadcrumb of the call chain


class LocalModuleIndex:
    def __init__(self, source_files):
        self._text: Dict[str, str] = {}
        self._infos: Dict[str, ModuleInfo] = {}
        self._by_dir: Dict[Tuple[str, str], str] = {}
        for sf in source_files:
            if getattr(sf, "language", "") != "python":
                continue
            path = os.path.normpath(sf.path)
            self._text[path] = sf.text
            d = os.path.dirname(path)
            base = os.path.basename(path)
            if base == "__init__.py":
                self._by_dir[(os.path.dirname(d), os.path.basename(d))] = path
            elif base.endswith(".py"):
                self._by_dir[(d, base[:-3])] = path

    # -- module loading ------------------------------------------------------
    def info(self, path: str) -> Optional[ModuleInfo]:
        path = os.path.normpath(path)
        if path in self._infos:
            return self._infos[path]
        text = self._text.get(path)
        if text is None:
            return None
        tree = parse_module(text)
        if tree is None:
            return None
        mi = ModuleInfo(path=path, tree=tree, text=text,
                        consts=_collect_str_consts(tree),
                        functions=collect_module_functions(tree))
        self._infos[path] = mi
        return mi

    def _find(self, from_dir: str, dotted: str) -> Optional[str]:
        """``a.b`` -> <dir>/a/b.py or <dir>/a/b/__init__.py (same-directory
        tree only)."""
        parts = [p for p in dotted.split(".") if p]
        if not parts:
            return None
        d = from_dir
        for p in parts[:-1]:
            d = os.path.join(d, p)
        key = (d, parts[-1])
        return self._by_dir.get(key)

    def resolve_imports(self, mi: ModuleInfo) -> None:
        if mi.imports_resolved:
            return
        mi.imports_resolved = True
        here = os.path.dirname(mi.path)
        for node in ast.walk(mi.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    target = self._find(here, a.name)
                    if target is None or target == mi.path:
                        continue
                    tinfo = self.info(target)
                    if tinfo is None:
                        continue
                    if a.asname:
                        mi.module_aliases[a.asname] = tinfo
                    elif "." not in a.name:
                        mi.module_aliases[a.name] = tinfo
            elif isinstance(node, ast.ImportFrom):
                level = node.level or 0
                base_dir = here
                for _ in range(max(0, level - 1)):
                    base_dir = os.path.dirname(base_dir)
                mod = node.module or ""
                if level == 0 and not mod:
                    continue
                if mod:
                    target = self._find(base_dir, mod)
                else:
                    target = None  # ``from . import x``: each name is a module
                tinfo = self.info(target) if target and target != mi.path else None
                for a in node.names:
                    local = a.asname or a.name
                    if a.name == "*":
                        if tinfo is not None:
                            for fname in tinfo.functions:
                                if not fname.startswith("_"):
                                    mi.name_imports.setdefault(fname, (tinfo, fname))
                        continue
                    # ``from pkg import submodule``
                    sub = self._find(os.path.join(base_dir, *mod.split(".")) if mod else base_dir,
                                     a.name)
                    if sub is not None and sub != mi.path and (
                            tinfo is None or a.name not in tinfo.functions):
                        sinfo = self.info(sub)
                        if sinfo is not None:
                            mi.module_aliases[local] = sinfo
                            continue
                    if tinfo is not None:
                        mi.name_imports[local] = (tinfo, a.name)

    # -- registries for the taint inliner --------------------------------------
    def registries(self, entry: ModuleInfo) -> Tuple[Dict[str, ast.AST], Dict[str, Dict[str, ast.AST]]]:
        """``(module_functions, instance_methods)`` additions contributed by
        the entry module's imports and, transitively (cycle-safe, two hops),
        the imports of the modules it reaches."""
        funcs: Dict[str, ast.AST] = {}
        methods: Dict[str, Dict[str, ast.AST]] = {}
        seen: Set[str] = set()

        def walk(mi: ModuleInfo, hops: int) -> None:
            if mi.path in seen or hops > MAX_IMPORT_HOPS:
                return
            seen.add(mi.path)
            self.resolve_imports(mi)
            for alias, tinfo in mi.module_aliases.items():
                methods.setdefault(alias, dict(tinfo.functions))
                # a module's own bare-name helper calls resolve inside it
                for fname, fnode in tinfo.functions.items():
                    funcs.setdefault(fname, fnode)
                walk(tinfo, hops + 1)
            for local, (tinfo, orig) in mi.name_imports.items():
                fnode = tinfo.functions.get(orig)
                if fnode is not None:
                    funcs.setdefault(local, fnode)
                for fname, f2 in tinfo.functions.items():
                    funcs.setdefault(fname, f2)
                walk(tinfo, hops + 1)

        walk(entry, 0)
        return funcs, methods

    def _refresh_consts(self, mi: ModuleInfo, hops: int, active: Set[str]) -> None:
        """Re-fold ``mi``'s module constants with the constants it imports
        (``from _texts import POLICY`` then ``NOTICE = POLICY``), at most
        ``MAX_IMPORT_HOPS`` deep and cycle-safe."""
        if getattr(mi, "_refreshed", False) or mi.path in active or hops > MAX_IMPORT_HOPS:
            return
        active.add(mi.path)
        self.resolve_imports(mi)
        base = _ConstEnv()
        for local, (tinfo, orig) in mi.name_imports.items():
            self._refresh_consts(tinfo, hops + 1, active)
            tinfos = getattr(tinfo.consts, "infos", {}) or {}
            if orig in tinfo.consts:
                base[local] = tinfo.consts[orig]
                if orig in tinfos:
                    base.infos[local] = tinfos[orig]
        for alias, tinfo in mi.module_aliases.items():
            self._refresh_consts(tinfo, hops + 1, active)
            tinfos = getattr(tinfo.consts, "infos", {}) or {}
            for k, v in tinfo.consts.items():
                base[f"{alias}.{k}"] = v
                if k in tinfos:
                    base.infos[f"{alias}.{k}"] = tinfos[k]
        if base:
            mi.consts = _collect_str_consts(mi.tree, base)
        mi._refreshed = True  # type: ignore[attr-defined]
        active.discard(mi.path)

    def const_env(self, entry: ModuleInfo) -> Dict[str, Any]:
        """The entry module's constants plus the module-level constants it
        imports (``from _gate import NOTICE`` -> ``NOTICE``; ``_gate.NOTICE``
        -> ``"_gate.NOTICE"``). ``infos`` (how an assembled constant was
        built) travels with them."""
        self.resolve_imports(entry)
        for tinfo in list(entry.module_aliases.values()) + [t for t, _ in entry.name_imports.values()]:
            self._refresh_consts(tinfo, 1, {entry.path})
        env = _ConstEnv(entry.consts)
        env.infos = dict(getattr(entry.consts, "infos", {}) or {})
        for alias, tinfo in entry.module_aliases.items():
            tinfos = getattr(tinfo.consts, "infos", {}) or {}
            for k, v in tinfo.consts.items():
                env.setdefault(f"{alias}.{k}", v)
                if k in tinfos:
                    env.infos.setdefault(f"{alias}.{k}", tinfos[k])
        for local, (tinfo, orig) in entry.name_imports.items():
            tinfos = getattr(tinfo.consts, "infos", {}) or {}
            if orig in tinfo.consts:
                env.setdefault(local, tinfo.consts[orig])
                if orig in tinfos:
                    env.infos.setdefault(local, tinfos[orig])
        return env

    # -- reachability ----------------------------------------------------------
    def reachable(self, entry: ModuleInfo, tool_node: ast.AST) -> List[Reached]:
        """Functions reachable from ``tool_node`` by calls: same-module
        helpers, and functions of same-directory modules imported (at most
        ``MAX_IMPORT_HOPS`` import hops). The tool's own function is excluded."""
        self.resolve_imports(entry)
        out: List[Reached] = []
        seen: Set[Tuple[str, str]] = set()
        own = getattr(tool_node, "name", None)
        seen.add((entry.path, own or ""))

        def calls_in(fn: ast.AST):
            for n in ast.walk(fn):
                if isinstance(n, ast.Call):
                    yield n

        def visit(mi: ModuleInfo, fn: ast.AST, hops: int, chain: str) -> None:
            if len(out) >= MAX_REACHED_FUNCTIONS:
                return
            self.resolve_imports(mi)
            for call in calls_in(fn):
                f = call.func
                target: Optional[Tuple[ModuleInfo, str, ast.AST, int, bool]] = None
                if isinstance(f, ast.Name):
                    if f.id in mi.functions:
                        target = (mi, f.id, mi.functions[f.id], hops, hops > 0)
                    elif f.id in mi.name_imports and hops + 1 <= MAX_IMPORT_HOPS:
                        tinfo, orig = mi.name_imports[f.id]
                        if orig in tinfo.functions:
                            target = (tinfo, orig, tinfo.functions[orig], hops + 1, True)
                elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                    tinfo = mi.module_aliases.get(f.value.id)
                    if tinfo is not None and hops + 1 <= MAX_IMPORT_HOPS \
                            and f.attr in tinfo.functions:
                        target = (tinfo, f.attr, tinfo.functions[f.attr], hops + 1, True)
                if target is None:
                    continue
                tmi, tname, tnode, thops, imported = target
                key = (tmi.path, tname)
                if key in seen:
                    continue
                seen.add(key)
                crumb = f"{os.path.basename(tmi.path)}::{tname}"
                via = f"{chain} -> {crumb}" if chain else crumb
                out.append(Reached(tmi, tname, tnode, thops, imported or tmi.path != entry.path, via))
                visit(tmi, tnode, thops, via)

        visit(entry, tool_node, 0, "")
        return out


# ---------------------------------------------------------------------------

def _module_level_names(tree: ast.AST) -> Set[str]:
    names: Set[str] = set()
    for node in getattr(tree, "body", []) or []:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def scan_counter_gates(func: ast.AST, module_names: Set[str]) -> List[int]:
    """v6 — thresholds of call-counter-shaped gates in ``func``: an ``if`` /
    ``while`` test comparing a module-level (or ``global``-declared) name
    directly against a bare number (``if _calls >= 10``). Parameters are
    excluded; ``in`` / ``is`` comparisons are not counters. Returned only to
    size the dynamic call plan -- it never becomes a finding by itself (an
    honest usage / rate-limit counter has the same shape)."""
    params = {a.arg for a in (getattr(func, "args", None).args
                              + getattr(func, "args", None).kwonlyargs)} \
        if getattr(func, "args", None) else set()
    declared: Set[str] = set()
    for n in ast.walk(func):
        if isinstance(n, ast.Global):
            declared.update(n.names)
    counters = (module_names | declared) - params
    out: List[int] = []
    for node in ast.walk(func):
        if not isinstance(node, (ast.If, ast.While, ast.IfExp)):
            continue
        for cmp_node in (n for n in ast.walk(node.test) if isinstance(n, ast.Compare)):
            if any(isinstance(op, (ast.In, ast.NotIn, ast.Is, ast.IsNot)) for op in cmp_node.ops):
                continue
            operands = [cmp_node.left] + list(cmp_node.comparators)
            if not any(isinstance(o, ast.Name) and o.id in counters for o in operands):
                continue
            for o in operands:
                if isinstance(o, ast.Constant) and isinstance(o.value, (int, float)) \
                        and not isinstance(o.value, bool):
                    thr = counter_gate_threshold(cmp_node.ops, o.value)
                    if thr is not None and thr not in out:
                        out.append(thr)
    return out


def augment_facts(facts: BehaviorFacts, tool_node: ast.AST, entry: ModuleInfo,
                  index: LocalModuleIndex) -> None:
    """Fold the behavior of every function reachable from the tool body into
    ``facts``: returned string literals (constant-folded), assembled
    chr-chains, whole-environment returns. Imported-module findings keep a
    breadcrumb (``module::function``) so a finding says WHERE the directive
    lives."""
    reached = index.reachable(entry, tool_node)
    if not reached:
        return
    seen_lit = set(facts.returned_string_literals)
    resolvers: Dict[str, Any] = {}

    def resolver_for(mi: ModuleInfo):
        if mi.path not in resolvers:
            funcs, methods = index.registries(mi)
            merged = dict(funcs)
            merged.update(mi.functions)
            resolvers[mi.path] = _make_call_resolver(merged, methods)
        return resolvers[mi.path]

    for r in reached:
        mi = r.module
        index.resolve_imports(mi)
        # v6 — counter-the gate thresholds of every reached function (any hop):
        # sizes the call plan; deliberately NOT ``uses_call_counter_gate``.
        try:
            for thr in scan_counter_gates(r.node, _module_level_names(mi.tree)):
                if thr not in facts.counter_gate_thresholds:
                    facts.counter_gate_thresholds.append(thr)
        except Exception:
            pass
        renv = index.const_env(mi)
        if mi.path != entry.path and mi.path not in facts.followed_modules:
            facts.followed_modules.append(mi.path)
        # 1) returned literals of the reached function. A same-module helper's
        # literal is attributed too (a tool that returns ``_note()`` returns
        # the helper's text), with the same constant folding.
        try:
            lits = extract_returned_string_literals(r.node, renv)
        except Exception:
            lits = []
        for lit in lits:
            if lit and lit not in seen_lit:
                seen_lit.add(lit)
                facts.returned_string_literals.append(lit)
                facts.literal_origins[lit] = r.via
        # 2) chr-chain assembly
        try:
            for rec in constfold.find_assembled_strings(
                    r.node, dict(renv), base_infos=getattr(renv, "infos", None)):
                rec = dict(rec)
                rec.update({"module": mi.path, "via": r.via})
                if rec not in facts.assembled_strings:
                    facts.assembled_strings.append(rec)
        except Exception:
            pass
        # 3) whole-environment returns (resolved with the callee's own module
        # as the import context)
        try:
            for rec in find_environ_dumps(r.node, mi.tree, resolver_for(mi), dict(renv)):
                rec = dict(rec)
                rec.update({"module": mi.path, "via": r.via})
                if rec not in facts.environ_dumps:
                    facts.environ_dumps.append(rec)
        except Exception:
            pass
