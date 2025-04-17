"""v6-W3 — whole-environment serialization (a static information-disclosure
source shape).

A tool that hands back the WHOLE process environment -- ``str(dict(os.environ))``,
``json.dumps(dict(os.environ))``, a loop over ``os.environ.items()`` that builds
the response -- discloses every secret the server process holds (cloud keys,
tokens, database URLs), whatever the tool is nominally for. The dynamic child
environment carries no decoy canary, so the live scan cannot see it; the rule keys on
the SOURCE SHAPE instead.

The distinguishing feature is WHOLE vs. SINGLE:

* ``os.environ.get(name)`` / ``os.environ[name]`` / ``os.getenv(name)`` /
  ``name in os.environ``                  -> one variable (the caller asked), clean
* ``os.environ`` / ``dict(os.environ)`` / ``os.environ.copy()`` /
  ``.items()`` / ``.keys()`` / ``.values()`` / iterating it, flowing into a
  RETURNED value                          -> the whole mapping, a disclosure sink

Handing the environment to a CHILD PROCESS (``subprocess.run(cmd, env={**os.environ,
"X": "1"})``) is the overwhelmingly common honest use and is a consumer, not a
disclosure: only an environment that reaches a ``return`` counts.

Flow is tracked through plain names (``env = dict(os.environ)``), accumulation
loops (``for k, v in os.environ.items(): lines.append(...)``), comprehensions,
f-strings and a callee that itself returns the environment (resolved through
the caller-supplied ``resolve`` callback, so a helper in another module is
followed too). A comprehension / loop that SELECTS keys against a constant
(``k.startswith("MCP_")``, ``k in ALLOWED``) is a partial view and is not
reported (a documented blind spot).
"""
from __future__ import annotations

import ast
from typing import Any, Callable, Dict, List, Optional, Set

from . import constfold

_SINGLE_ACCESS_ATTRS = frozenset({"get", "pop", "setdefault", "__getitem__",
                                  "__contains__", "has_key", "update", "clear",
                                  "__setitem__", "__delitem__"})
_WHOLE_VIEW_ATTRS = frozenset({"copy", "items", "keys", "values"})
_REDUCERS = frozenset({"len", "bool", "any", "all", "isinstance", "type", "id",
                       "hash", "callable", "min", "max", "sum", "next", "iter",
                       "print", "logging.debug", "logger.debug"})
# a call that CONSUMES an environment mapping (a child process / exec) is not
# a disclosure to the agent
_CONSUMER_PREFIXES = ("subprocess.", "os.exec", "os.spawn", "os.system", "os.popen",
                      "asyncio.create_subprocess", "pty.spawn", "multiprocessing.",
                      "sh.", "plumbum.")
_CONSUMER_NAMES = frozenset({"Popen", "run", "check_call", "check_output", "call",
                             "exec", "execve", "execvpe", "spawn", "spawnve"})
_MUTATORS = frozenset({"append", "extend", "add", "update", "insert", "write",
                       "writelines", "setdefault", "appendleft", "push"})
_ENV_COMMANDS = frozenset({"env", "printenv", "set", "export", "export -p", "declare -x",
                           "env -0", "printenv -0", "cmd /c set", "set"})
_COMMAND_RUNNERS = frozenset({
    "subprocess.check_output", "subprocess.run", "subprocess.getoutput",
    "subprocess.getstatusoutput", "subprocess.Popen", "os.popen", "os.system"})


def _dotted(node: ast.AST) -> str:
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def module_environ_names(tree: Optional[ast.AST]) -> Dict[str, Set[str]]:
    """``{"os": {names bound to the os module}, "environ": {names bound to
    os.environ itself}}`` from the module's imports."""
    os_names: Set[str] = {"os"}
    environ_names: Set[str] = set()
    if isinstance(tree, ast.Module):
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.name in ("os", "posix"):
                        os_names.add(a.asname or a.name)
            elif isinstance(n, ast.ImportFrom) and n.module in ("os", "posix"):
                for a in n.names:
                    if a.name == "environ":
                        environ_names.add(a.asname or a.name)
    return {"os": os_names, "environ": environ_names}


class EnvironAnalyzer:
    def __init__(self, names: Dict[str, Set[str]],
                 resolve: Optional[Callable[[ast.Call], Optional[ast.AST]]] = None,
                 env: Optional[Dict[str, Any]] = None, max_depth: int = 2):
        self.os_names = names.get("os") or {"os"}
        self.environ_names = names.get("environ") or set()
        self.resolve = resolve
        self.env = env or {}
        self.max_depth = max_depth
        self._summary: Dict[int, bool] = {}
        self._active: Set[int] = set()

    # -- roots -----------------------------------------------------------------
    def is_root(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.environ_names
        if isinstance(node, ast.Attribute) and node.attr == "environ":
            return isinstance(node.value, ast.Name) and node.value.id in self.os_names
        return False

    def is_env_command(self, call: ast.Call) -> bool:
        dn = _dotted(call.func)
        if dn not in _COMMAND_RUNNERS or not call.args:
            return False
        v, _ = constfold.fold_value(call.args[0], self.env)
        if isinstance(v, str):
            return v.strip().lower() in _ENV_COMMANDS
        if isinstance(v, (list, tuple)) and v and all(isinstance(x, str) for x in v):
            return " ".join(v).strip().lower() in _ENV_COMMANDS
        return False

    def is_consumer(self, call: ast.Call) -> bool:
        dn = _dotted(call.func)
        if dn.startswith(_CONSUMER_PREFIXES):
            return True
        last = call.func.attr if isinstance(call.func, ast.Attribute) else (
            call.func.id if isinstance(call.func, ast.Name) else "")
        if last in _CONSUMER_NAMES and not self.is_root(call.func):
            return True
        return dn in _REDUCERS or last in _REDUCERS and not isinstance(call.func, ast.Attribute)

    # -- whole(expr) -------------------------------------------------------------
    def whole(self, node: Optional[ast.AST], derived: Set[str], depth: int) -> bool:
        if node is None:
            return False
        if self.is_root(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in derived
        if isinstance(node, ast.Call):
            if self.is_env_command(node):
                return True
            f = node.func
            if isinstance(f, ast.Attribute):
                if self.is_root(f.value):
                    return f.attr in _WHOLE_VIEW_ATTRS
                if f.attr in _SINGLE_ACCESS_ATTRS:
                    return False
                if self.whole(f.value, derived, depth):
                    return True  # .encode()/.strip()/.items() of a whole value
            # a callee that itself returns the environment
            if self._resolved_whole(node, depth):
                return True
            if self.is_consumer(node):
                return False
            return any(self.whole(a, derived, depth) for a in node.args) or any(
                self.whole(k.value, derived, depth) for k in node.keywords)
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue)
                       and self.whole(v.value, derived, depth) for v in node.values)
        if isinstance(node, ast.BinOp):
            return self.whole(node.left, derived, depth) or self.whole(node.right, derived, depth)
        if isinstance(node, ast.IfExp):
            return self.whole(node.body, derived, depth) or self.whole(node.orelse, derived, depth)
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if k is None and self.whole(v, derived, depth):
                    return True  # {**os.environ, ...}
                if k is not None and self.whole(v, derived, depth):
                    return True
            return False
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.whole(e, derived, depth) for e in node.elts)
        if isinstance(node, ast.Starred):
            return self.whole(node.value, derived, depth)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return self.comprehension_whole(node, derived, depth)
        if isinstance(node, ast.Subscript):
            # a single key (environ[name]) is not the whole; a slice/index of a
            # derived whole value is still (part of) the whole
            return self.whole(node.value, derived, depth) if not self.is_root(node.value) else False
        if isinstance(node, ast.Attribute):
            return self.whole(node.value, derived, depth) if not self.is_root(node.value) else False
        if isinstance(node, ast.Await):
            return self.whole(node.value, derived, depth)
        return False

    def _resolved_whole(self, call: ast.Call, depth: int) -> bool:
        if self.resolve is None or depth >= self.max_depth:
            return False
        target = self.resolve(call)
        return target is not None and self.returns_whole(target, depth + 1)

    def comprehension_whole(self, node: ast.AST, derived: Set[str], depth: int) -> bool:
        for g in node.generators:  # type: ignore[attr-defined]
            if self.whole(g.iter, derived, depth):
                key_names = _target_names(g.target)
                if any(self.const_key_filter(t, key_names) for t in g.ifs):
                    continue  # a constant-key selection: a partial view
                return True
        return False

    @staticmethod
    def const_key_filter(test: ast.AST, names: Set[str]) -> bool:
        """The test selects by comparing a loop variable against a CONSTANT
        (``k.startswith("MCP_")``, ``k in ALLOWED``, ``k == "HOME"``)."""
        mentions = any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(test))
        if not mentions:
            return False
        for n in ast.walk(test):
            if isinstance(n, ast.Constant) and isinstance(n.value, (str, tuple)):
                return True
            if isinstance(n, (ast.Tuple, ast.List, ast.Set)) and any(
                    isinstance(e, ast.Constant) for e in n.elts):
                return True
            if isinstance(n, ast.Name) and n.id.isupper() and n.id not in names:
                return True
        return False

    # -- derived names -----------------------------------------------------------
    def derive_names(self, func: ast.AST, depth: int) -> Set[str]:
        derived: Set[str] = set()
        for _ in range(3):  # a few passes reach a flow fixpoint on straight-line code
            before = len(derived)
            for n in ast.walk(func):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and n is not func:
                    continue
                if isinstance(n, ast.Assign):
                    if self.whole(n.value, derived, depth):
                        for t in n.targets:
                            derived |= _target_names(t)
                elif isinstance(n, ast.AnnAssign) and n.value is not None:
                    if self.whole(n.value, derived, depth):
                        derived |= _target_names(n.target)
                elif isinstance(n, ast.AugAssign):
                    if self.whole(n.value, derived, depth):
                        derived |= _target_names(n.target)
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    if self.whole(n.iter, derived, depth):
                        keys = _target_names(n.target)
                        if any(isinstance(x, ast.If) and self.const_key_filter(x.test, keys)
                               for x in ast.walk(ast.Module(body=n.body, type_ignores=[]))):
                            continue  # selects keys by a constant: partial
                        derived |= keys
                        derived |= self._loop_accumulators(n)
            if len(derived) == before:
                break
        return derived

    @staticmethod
    def _loop_accumulators(loop: ast.AST) -> Set[str]:
        out: Set[str] = set()
        for st in ast.walk(ast.Module(body=loop.body, type_ignores=[])):  # type: ignore[attr-defined]
            if isinstance(st, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = st.targets if isinstance(st, ast.Assign) else [st.target]
                for t in targets:
                    root = _root_name(t)
                    if root:
                        out.add(root)
            elif (isinstance(st, ast.Call) and isinstance(st.func, ast.Attribute)
                  and st.func.attr in _MUTATORS):
                root = _root_name(st.func.value)
                if root:
                    out.add(root)
        return out

    # -- disclosure sites ----------------------------------------------------------
    def disclosure_in(self, expr: ast.AST, derived: Set[str], depth: int) -> Optional[ast.AST]:
        """The maximal whole-environment sub-expression of a returned
        expression, or None. Single-key accesses, reducers, comparisons and
        child-process consumers are skipped."""
        def visit(n: ast.AST) -> Optional[ast.AST]:
            if isinstance(n, ast.Compare):
                return None
            if isinstance(n, ast.Subscript) and self.is_root(n.value):
                return None
            if isinstance(n, ast.Call):
                f = n.func
                if (isinstance(f, ast.Attribute) and self.is_root(f.value)
                        and f.attr in _SINGLE_ACCESS_ATTRS):
                    return None
                if (self.is_consumer(n) and not self.is_env_command(n)
                        and not self._resolved_whole(n, depth)):
                    return None
            if isinstance(n, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
                return None
            if isinstance(n, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                if not self.comprehension_whole(n, derived, depth):
                    # a constant-key selection over the environment is a
                    # partial view: do not descend into its iterable
                    if any(self.whole(g.iter, derived, depth) for g in n.generators):
                        return None
            if self.whole(n, derived, depth):
                return n
            for ch in ast.iter_child_nodes(n):
                r = visit(ch)
                if r is not None:
                    return r
            return None
        return visit(expr)

    def returns_whole(self, func: ast.AST, depth: int = 0) -> bool:
        key = id(func)
        if key in self._summary:
            return self._summary[key]
        if key in self._active or depth > self.max_depth:
            return False
        self._active.add(key)
        try:
            derived = self.derive_names(func, depth)
            result = False
            for n in ast.walk(func):
                if isinstance(n, ast.Return) and n.value is not None:
                    if self.disclosure_in(n.value, derived, depth) is not None:
                        result = True
                        break
        finally:
            self._active.discard(key)
        self._summary[key] = result
        return result

    def dumps_in(self, func: ast.AST, depth: int = 0) -> List[Dict[str, Any]]:
        """Every ``return`` of ``func`` that hands back the whole environment:
        ``[{"lineno", "snippet", "form"}]``."""
        derived = self.derive_names(func, depth)
        out: List[Dict[str, Any]] = []
        for n in ast.walk(func):
            if isinstance(n, ast.Return) and n.value is not None:
                hit = self.disclosure_in(n.value, derived, depth)
                if hit is None:
                    continue
                try:
                    snippet = ast.unparse(n.value)[:200]
                except Exception:
                    snippet = ""
                out.append({"lineno": getattr(n, "lineno", 0), "snippet": snippet,
                            "form": self.form_of(hit, n.value)})
        return out

    @staticmethod
    def form_of(hit: ast.AST, returned: ast.AST) -> str:
        if isinstance(hit, ast.Call):
            dn = _dotted(hit.func)
            if dn in _COMMAND_RUNNERS:
                return "env-command"
            if isinstance(hit.func, ast.Attribute) and hit.func.attr in _WHOLE_VIEW_ATTRS:
                return f"environ.{hit.func.attr}()"
            return dn or "call"
        if isinstance(hit, (ast.ListComp, ast.GeneratorExp, ast.DictComp, ast.SetComp)):
            return "comprehension"
        if isinstance(hit, ast.JoinedStr):
            return "f-string"
        if isinstance(hit, ast.Name):
            return "derived-name"
        if isinstance(hit, (ast.Attribute, ast.Dict)):
            return "mapping"
        return type(hit).__name__


def _target_names(t: ast.AST) -> Set[str]:
    out: Set[str] = set()
    for n in ast.walk(t):
        if isinstance(n, ast.Name):
            out.add(n.id)
    return out


def _root_name(node: ast.AST) -> Optional[str]:
    cur = node
    while isinstance(cur, (ast.Subscript, ast.Attribute)):
        cur = cur.value
    return cur.id if isinstance(cur, ast.Name) else None


def find_environ_dumps(func: ast.AST, tree: Optional[ast.AST] = None,
                       resolve: Optional[Callable[[ast.Call], Optional[ast.AST]]] = None,
                       env: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """The returns of ``func`` that hand back the whole process environment
    (see the module docstring). ``tree`` supplies the module's import aliases;
    ``resolve`` maps a call to the function node it targets (a local helper or
    one imported from a same-directory module) so a helper that returns the
    environment is followed."""
    ea = EnvironAnalyzer(module_environ_names(tree), resolve, env)
    try:
        return ea.dumps_in(func)
    except RecursionError:
        return []
