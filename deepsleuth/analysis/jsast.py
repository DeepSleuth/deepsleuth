"""rule 2.8 — JavaScript/TypeScript source extraction.

No JS/TS parser dependency: this scanner stays LLM-free and (deliberately)
dependency-free, so this is a brace/paren-balanced scan over the raw source
text rather than a real AST. It recovers the same two things Python source
analysis already gives for free, which JS/TS source analysis gave nothing
for at all:

1. Every tool's declared *name* and *description* — high-level SDK
   registration (``server.tool("name", "description", schema, handler)`` /
   ``server.registerTool("name", {description, inputSchema}, handler)``) and
   the low-level SDK's array-of-object-literals form
   (``{tools: [{name: "...", description: "..."}, ...]}``). Feeding these
   into a ``ToolContract`` means the SAME text-engine description rules that
   already run over Python-sourced tools (desc-poisoning, cross-tool-
   redirect, param-tampering, ...) run over JS/TS ones too, with no
   language-specific detector code at all.

2. The dangerous sinks (``child_process``/``fs``/network) a tool's own
   handler body reaches, tainted when the sink's own argument text
   references one of the handler's declared parameters — the JS/TS analogue
   of the Python taint engine's "a tool parameter reaches a sink" check,
   reusing the SAME ``SinkRecord``/``BehaviorFacts`` shapes so
   ``detectors/taint.py`` needs no changes to consume them.

This is intentionally best-effort and structural: it keys on *shape* (a
balanced-call registration, a sink call whose argument textually contains a
declared parameter name), never on specific tool/package vocabulary, so it
degrades gracefully on source it cannot fully make sense of instead of
guessing.
"""
from __future__ import annotations

import re
from typing import Set, Any, Dict, List, Optional, Tuple

from .pyast import BehaviorFacts, SinkRecord, ToolDef

# --- balanced-delimiter scanning -------------------------------------------


def _find_matching(text: str, open_idx: int, open_ch: str = "(", close_ch: str = ")") -> int:
    """Index of the delimiter matching ``text[open_idx]`` (which must be
    ``open_ch``), skipping over string/template literals and comments so a
    stray ``)``/``}`` inside a description string never throws off the
    count. Returns -1 if unbalanced."""
    n = len(text)
    if open_idx >= n or text[open_idx] != open_ch:
        return -1
    depth = 0
    i = open_idx
    in_str: Optional[str] = None
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ("'", '"', "`"):
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = j + 1 if j != -1 else n
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = j + 2 if j != -1 else n
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


# --- rule P5.1 — delimiter-aware string literals, concatenation, constants -----
# A naive ``['"`]([^'"`]{0,N})['"`]`` regex (the pre-rule P5.1 shape) opens on
# WHICHEVER of the three quote characters occurs, but then excludes ALL
# THREE from the content class — so a template literal containing an
# apostrophe (`` `Fetches the user's profile` ``, a completely ordinary
# sentence) truncates at that apostrophe, silently dropping everything
# after it. These honor the delimiter that actually opened the string, walk
# past backslash escapes, and additionally resolve ``"a" + "b"`` string
# concatenation and a bare identifier that refers to a ``const``/``let``/
# ``var`` string constant defined elsewhere in the file.
#
# v5-8 — descriptions HELD INDIRECTLY. A description (or a schema
# ``.describe(...)`` / ``description:`` text) is often not a literal at the
# registration site: it is an identifier, a property of a constant object
# (``TEXTS.search``, ``TEXTS["search"]``), a template literal with
# ``${CONST}`` parts, an array ``.join(...)``, or a concatenation across
# constants. ``_js_eval_expr`` is a small static evaluator for exactly
# those shapes — string / template / array / object literals, identifier
# and member paths, ``+``, ``.join`` / ``.trim`` / ``.concat``, parentheses,
# ``Object.freeze(...)``, tagged templates — following at most
# ``_JS_MAX_HOPS`` hops of ``const`` bindings within the file. Anything it
# cannot evaluate statically (a function call, an imported name) contributes
# nothing, and the literal text around it is still read.

_CONST_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=;\n]*?)?=\s*(?![=>])"
)
_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_JS_MAX_HOPS = 2
_JS_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "", "f": "", "v": "", "0": ""}
_JS_NON_VALUE_WORDS = frozenset({"new", "await", "typeof", "void", "function", "async",
                                 "class", "return", "yield", "delete"})
_JS_STRING_PASSTHROUGH = frozenset({
    "toString", "valueOf", "normalize", "replace", "replaceAll", "padEnd", "padStart",
    "toLowerCase", "toUpperCase", "toLocaleLowerCase", "toLocaleUpperCase",
})
_JS_TRIMS = {"trim": str.strip, "trimStart": str.lstrip, "trimLeft": str.lstrip,
             "trimEnd": str.rstrip, "trimRight": str.rstrip}
_JS_OBJ_KEY_RE = re.compile(
    r"\s*(?:([A-Za-z_$][A-Za-z0-9_$]*)|([\"'`])(.*?)\2|\[\s*([\"'`])(.*?)\4\s*\])\s*:(?!:)",
    re.DOTALL)


def _decode_escape(text: str, i: int) -> Tuple[str, int]:
    """``text[i]`` is a backslash. Returns (decoded text, index after the
    escape sequence)."""
    n = len(text)
    if i + 1 >= n:
        return "", i + 1
    c = text[i + 1]
    if c == "\n":
        return "", i + 2  # line continuation
    if c in _JS_ESCAPES:
        return _JS_ESCAPES[c], i + 2
    if c == "x" and i + 3 < n:
        try:
            return chr(int(text[i + 2:i + 4], 16)), i + 4
        except ValueError:
            return "x", i + 2
    if c == "u":
        if i + 2 < n and text[i + 2] == "{":
            j = text.find("}", i + 3)
            if j != -1:
                try:
                    return chr(int(text[i + 3:j], 16)), j + 1
                except (ValueError, OverflowError):
                    return "u", i + 2
        try:
            return chr(int(text[i + 2:i + 6], 16)), i + 6
        except ValueError:
            return "u", i + 2
    return c, i + 2


def _match_string_literal(text: str, start: int) -> Optional[Tuple[str, int]]:
    """``text[start]`` must be a quote character. Returns (content, index
    right after the CLOSING delimiter that matches it), honoring backslash
    escapes; ``None`` if unterminated."""
    if start >= len(text) or text[start] not in ("'", '"', "`"):
        return None
    quote = text[start]
    n = len(text)
    i = start + 1
    out: List[str] = []
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            piece, i = _decode_escape(text, i)
            out.append(piece)
            continue
        if c == quote:
            return "".join(out), i + 1
        out.append(c)
        i += 1
    return None


def _skip_ws(text: str, i: int) -> int:
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    return i


def _skip_ws_comments(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        if text[i] in " \t\r\n":
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = j + 1 if j != -1 else n
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = j + 2 if j != -1 else n
        else:
            break
    return i


def _strip_js_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments, leaving string / template
    literals untouched (a comment may hold an apostrophe that would
    otherwise read as an opening quote)."""
    out: List[str] = []
    i, n = 0, len(text)
    in_str: Optional[str] = None
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ("'", '"', "`"):
            in_str = c
            out.append(c)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = j if j != -1 else n
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = j + 2 if j != -1 else n
            continue
        out.append(c)
        i += 1
    return "".join(out)


class _JsObject:
    """An object literal: property name -> the SOURCE TEXT of its value
    expression (evaluated lazily, against the same environment)."""
    __slots__ = ("props",)

    def __init__(self, props: Dict[str, str]):
        self.props = props


class _JsArray:
    """An array literal: the source text of each element expression."""
    __slots__ = ("items",)

    def __init__(self, items: List[str]):
        self.items = items


def _js_object(body: str) -> _JsObject:
    props: Dict[str, str] = {}
    for seg in _split_top_level_args(_strip_js_comments(body)):
        if not seg.strip() or seg.lstrip().startswith("..."):
            continue
        m = _JS_OBJ_KEY_RE.match(seg)
        if m:
            key = m.group(1) or m.group(3) or m.group(5) or ""
            if key:
                props.setdefault(key, seg[m.end():])
            continue
        name = seg.strip()
        if _IDENT_RE.fullmatch(name):
            props.setdefault(name, name)  # shorthand ``{ description }``
    return _JsObject(props)


class _JsEnv:
    """The ``const``/``let``/``var`` bindings of one file, evaluated lazily.
    Also answers ``name in env`` / ``env[name]`` for a binding that resolves
    to a string (the pre-v5-8 ``Dict[str, str]`` interface)."""

    def __init__(self, text: str = "", literal: Optional[Dict[str, str]] = None):
        self.text = text
        self.literal: Dict[str, str] = dict(literal or {})
        self.bindings: Dict[str, int] = {}
        for m in _CONST_ASSIGN_RE.finditer(text):
            self.bindings.setdefault(m.group(1), m.end())

    def lookup(self, name: str, hops: int) -> Any:
        if name in self.literal:
            return self.literal[name]
        if hops >= _JS_MAX_HOPS:
            return None
        pos = self.bindings.get(name)
        if pos is None:
            return None
        value, _ = _js_eval_expr(self.text, pos, self, hops + 1)
        return value

    def get(self, name: str, default: Any = None) -> Any:
        value = self.lookup(name, 0)
        return value if isinstance(value, str) else default

    def __contains__(self, name: str) -> bool:
        return isinstance(self.lookup(name, 0), str)

    def __getitem__(self, name: str) -> str:
        value = self.lookup(name, 0)
        if not isinstance(value, str):
            raise KeyError(name)
        return value


def _as_env(consts: Any) -> "_JsEnv":
    if isinstance(consts, _JsEnv):
        return consts
    return _JsEnv("", dict(consts or {}))


def _js_template(text: str, start: int, env: "_JsEnv", hops: int) -> Optional[Tuple[str, int]]:
    """``text[start]`` is a backtick. Returns (content with every ``${...}``
    part evaluated — an unresolvable part contributes nothing —, index after
    the closing backtick)."""
    n = len(text)
    i = start + 1
    out: List[str] = []
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            piece, i = _decode_escape(text, i)
            out.append(piece)
            continue
        if c == "`":
            return "".join(out), i + 1
        if c == "$" and i + 1 < n and text[i + 1] == "{":
            close = _find_matching(text, i + 1, "{", "}")
            if close == -1:
                return None
            value, _ = _js_eval_expr(text[i + 2:close], 0, env, hops)
            if isinstance(value, str):
                out.append(value)
            i = close + 1
            continue
        out.append(c)
        i += 1
    return None


def _js_member(value: Any, prop: str, env: "_JsEnv", hops: int) -> Any:
    if isinstance(value, _JsObject) and prop in value.props:
        return _js_eval_expr(value.props[prop], 0, env, hops)[0]
    if isinstance(value, _JsArray) and prop.isdigit() and int(prop) < len(value.items):
        return _js_eval_expr(value.items[int(prop)], 0, env, hops)[0]
    return None


def _js_method(value: Any, path: List[str], prop: str, args_text: str,
               env: "_JsEnv", hops: int) -> Any:
    args = [a for a in _split_top_level_args(_strip_js_comments(args_text)) if a.strip()]
    if path == ["Object"] and prop in ("freeze", "seal", "assign") and args:
        return _js_eval_expr(args[-1] if prop == "assign" else args[0], 0, env, hops)[0]
    if prop == "join" and isinstance(value, _JsArray):
        sep: Any = ","
        if args:
            sep = _js_eval_expr(args[0], 0, env, hops)[0]
            if not isinstance(sep, str):
                sep = " "
        parts = [_js_eval_expr(item, 0, env, hops)[0] for item in value.items]
        strings = [p for p in parts if isinstance(p, str)]
        return sep.join(strings) if strings else None
    if isinstance(value, str):
        if prop in _JS_TRIMS:
            return _JS_TRIMS[prop](value)
        if prop in _JS_STRING_PASSTHROUGH:
            return value
        if prop == "concat":
            extra = [_js_eval_expr(a, 0, env, hops)[0] for a in args]
            return value + "".join(e for e in extra if isinstance(e, str))
    return None


def _js_eval_term(text: str, pos: int, env: "_JsEnv", hops: int) -> Tuple[Any, int]:
    """One operand and its postfix chain (member access, index, call).
    Returns (value, end); ``end == pos`` means "not an operand at all"."""
    n = len(text)
    i = _skip_ws_comments(text, pos)
    if i >= n:
        return None, pos
    c = text[i]
    value: Any = None
    path: List[str] = []
    if c in ("'", '"'):
        res = _match_string_literal(text, i)
        if res is None:
            return None, pos
        value, i = res
    elif c == "`":
        res = _js_template(text, i, env, hops)
        if res is None:
            return None, pos
        value, i = res
    elif c == "(":
        close = _find_matching(text, i, "(", ")")
        if close == -1:
            return None, pos
        value = _js_eval_expr(text[i + 1:close], 0, env, hops)[0]
        i = close + 1
    elif c == "[":
        close = _find_matching(text, i, "[", "]")
        if close == -1:
            return None, pos
        inner = _strip_js_comments(text[i + 1:close])
        value = _JsArray([seg for seg in _split_top_level_args(inner) if seg.strip()])
        i = close + 1
    elif c == "{":
        close = _find_matching(text, i, "{", "}")
        if close == -1:
            return None, pos
        value = _js_object(text[i + 1:close])
        i = close + 1
    else:
        m = _IDENT_RE.match(text, i)
        if not m or m.group(0) in _JS_NON_VALUE_WORDS:
            return None, pos
        path = [m.group(0)]
        i = m.end()
        value = env.lookup(path[0], hops)
    while True:
        j = _skip_ws_comments(text, i)
        if j >= n:
            break
        ch = text[j]
        if ch == "`" and path:  # tagged template: the tag is ignored
            res = _js_template(text, j, env, hops)
            if res is None:
                break
            value, i = res
            path = []
            continue
        if ch == "?" and text.startswith("?.", j):
            j += 1
            ch = "."
        if ch == "." and not text.startswith("...", j):
            pm = _IDENT_RE.match(text, j + 1)
            if not pm:
                break
            prop = pm.group(0)
            k = _skip_ws(text, pm.end())
            if k < n and text[k] == "(":
                close = _find_matching(text, k, "(", ")")
                if close == -1:
                    break
                value = _js_method(value, path, prop, text[k + 1:close], env, hops)
                path = []
                i = close + 1
            else:
                value = _js_member(value, prop, env, hops)
                if path:
                    path.append(prop)
                i = pm.end()
            continue
        if ch == "[":
            close = _find_matching(text, j, "[", "]")
            if close == -1:
                break
            key_text = text[j + 1:close].strip()
            key = _js_eval_expr(key_text, 0, env, hops)[0]
            if not isinstance(key, str) and key_text.isdigit():
                key = key_text
            value = _js_member(value, key, env, hops) if isinstance(key, str) else None
            path = []
            i = close + 1
            continue
        if ch == "(":
            close = _find_matching(text, j, "(", ")")
            if close == -1:
                break
            value = None  # a call: not statically known
            path = []
            i = close + 1
            continue
        if ch == "!" and not text.startswith("!=", j):
            i = j + 1  # TypeScript non-null assertion
            continue
        break
    return value, i


def _js_eval_expr(text: str, pos: int, env: "_JsEnv", hops: int = 0) -> Tuple[Any, int]:
    """Statically evaluate the expression at ``pos``: one operand, or a
    ``+`` chain of them. In a chain an operand that is not statically a
    string contributes nothing (the literal text around it is what an
    injected instruction lives in). Returns (value, end)."""
    value, i = _js_eval_term(text, pos, env, hops)
    if i == pos:
        return None, pos
    j = _skip_ws_comments(text, i)
    if not (j < len(text) and text[j] == "+" and text[j + 1:j + 2] not in ("+", "=")):
        return value, i
    parts: List[str] = [value] if isinstance(value, str) else []
    resolved = isinstance(value, str)
    while j < len(text) and text[j] == "+" and text[j + 1:j + 2] not in ("+", "="):
        nxt, k = _js_eval_term(text, j + 1, env, hops)
        if k == j + 1:
            break
        if isinstance(nxt, str):
            parts.append(nxt)
            resolved = True
        i = k
        j = _skip_ws_comments(text, i)
    return ("".join(parts) if resolved else None), i


def _js_to_obj(value: Any, env: "_JsEnv", hops: int = 0, depth: int = 0) -> Any:
    """A statically evaluated JS value as a JSON-shaped Python object holding
    only what resolved to strings (nested objects / arrays kept, everything
    else dropped). ``None`` when nothing in it is a string."""
    if isinstance(value, str):
        return value
    if depth > 8:
        return None
    if isinstance(value, _JsObject):
        out: Dict[str, Any] = {}
        for key, expr in value.props.items():
            sub = _js_to_obj(_js_eval_expr(expr, 0, env, hops)[0], env, hops, depth + 1)
            if sub is not None:
                out[key] = sub
        return out or None
    if isinstance(value, _JsArray):
        items = [_js_to_obj(_js_eval_expr(e, 0, env, hops)[0], env, hops, depth + 1)
                 for e in value.items]
        items = [x for x in items if x is not None]
        return items or None
    return None


def _js_listing_entry(obj: Any) -> Dict[str, Any]:
    """v5-6 static twin for JS/TS — the registration's own object fields
    other than the name and the description, as listing-entry fields."""
    if not isinstance(obj, dict):
        return {}
    return {k: v for k, v in obj.items() if k not in ("name", "description")}


def _resolve_js_string_expr(text: str, pos: int, consts: Any = None
                           ) -> Tuple[Optional[str], int]:
    """Resolve the string EXPRESSION starting at ``pos`` (see the block
    comment above for the shapes). ``consts`` is the file's ``_JsEnv`` (or a
    plain name -> string dict). Returns (resolved_text_or_None, index after
    the last token consumed)."""
    value, end = _js_eval_expr(text, pos, _as_env(consts), 0)
    if isinstance(value, str):
        return value, end
    return None, pos


def _collect_js_string_consts(text: str) -> "_JsEnv":
    """The file's binding environment, so a ``description: SOME_CONST`` /
    ``TEXTS.search`` / `` `${PREFIX} ...` `` reference resolves the same way
    a Python ``description=SOME_CONST`` decorator kwarg does."""
    return _JsEnv(text)


# --- tool registration shapes -----------------------------------------------

# High-level SDK: ``server.tool("name", ...)`` / ``server.registerTool("name", ...)``.
_TOOL_CALL_RE = re.compile(
    r"\.(?:tool|registerTool)\s*\(\s*['\"`]([A-Za-z0-9_\-]{1,80})['\"`]"
)
# an immediately-following plain string/concatenation/const arg is the
# (optional) description
_LEADING_COMMA_RE = re.compile(r"^\s*,\s*")
# ``registerTool``'s config-object form: ``{ ... description: "...", ... }``
_DESC_FIELD_START_RE = re.compile(r"\bdescription\s*:\s*")

# Low-level SDK: an array of ``{name: "...", ...}`` object literals (which
# may contain a NESTED ``inputSchema``/``properties`` object of arbitrary
# depth — rule P5.2 needs brace-BALANCED matching, not a regex that stops at
# the first nested ``{``), as returned from a ``ListToolsRequestSchema``
# handler.
_OBJ_TOOL_START_RE = re.compile(
    r"\{\s*name\s*:\s*['\"`]([A-Za-z0-9_\-]{1,80})['\"`]"
)

# --- sinks -------------------------------------------------------------------

_SINK_PATTERNS: Dict[str, re.Pattern] = {
    "command-exec": re.compile(
        r"\b(?:child_process\s*\.\s*)?(?:exec(?:Sync|File(?:Sync)?)?|spawn(?:Sync)?)\s*\("
    ),
    "code-exec": re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
    "network": re.compile(
        r"\bfetch\s*\(|\baxios(?:\s*\.\s*\w+)?\s*\(|\bhttps?\s*\.\s*(?:request|get)\s*\("
    ),
    "file-write": re.compile(
        r"\bfs(?:\s*\.\s*promises)?\s*\.\s*"
        r"(?:writeFile(?:Sync)?|appendFile(?:Sync)?|unlink(?:Sync)?|rm(?:dir)?(?:Sync)?)\s*\("
    ),
    "file-read": re.compile(r"\bfs(?:\s*\.\s*promises)?\s*\.\s*readFile(?:Sync)?\s*\("),
}

# a handler's own parameter list: ``(a, {b, c}) =>`` / ``async function f(a, b) {``
_PARAM_LIST_RE = re.compile(
    r"(?:async\s+)?function\s*[A-Za-z0-9_$]*\s*\(([^)]*)\)|"
    r"(?:async\s*)?\(([^)]*)\)\s*=>|"
    r"(?:async\s*)?([A-Za-z0-9_$]+)\s*=>"
)


def _split_param_names(raw: str) -> List[str]:
    """Split "a, {b, c}, [d, e] = []" into bare identifier tokens."""
    names: List[str] = []
    for tok in re.split(r"[,{}\[\]:=\s]+", raw):
        tok = tok.strip()
        if tok and re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", tok) and tok not in (
                "async", "function"):
            names.append(tok)
    return names


def _extract_handler_params(body: str) -> List[str]:
    """Every plain or destructured parameter name from any arrow-function /
    ``function`` signature found in ``body`` (unioned, best-effort — a tool()
    call's arguments commonly include a schema object literal *and* a
    handler; taking every signature's params rather than isolating exactly
    the handler's own is a deliberate over-approximation that only widens
    what counts as "tainted", never narrows a real handler param out)."""
    names: List[str] = []
    for m in _PARAM_LIST_RE.finditer(body):
        raw = next((g for g in m.groups() if g), "")
        names.extend(_split_param_names(raw))
    return names


# --- rule P5.3 — resolve a handler passed BY NAME to its function body ---------
# ``server.tool("run", "desc", schema, runHandler)`` — the call's own
# argument text contains only the bare identifier ``runHandler``, not the
# function body a sink scan needs. This locates ``runHandler``'s OWN
# definition elsewhere in the file (``function runHandler(...) {...}`` or
# ``const runHandler = (...) => {...}`` / ``= function(...) {...}``) and
# hands back its real parameter-list text and body, so sinks inside it are
# visible the same way they are for an inline handler.


def _split_top_level_args(s: str) -> List[str]:
    """Split a call's argument-list text on top-level commas only (never
    inside nested parens/braces/brackets or a string/template literal)."""
    parts: List[str] = []
    cur: List[str] = []
    depth = 0
    in_str: Optional[str] = None
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if in_str:
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(s[i + 1])
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ("'", '"', "`"):
            in_str = c
            cur.append(c)
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if cur:
        parts.append("".join(cur))
    return parts


def _find_function_body_by_name(text: str, name: str) -> Optional[Tuple[str, str]]:
    """Returns (param_list_text, body_text) for ``name``'s own function
    definition anywhere in ``text``, or ``None`` if it cannot be found as a
    brace-bodied function/arrow function."""
    pat_fn = re.compile(r"\bfunction\s+" + re.escape(name) + r"\s*\(")
    m = pat_fn.search(text)
    if not m:
        pat_arrow = re.compile(
            r"\b(?:const|let|var)\s+" + re.escape(name)
            + r"\s*=\s*(?:async\s*)?(?:function\b\s*)?\("
        )
        m = pat_arrow.search(text)
    if not m:
        return None
    open_paren = m.end() - 1  # both patterns end with the literal "("
    if text[open_paren] != "(":
        return None
    close_paren = _find_matching(text, open_paren, "(", ")")
    if close_paren == -1:
        return None
    # the body's opening "{" follows shortly after (allowing "=>"/return-type
    # annotations in between, never a whole separate statement)
    brace_idx = text.find("{", close_paren)
    if brace_idx == -1 or brace_idx - close_paren > 80:
        return None
    close_brace = _find_matching(text, brace_idx, "{", "}")
    if close_brace == -1:
        return None
    return text[open_paren + 1:close_paren], text[brace_idx + 1:close_brace]


# --- rule P5.4 — schema-builder (zod-style) parameter names + description text -
# ``z.object({ url: z.string().describe("The URL to fetch"), ... })`` — read
# each property NAME and any ``.describe("...")`` text chained onto its
# value, so the SAME schema-field description rules that already run over a
# Python tool's JSON-Schema ``properties[*].description`` (poisoning.py) run
# over a JS/TS tool's zod schema too, with no new detector code.
_ZOD_PROP_START_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(?=z\s*\.)")


def _extract_zod_properties(text: str, consts: Any) -> Dict[str, Dict[str, Any]]:
    props: Dict[str, Dict[str, Any]] = {}
    for m in _ZOD_PROP_START_RE.finditer(text):
        name = m.group(1)
        i, n = m.end(), len(text)
        depth = 0
        describe_text: Optional[str] = None
        while i < n:
            c = text[i]
            if c in "([{":
                depth += 1
                i += 1
                continue
            if c in ")]}":
                if depth == 0:
                    break
                depth -= 1
                i += 1
                continue
            if depth == 0 and c == ",":
                break
            if depth == 0 and text.startswith(".describe(", i):
                open_idx = i + len(".describe")
                close_idx = _find_matching(text, open_idx, "(", ")")
                if close_idx != -1:
                    val, _ = _resolve_js_string_expr(text, open_idx + 1, consts)
                    if isinstance(val, str):
                        describe_text = val
                    i = close_idx + 1
                    continue
            i += 1
        entry = props.setdefault(name, {"type": "string"})
        if describe_text is not None:
            entry["description"] = describe_text
    return props


# v3-1.2 — does a JS/TS handler body RETURN content derived from a network
# call / file read? Text-level approximation of the Python engine's
# ``returns_external_content``: a local bound from a fetch/axios/http/
# readFile call (one further hop through ``x = await resp.text()/json()``
# allowed), referenced inside a ``return`` expression — or a ``return`` that
# directly wraps such a call. Mere presence of the read elsewhere in the body
# is NOT enough.
_JS_READ_CALL_RE = re.compile(
    r"\b(?:fetch|axios(?:\s*\.\s*\w+)?|got|superagent|https?\s*\.\s*(?:request|get)|"
    r"fs(?:\s*\.\s*promises)?\s*\.\s*readFile(?:Sync)?|readFile(?:Sync)?|"
    r"fsp\s*\.\s*readFile)\s*\(")
_JS_BIND_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?([^;\n]*)")
_JS_RETURN_RE = re.compile(r"\breturn\b([^;]*)")


def _js_returns_external_content(body: str) -> bool:
    derived: set = set()
    for m in _JS_BIND_RE.finditer(body):
        name, rhs = m.group(1), m.group(2)
        if _JS_READ_CALL_RE.search(rhs) or any(
                re.search(r"\b" + re.escape(d) + r"\b", rhs) for d in derived):
            derived.add(name)
    for m in _JS_RETURN_RE.finditer(body):
        expr = m.group(1)
        if _JS_READ_CALL_RE.search(expr):
            return True
        if any(re.search(r"\b" + re.escape(d) + r"\b", expr) for d in derived):
            return True
    return False


# v4-9 — one level of TEXTUAL taint flow inside a handler body. A local
# bound (``const``/``let``/``var``, destructuring, or a plain/``+=``
# assignment) from an expression that mentions a handler parameter — or a
# property of the arguments object (``args.path``, ``request.params.
# arguments.cmd``: the object IS the parameter) — is tainted by that
# parameter's roots; string concatenation and template literals count as
# flow because the mention is all that is tested. Bindings are read in
# source order, so ``const { arguments: args } = request.params`` followed
# by ``const cmd = args.command`` taints ``cmd`` too.
_JS_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
_JS_BINDING_RE = re.compile(
    r"\b(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|" + _JS_IDENT + r")\s*=(?!=)\s*([^;\n]+)"
    r"|(?<![\w$.])(" + _JS_IDENT + r")\s*(?:\+=|=(?![=>]))\s*([^;\n]+)")
_JS_SHELL_OPTION_RE = re.compile(r"\bshell\s*:\s*true\b")
_JS_SHELL_CALL_RE = re.compile(r"^(?:child_process\s*\.\s*)?exec(?:Sync)?\s*\($")
_JS_KEYWORDS = frozenset({"const", "let", "var", "if", "else", "for", "while", "return",
                          "await", "async", "function", "new", "typeof", "true", "false",
                          "null", "undefined", "this"})


def _js_name_rx(name: str) -> re.Pattern:
    # a bare mention, not a property of something else (``foo.args`` is not ``args``)
    return re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])")


def _js_tainted_locals(body: str, params: List[str]) -> Dict[str, Set[str]]:
    """name -> the handler parameters it derives from (params map to
    themselves); one ordered pass over the bindings of ``body``."""
    taint: Dict[str, Set[str]] = {p: {p} for p in params if len(p) >= 2}
    rxs: Dict[str, re.Pattern] = {n: _js_name_rx(n) for n in taint}
    for m in _JS_BINDING_RE.finditer(body):
        target, expr = (m.group(1), m.group(2)) if m.group(1) is not None else (m.group(3), m.group(4))
        roots: Set[str] = set()
        for n, rx in list(rxs.items()):
            if rx.search(expr):
                roots |= taint[n]
        if not roots:
            continue
        for bound in _split_param_names(target):
            if len(bound) < 2 or bound in _JS_KEYWORDS:
                continue
            taint[bound] = taint.get(bound, set()) | roots
            rxs.setdefault(bound, _js_name_rx(bound))
    return taint


def _sink_records(body: str, params: List[str], base_lineno: int) -> List[SinkRecord]:
    out: List[SinkRecord] = []
    taint = _js_tainted_locals(body, params)
    rxs = {n: _js_name_rx(n) for n in taint}
    param_set = set(params)
    for kind, pat in _SINK_PATTERNS.items():
        for m in pat.finditer(body):
            open_idx = m.end() - 1  # pattern always ends with the literal "("
            close_idx = _find_matching(body, open_idx)
            arg_text = body[open_idx + 1: close_idx] if close_idx != -1 else ""
            hit = sorted(n for n, rx in rxs.items() if rx.search(arg_text))
            direct = [n for n in hit if n in param_set]
            # a sink whose arguments mention no handler parameter (directly
            # or through a tainted local) is a capability fact, not taint
            tainted = bool(hit)
            lineno = base_lineno + body.count("\n", 0, m.start())
            snippet = " ".join(body[max(0, m.start() - 10):m.start() + 80].split())[:200]
            shell = kind == "command-exec" and bool(
                _JS_SHELL_CALL_RE.match(m.group(0).strip()) or _JS_SHELL_OPTION_RE.search(arg_text))
            out.append(SinkRecord(
                kind=kind, lineno=lineno, call=m.group(0).rstrip("("),
                tainted=tainted, shell=shell,
                # like the Python engine: a parameter reaching the sink by
                # name is direct (high confidence); through a local it is
                # attributed to the local (medium)
                tainted_params=sorted(direct) if direct else hit,
                snippet=snippet, arg_names=hit, sanitized=False,
            ))
    return out


def extract_js_tools(text: str) -> List[Tuple[ToolDef, BehaviorFacts]]:
    """Every tool this JS/TS source registers, high-level or low-level SDK
    shape, each paired with a ``BehaviorFacts`` populated only with the
    sinks found inside that specific registration call's body (everything
    else stays at its dataclass default — JS/TS behavior facts are
    deliberately narrower than the Python engine's, limited to what a
    text-level scan can support without guessing)."""
    out: List[Tuple[ToolDef, BehaviorFacts]] = []
    seen_names: set = set()
    consts = _collect_js_string_consts(text)
    # rule P5.4 — zod-style schema-builder properties, scanned once over the
    # whole file (a schema object is commonly defined as its own
    # ``const paramsSchema = z.object({...})`` referenced by name, same as a
    # description constant) and intersected per-tool with that tool's own
    # ``params`` below.
    zod_props = _extract_zod_properties(text, consts)

    for m in _TOOL_CALL_RE.finditer(text):
        name = m.group(1)
        open_idx = text.find("(", m.start())
        if open_idx == -1:
            continue
        close_idx = _find_matching(text, open_idx)
        if close_idx == -1:
            continue
        body = text[open_idx + 1: close_idx]
        # description: either a leading bare string/concatenation/const arg,
        # or a `description:` field inside a config-object argument (rule P5.1 —
        # delimiter-aware, so an apostrophe inside a template-literal
        # description no longer truncates it).
        rest_after_name = text[m.end():close_idx]
        lm = _LEADING_COMMA_RE.match(rest_after_name)
        desc = ""
        if lm:
            val, _ = _resolve_js_string_expr(rest_after_name, lm.end(), consts)
            if isinstance(val, str):
                desc = val
        if not desc:
            fm = _DESC_FIELD_START_RE.search(body)
            if fm:
                val, _ = _resolve_js_string_expr(body, fm.end(), consts)
                if isinstance(val, str):
                    desc = val
        # rule P5.3 — if the LAST top-level argument is a bare identifier (a
        # handler passed BY NAME, not written inline), resolve it to its own
        # function body before extracting params/scanning for sinks.
        sink_scan_body = body
        top_args = _split_top_level_args(body)
        if top_args and re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", top_args[-1].strip()):
            resolved = _find_function_body_by_name(text, top_args[-1].strip())
            if resolved:
                param_text, handler_body = resolved
                params = _split_param_names(param_text) or _extract_handler_params(body)
                sink_scan_body = handler_body
            else:
                params = _extract_handler_params(body)
        else:
            params = _extract_handler_params(body)
        lineno = 1 + text.count("\n", 0, m.start())
        facts = BehaviorFacts()
        facts.sinks = _sink_records(sink_scan_body, params, lineno)
        facts.writes_fs = any(s.kind == "file-write" for s in facts.sinks)
        facts.reads_fs = any(s.kind == "file-read" for s in facts.sinks)
        facts.spawns_proc = any(s.kind == "command-exec" for s in facts.sinks)
        facts.code_exec = any(s.kind == "code-exec" for s in facts.sinks)
        facts.network = any(s.kind == "network" for s in facts.sinks)
        if facts.network or facts.reads_fs:
            facts.returns_external_content = _js_returns_external_content(sink_scan_body)
        schema_properties = {p: zod_props[p] for p in params if p in zod_props}
        # v5-6 static twin — the registration's object-literal arguments:
        # ``registerTool(name, {title, description, annotations, ...}, cb)``
        # contributes its own fields; a positional annotations object of
        # ``tool(name, desc, schema, {title, readOnlyHint, ...}, cb)`` is
        # recognised by its keys (a title or a *Hint key).
        listing_entry: Dict[str, Any] = {}
        for arg in top_args[1:]:
            if not arg.lstrip().startswith("{"):
                continue
            val = _js_eval_expr(arg, 0, consts, 0)[0]
            if not isinstance(val, _JsObject):
                continue
            keys = set(val.props)
            obj = _js_to_obj(val, consts)
            if not isinstance(obj, dict):
                continue
            if "description" in keys or "inputSchema" in keys:
                for k, v in _js_listing_entry(obj).items():
                    listing_entry.setdefault(k, v)
            elif "title" in keys or any(k.endswith("Hint") for k in keys):
                listing_entry.setdefault("annotations", obj)
        td = ToolDef(name=name, func_name=name, lineno=lineno, description=desc,
                     hints={}, params=params, kind="tool", node=None,
                     schema_properties=schema_properties, listing_entry=listing_entry)
        out.append((td, facts))
        seen_names.add(name)

    # low-level SDK: object-literal tool descriptors not already captured
    # above. rule P5.2 — brace-BALANCED matching (not a regex that stops at the
    # first nested "{"), so a tool object containing a nested inputSchema/
    # properties object of any depth is still captured whole.
    for m in _OBJ_TOOL_START_RE.finditer(text):
        name = m.group(1)
        if name in seen_names:
            continue
        open_idx = m.start()
        close_idx = _find_matching(text, open_idx, "{", "}")
        if close_idx == -1:
            continue
        obj_text = text[open_idx:close_idx + 1]
        desc = ""
        fm = _DESC_FIELD_START_RE.search(obj_text)
        if fm:
            val, _ = _resolve_js_string_expr(obj_text, fm.end(), consts)
            if isinstance(val, str):
                desc = val
        # rule P5.2 — also read the nested inputSchema/properties object's own
        # param names + description text, same as the JSON-Schema
        # ``properties[*].description`` shape (schema-poisoning already
        # scans this on ANY contract once it is populated).
        schema_properties: Dict[str, Dict[str, Any]] = {}
        # v5-8 — read the descriptor through the static evaluator first:
        # the TOP-LEVEL properties only (a nested object's own keys are not
        # parameters of the tool), each description resolved like any other
        # indirectly held text. The textual scan below is the fallback for a
        # descriptor the evaluator cannot make sense of.
        descriptor_val = _js_eval_expr(obj_text, 0, consts, 0)[0]
        props_val = None
        for schema_key in ("inputSchema", "input_schema", "schema"):
            schema_val = _js_member(descriptor_val, schema_key, consts, 0)
            if isinstance(schema_val, _JsObject):
                props_val = _js_member(schema_val, "properties", consts, 0)
                break
        sm = None
        if isinstance(props_val, _JsObject):
            for pname, pexpr in props_val.props.items():
                entry = {"type": "string"}
                pval = _js_eval_expr(pexpr, 0, consts, 0)[0]
                pdesc = _js_member(pval, "description", consts, 0)
                if isinstance(pdesc, str):
                    entry["description"] = pdesc
                schema_properties[pname] = entry
        else:
            sm = re.search(r"\b(?:inputSchema|schema)\s*:\s*\{", obj_text)
        if sm:
            schema_open = obj_text.index("{", sm.start())
            schema_close = _find_matching(obj_text, schema_open, "{", "}")
            schema_text = obj_text[schema_open:schema_close + 1] if schema_close != -1 else ""
            pm = re.search(r"\bproperties\s*:\s*\{", schema_text)
            if pm:
                props_open = schema_text.index("{", pm.start())
                props_close = _find_matching(schema_text, props_open, "{", "}")
                props_text = (schema_text[props_open + 1:props_close]
                             if props_close != -1 else "")
                for fnm in re.finditer(
                        r"([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*\{", props_text):
                    fopen = props_text.index("{", fnm.start())
                    fclose = _find_matching(props_text, fopen, "{", "}")
                    ftext = props_text[fopen:fclose + 1] if fclose != -1 else ""
                    entry: Dict[str, Any] = {"type": "string"}
                    dm2 = _DESC_FIELD_START_RE.search(ftext)
                    if dm2:
                        dval, _ = _resolve_js_string_expr(ftext, dm2.end(), consts)
                        if isinstance(dval, str):
                            entry["description"] = dval
                    schema_properties[fnm.group(1)] = entry
        lineno = 1 + text.count("\n", 0, m.start())
        # v5-6 static twin — every other string field of the descriptor
        descriptor = _js_to_obj(descriptor_val, consts)
        td = ToolDef(name=name, func_name=name, lineno=lineno, description=desc,
                     hints={}, params=list(schema_properties.keys()), kind="tool",
                     node=None, schema_properties=schema_properties,
                     listing_entry=_js_listing_entry(descriptor))
        out.append((td, BehaviorFacts()))
        seen_names.add(name)

    return out
