"""v6-W6 — deterministic constant folding for string-assembling expressions.

A literal-based matcher (static response poisoning, the tool description poison
families) is blind to a string that never appears as a literal: an
agent-directed instruction assembled at runtime from integer CONSTANTS --
``"".join(chr(c) for c in (73, 103, ...))``, ``chr(73) + chr(103) + ...``,
``bytes([73, 103, ...]).decode()``, a loop that appends ``chr(c)`` for each
``c`` of a constant tuple. None of that needs a runtime: it is a pure function
of constants, so the scanner evaluates it.

This module is a SAFE evaluator for a closed subset of Python expressions
(ints, strings, bytes, tuples/lists, ``chr``/``ord``/``bytes``/``str``/
``int``/``len``/``range``/``map``/``reversed``, ``str.join``/``decode``/
``encode``/``replace``/..., comprehensions and generators over constant
iterables, slices, ``%`` formatting). It never calls ``eval`` and never
touches anything outside the expression it is handed. Anything outside the
subset -- a name that is not a known constant (e.g. a tool PARAMETER), an
unknown call -- raises ``NoFold`` and the expression is simply "not
constant". That is the distinguishing feature: ``chr(ord(c) + 1) for c in
text`` (``text`` a caller input) never folds, so an encoder/decoder whose job
is converting the CALLER's data is never mistaken for obfuscation.

``FoldInfo`` records HOW a value was assembled (how many ``chr`` calls ran on
constants, whether a literal integer sequence fed them, or only a
formula-defined ``range``), which is what the obfuscation signal keys on.
"""
from __future__ import annotations

import ast
import operator
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

NOFOLD = object()

_MAX_STEPS = 60000
_MAX_SEQ = 8192
_MAX_STR = 200000
_MAX_LOOP = 4096

# the number of chr() calls on constants (or constant codepoints decoded
# from a literal integer sequence) at which an expression is an assembly
# chain rather than an incidental ``chr(10)``.
ASSEMBLY_MIN_CHARS = 4


class NoFold(Exception):
    """The expression is not a pure function of constants."""


@dataclass
class FoldInfo:
    const_chr_calls: int = 0     # chr() evaluated outside any comprehension scope
    iter_chr_calls: int = 0      # chr() evaluated once per element of a comprehension/map
    literal_seq_max: int = 0     # longest LITERAL tuple/list of ints/chars that was folded
    bytes_codepoints: int = 0    # codepoints decoded from bytes(<int sequence>)
    used_range: bool = False

    def merge(self, other: "FoldInfo") -> None:
        self.const_chr_calls += other.const_chr_calls
        self.iter_chr_calls += other.iter_chr_calls
        self.literal_seq_max = max(self.literal_seq_max, other.literal_seq_max)
        self.bytes_codepoints += other.bytes_codepoints
        self.used_range = self.used_range or other.used_range

    @property
    def char_count(self) -> int:
        return self.const_chr_calls + self.iter_chr_calls + self.bytes_codepoints

    @property
    def assembled(self) -> bool:
        """True when the value was built character-by-character from
        constants: a chain of ``chr(<constant>)`` calls, or chr()/bytes()
        applied over a LITERAL integer sequence. A ``range()``-defined
        alphabet (``chr(65 + i) for i in range(26)``) is a formula, not a
        hidden literal, and does not count."""
        if self.const_chr_calls >= ASSEMBLY_MIN_CHARS:
            return True
        return (self.literal_seq_max >= ASSEMBLY_MIN_CHARS
                and self.iter_chr_calls + self.bytes_codepoints >= ASSEMBLY_MIN_CHARS)


_BINOPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
    ast.BitXor: operator.xor, ast.BitOr: operator.or_, ast.BitAnd: operator.and_,
    ast.LShift: operator.lshift, ast.RShift: operator.rshift,
}
_CMPOPS = {
    ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt,
    ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
}
_SAFE_CODECS = {"utf-8": "utf-8", "utf8": "utf-8", "ascii": "ascii",
                "latin-1": "latin-1", "latin1": "latin-1", "iso-8859-1": "latin-1",
                "utf-16": "utf-16", "utf-16le": "utf-16-le", "utf-16-le": "utf-16-le"}
_SEQ = (tuple, list)


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


class _Folder:
    def __init__(self, env: Dict[str, Any]):
        self.env = env
        self.steps = 0
        self.info = FoldInfo()
        self.scope_depth = 0  # >0 while evaluating a comprehension element / map body

    # -- helpers -------------------------------------------------------------
    def tick(self) -> None:
        self.steps += 1
        if self.steps > _MAX_STEPS:
            raise NoFold("budget")

    def note_seq(self, v: Any, literal: bool = True) -> None:
        if isinstance(v, _SEQ) and len(v) >= ASSEMBLY_MIN_CHARS and literal:
            if all(_is_int(x) or (isinstance(x, str) and len(x) == 1) for x in v):
                self.info.literal_seq_max = max(self.info.literal_seq_max, len(v))

    @staticmethod
    def check_str(v: Any) -> Any:
        if isinstance(v, (str, bytes)) and len(v) > _MAX_STR:
            raise NoFold("too long")
        if isinstance(v, _SEQ) and len(v) > _MAX_SEQ:
            raise NoFold("too long")
        return v

    def iterable(self, v: Any) -> List[Any]:
        if isinstance(v, str):
            return list(v)
        if isinstance(v, bytes):
            return list(v)
        if isinstance(v, _SEQ):
            return list(v)
        raise NoFold("not iterable")

    # -- evaluation ----------------------------------------------------------
    def ev(self, node: ast.AST, loc: Dict[str, Any]) -> Any:
        self.tick()
        if isinstance(node, ast.Constant):
            v = node.value
            if v is Ellipsis:
                raise NoFold("ellipsis")
            return v
        if isinstance(node, ast.Name):
            if node.id in loc:
                return loc[node.id]
            if node.id in self.env:
                v = self.env[node.id]
                if v is NOFOLD:
                    raise NoFold("unknown")
                # a named literal sequence is still a literal sequence
                self.note_seq(v)
                return v
            raise NoFold(f"free name {node.id}")
        if isinstance(node, ast.Attribute):
            # dotted constants resolved through an imported module alias
            # (``_gate.NOTICE``): the environment carries "alias.NAME" keys.
            dn = _dotted(node)
            if dn and dn in self.env:
                v = self.env[dn]
                if v is NOFOLD:
                    raise NoFold("unknown")
                self.note_seq(v)
                return v
            raise NoFold("attribute")
        if isinstance(node, (ast.Tuple, ast.List)):
            vals = []
            for e in node.elts:
                if isinstance(e, ast.Starred):
                    raise NoFold("starred")
                vals.append(self.ev(e, loc))
            out = tuple(vals) if isinstance(node, ast.Tuple) else list(vals)
            self.note_seq(out)
            return self.check_str(out)
        if isinstance(node, ast.UnaryOp):
            v = self.ev(node.operand, loc)
            if isinstance(node.op, ast.USub) and _is_int(v):
                return -v
            if isinstance(node.op, ast.UAdd) and _is_int(v):
                return v
            if isinstance(node.op, ast.Invert) and _is_int(v):
                return ~v
            if isinstance(node.op, ast.Not):
                return not v
            raise NoFold("unary")
        if isinstance(node, ast.BinOp):
            return self.binop(node, loc)
        if isinstance(node, ast.BoolOp):
            result: Any = None
            for i, e in enumerate(node.values):
                result = self.ev(e, loc)
                if isinstance(node.op, ast.And) and not result:
                    return result
                if isinstance(node.op, ast.Or) and result:
                    return result
            return result
        if isinstance(node, ast.Compare):
            left = self.ev(node.left, loc)
            for op, comp in zip(node.ops, node.comparators):
                right = self.ev(comp, loc)
                fn = _CMPOPS.get(type(op))
                if fn is None:
                    raise NoFold("cmp")
                try:
                    ok = fn(left, right)
                except TypeError:
                    raise NoFold("cmp type")
                if not ok:
                    return False
                left = right
            return True
        if isinstance(node, ast.IfExp):
            return self.ev(node.body if self.ev(node.test, loc) else node.orelse, loc)
        if isinstance(node, ast.Subscript):
            return self.subscript(node, loc)
        if isinstance(node, ast.JoinedStr):
            parts: List[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                elif isinstance(v, ast.FormattedValue):
                    if v.format_spec is not None or v.conversion not in (-1, None):
                        raise NoFold("fstring spec")
                    fv = self.ev(v.value, loc)
                    if not isinstance(fv, (str, int)) or isinstance(fv, bool):
                        raise NoFold("fstring value")
                    parts.append(str(fv))
                else:
                    raise NoFold("fstring")
            return self.check_str("".join(parts))
        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            return self.check_str(self.comprehension(node, loc))
        if isinstance(node, ast.Call):
            return self.call(node, loc)
        raise NoFold(type(node).__name__)

    def binop(self, node: ast.BinOp, loc: Dict[str, Any]) -> Any:
        a = self.ev(node.left, loc)
        b = self.ev(node.right, loc)
        t = type(node.op)
        fn = _BINOPS.get(t)
        if fn is None:
            raise NoFold("binop")
        if t is ast.Add:
            ok = ((isinstance(a, str) and isinstance(b, str))
                  or (isinstance(a, bytes) and isinstance(b, bytes))
                  or (isinstance(a, tuple) and isinstance(b, tuple))
                  or (isinstance(a, list) and isinstance(b, list))
                  or (_is_int(a) and _is_int(b)))
            if not ok:
                raise NoFold("add types")
            return self.check_str(a + b)
        if t is ast.Mult:
            if _is_int(a) and _is_int(b):
                if abs(a) > 10 ** 9 or abs(b) > 10 ** 9:
                    raise NoFold("big")
                return a * b
            seq, n = (a, b) if _is_int(b) else (b, a)
            if isinstance(seq, (str, bytes, tuple, list)) and _is_int(n):
                if n < 0 or len(seq) * n > _MAX_STR:
                    raise NoFold("big")
                return self.check_str(seq * n)
            raise NoFold("mult types")
        if t is ast.Mod:
            if isinstance(a, str):
                try:
                    return self.check_str(a % b)
                except (TypeError, ValueError):
                    raise NoFold("format")
            if _is_int(a) and _is_int(b) and b != 0:
                return a % b
            raise NoFold("mod types")
        if t in (ast.LShift, ast.RShift):
            if not (_is_int(a) and _is_int(b)) or b < 0 or b > 64:
                raise NoFold("shift")
            return fn(a, b)
        if not (_is_int(a) and _is_int(b)):
            raise NoFold("int op types")
        if t is ast.FloorDiv and b == 0:
            raise NoFold("div0")
        return fn(a, b)

    def subscript(self, node: ast.Subscript, loc: Dict[str, Any]) -> Any:
        base = self.ev(node.value, loc)
        if not isinstance(base, (str, bytes, tuple, list)):
            raise NoFold("subscript base")
        sl = node.slice
        if isinstance(sl, ast.Slice):
            lo = self.ev(sl.lower, loc) if sl.lower is not None else None
            hi = self.ev(sl.upper, loc) if sl.upper is not None else None
            st = self.ev(sl.step, loc) if sl.step is not None else None
            for x in (lo, hi, st):
                if x is not None and not _is_int(x):
                    raise NoFold("slice type")
            if st == 0:
                raise NoFold("slice step")
            return base[lo:hi:st]
        idx = self.ev(sl, loc)
        if not _is_int(idx):
            raise NoFold("index")
        try:
            v = base[idx]
        except IndexError:
            raise NoFold("index range")
        return v

    # -- comprehensions ------------------------------------------------------
    def comprehension(self, node: ast.AST, loc: Dict[str, Any]) -> list:
        gens = node.generators  # type: ignore[attr-defined]
        out: List[Any] = []

        def run(gi: int, bound: Dict[str, Any]) -> None:
            if gi == len(gens):
                self.scope_depth += 1
                try:
                    out.append(self.ev(node.elt, bound))  # type: ignore[attr-defined]
                finally:
                    self.scope_depth -= 1
                if len(out) > _MAX_SEQ:
                    raise NoFold("too many")
                return
            g = gens[gi]
            if g.is_async:
                raise NoFold("async")
            items = self.iterable(self.ev(g.iter, bound))
            if len(items) > _MAX_LOOP:
                raise NoFold("loop too long")
            for item in items:
                nb = dict(bound)
                self.bind(g.target, item, nb)
                if all(self.ev(c, nb) for c in g.ifs):
                    run(gi + 1, nb)

        run(0, dict(loc))
        return out

    def bind(self, target: ast.AST, value: Any, into: Dict[str, Any]) -> None:
        if isinstance(target, ast.Name):
            into[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            vals = self.iterable(value)
            if len(vals) != len(target.elts):
                raise NoFold("unpack")
            for t, v in zip(target.elts, vals):
                self.bind(t, v, into)
            return
        raise NoFold("bind target")

    # -- calls ---------------------------------------------------------------
    def call(self, node: ast.Call, loc: Dict[str, Any]) -> Any:
        if node.keywords and not _only_codec_keywords(node):
            raise NoFold("keywords")
        func = node.func
        if isinstance(func, ast.Name):
            return self.call_builtin(func.id, node, loc)
        if isinstance(func, ast.Attribute):
            # bytes.fromhex("...")
            if (isinstance(func.value, ast.Name) and func.value.id == "bytes"
                    and func.attr == "fromhex" and len(node.args) == 1):
                s = self.ev(node.args[0], loc)
                if not isinstance(s, str):
                    raise NoFold("fromhex")
                try:
                    b = bytes.fromhex(s)
                except ValueError:
                    raise NoFold("fromhex")
                if len(b) >= ASSEMBLY_MIN_CHARS:
                    self.info.literal_seq_max = max(self.info.literal_seq_max, len(b))
                return self.check_str(b)
            recv = self.ev(func.value, loc)
            return self.call_method(recv, func.attr, node, loc)
        raise NoFold("call target")

    def args(self, node: ast.Call, loc: Dict[str, Any]) -> List[Any]:
        out = []
        for a in node.args:
            if isinstance(a, ast.Starred):
                raise NoFold("starred arg")
            out.append(self.ev(a, loc))
        return out

    def call_builtin(self, name: str, node: ast.Call, loc: Dict[str, Any]) -> Any:
        if name in loc or name in self.env:
            raise NoFold("shadowed builtin")
        if name == "map":
            return self.call_map(node, loc)
        a = self.args(node, loc)
        if name == "chr" and len(a) == 1:
            if not _is_int(a[0]) or not 0 <= a[0] <= 0x10FFFF:
                raise NoFold("chr arg")
            if self.scope_depth:
                self.info.iter_chr_calls += 1
            else:
                self.info.const_chr_calls += 1
            return chr(a[0])
        if name == "ord" and len(a) == 1:
            if isinstance(a[0], str) and len(a[0]) == 1:
                return ord(a[0])
            if isinstance(a[0], bytes) and len(a[0]) == 1:
                return a[0][0]
            raise NoFold("ord arg")
        if name in ("bytes", "bytearray"):
            return self.call_bytes(name, a)
        if name == "str" and len(a) == 1:
            if isinstance(a[0], (str, int)) and not isinstance(a[0], bool):
                return str(a[0])
            raise NoFold("str arg")
        if name == "int" and 1 <= len(a) <= 2:
            try:
                return int(*a)
            except (TypeError, ValueError):
                raise NoFold("int arg")
        if name == "len" and len(a) == 1 and isinstance(a[0], (str, bytes, tuple, list)):
            return len(a[0])
        if name in ("list", "tuple") and len(a) == 1:
            items = self.iterable(a[0])
            return self.check_str(list(items) if name == "list" else tuple(items))
        if name == "reversed" and len(a) == 1:
            return self.check_str(list(reversed(self.iterable(a[0]))))
        if name == "range" and 1 <= len(a) <= 3 and all(_is_int(x) for x in a):
            r = range(*a)
            if len(r) > _MAX_LOOP:
                raise NoFold("range too long")
            self.info.used_range = True
            return list(r)
        if name == "abs" and len(a) == 1 and _is_int(a[0]):
            return abs(a[0])
        raise NoFold(f"call {name}")

    def call_bytes(self, name: str, a: List[Any]) -> Any:
        if len(a) == 1 and isinstance(a[0], _SEQ):
            if not all(_is_int(x) and 0 <= x <= 255 for x in a[0]):
                raise NoFold("bytes values")
            b = bytes(a[0])
            if len(b) >= ASSEMBLY_MIN_CHARS:
                # a literal integer sequence turned into bytes: the decode
                # step that follows is what makes it a string.
                self.info.literal_seq_max = max(self.info.literal_seq_max, len(b))
            return b if name == "bytes" else _ByteArray(b)
        if len(a) >= 1 and isinstance(a[0], str) and len(a) >= 2 and isinstance(a[1], str):
            codec = _SAFE_CODECS.get(a[1].lower())
            if codec is None:
                raise NoFold("codec")
            try:
                b = a[0].encode(codec)
            except UnicodeError:
                raise NoFold("encode")
            return b if name == "bytes" else _ByteArray(b)
        raise NoFold("bytes args")

    def call_map(self, node: ast.Call, loc: Dict[str, Any]) -> Any:
        if len(node.args) != 2:
            raise NoFold("map arity")
        fn_node = node.args[0]
        items = self.iterable(self.ev(node.args[1], loc))
        if len(items) > _MAX_LOOP:
            raise NoFold("map too long")
        out: List[Any] = []
        if isinstance(fn_node, ast.Name) and fn_node.id in ("chr", "ord", "str", "int", "abs"):
            for item in items:
                self.scope_depth += 1
                try:
                    fake = ast.Call(func=fn_node, args=[ast.Constant(value=item)], keywords=[])
                    out.append(self.call_builtin(fn_node.id, fake, loc))
                finally:
                    self.scope_depth -= 1
            return out
        if (isinstance(fn_node, ast.Lambda) and len(fn_node.args.args) == 1
                and not fn_node.args.vararg and not fn_node.args.kwarg):
            pname = fn_node.args.args[0].arg
            for item in items:
                nb = dict(loc)
                nb[pname] = item
                self.scope_depth += 1
                try:
                    out.append(self.ev(fn_node.body, nb))
                finally:
                    self.scope_depth -= 1
            return out
        raise NoFold("map function")

    def call_method(self, recv: Any, meth: str, node: ast.Call, loc: Dict[str, Any]) -> Any:
        if isinstance(recv, _ByteArray):
            recv = bytes(recv)
        if isinstance(recv, str):
            if meth == "join":
                a = self.args(node, loc)
                if len(a) != 1:
                    raise NoFold("join")
                items = self.iterable(a[0])
                if not all(isinstance(x, str) for x in items):
                    raise NoFold("join items")
                return self.check_str(recv.join(items))
            if meth in ("lower", "upper", "strip", "lstrip", "rstrip", "title",
                        "capitalize", "swapcase"):
                a = self.args(node, loc)
                if not all(isinstance(x, str) for x in a) or len(a) > 1:
                    raise NoFold("str method args")
                return getattr(recv, meth)(*a)
            if meth == "replace":
                a = self.args(node, loc)
                if len(a) != 2 or not all(isinstance(x, str) for x in a):
                    raise NoFold("replace")
                return self.check_str(recv.replace(*a))
            if meth == "format":
                a = self.args(node, loc)
                if not all(isinstance(x, (str, int)) for x in a):
                    raise NoFold("format args")
                try:
                    return self.check_str(recv.format(*a))
                except (IndexError, KeyError, ValueError):
                    raise NoFold("format")
            if meth == "split":
                a = self.args(node, loc)
                if len(a) > 1 or not all(isinstance(x, str) for x in a):
                    raise NoFold("split")
                return recv.split(*a)
            if meth == "encode":
                codec = self.codec_arg(node, loc)
                try:
                    return self.check_str(recv.encode(codec))
                except UnicodeError:
                    raise NoFold("encode")
        if isinstance(recv, bytes) and meth == "decode":
            codec = self.codec_arg(node, loc)
            try:
                s = recv.decode(codec, errors="replace")
            except (UnicodeError, LookupError):
                raise NoFold("decode")
            if (self.info.literal_seq_max >= ASSEMBLY_MIN_CHARS
                    or len(recv) >= ASSEMBLY_MIN_CHARS):
                self.info.bytes_codepoints += len(s)
            return self.check_str(s)
        raise NoFold(f"method {meth}")

    def codec_arg(self, node: ast.Call, loc: Dict[str, Any]) -> str:
        name = "utf-8"
        if node.args:
            v = self.ev(node.args[0], loc)
            if not isinstance(v, str):
                raise NoFold("codec arg")
            name = v
        for kw in node.keywords:
            if kw.arg == "encoding":
                v = self.ev(kw.value, loc)
                if not isinstance(v, str):
                    raise NoFold("codec arg")
                name = v
        codec = _SAFE_CODECS.get(name.lower())
        if codec is None:
            raise NoFold("codec")
        return codec


class _ByteArray(bytes):
    """A bytearray stand-in: an immutable ``bytes`` that remembers its origin."""


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


def _only_codec_keywords(node: ast.Call) -> bool:
    return all(kw.arg in ("encoding", "errors") for kw in node.keywords)


def fold_value(node: ast.AST, env: Optional[Dict[str, Any]] = None,
               loc: Optional[Dict[str, Any]] = None) -> Tuple[Any, FoldInfo]:
    """Fold ``node`` to a Python constant: ``(value, info)``, or ``(NOFOLD,
    info)`` when the expression is not a pure function of constants."""
    f = _Folder(env if env is not None else {})
    try:
        v = f.ev(node, loc or {})
    except (NoFold, RecursionError, OverflowError, ValueError, MemoryError):
        return NOFOLD, f.info
    if isinstance(v, _ByteArray):
        v = bytes(v)
    return v, f.info


def fold_str(node: ast.AST, env: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """The string ``node`` folds to, or None."""
    v, _info = fold_value(node, env)
    return v if isinstance(v, str) else None


# ---------------------------------------------------------------------------
# a local environment: forward evaluation of a function body's assignments,
# including a loop that appends ``chr(c)`` for each ``c`` of a constant
# iterable. Returns ``(env, infos)`` -- the final binding of each name that
# folded to a constant, and the FoldInfo of how it was assembled.

def _assigned_names(stmts: List[ast.stmt]) -> List[str]:
    names: List[str] = []
    for s in stmts:
        for n in ast.walk(s):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                names.append(n.id)
    return names


class _LocalEnv:
    def __init__(self, base: Dict[str, Any]):
        self.env: Dict[str, Any] = dict(base)
        self.infos: Dict[str, FoldInfo] = {}
        self.steps = 0

    def eval(self, node: ast.AST, loc: Dict[str, Any]) -> Tuple[Any, FoldInfo]:
        merged = self.env if not loc else {**self.env, **loc}
        return fold_value(node, merged)

    def forget(self, names: List[str]) -> None:
        for n in names:
            self.env.pop(n, None)
            self.infos.pop(n, None)

    def assign(self, name: str, value: Any, info: FoldInfo) -> None:
        self.env[name] = value
        merged = FoldInfo()
        merged.merge(info)
        self.infos[name] = merged

    def block(self, stmts: List[ast.stmt], loc: Dict[str, Any], depth: int = 0) -> None:
        for s in stmts:
            self.steps += 1
            if self.steps > _MAX_STEPS or depth > 6:
                return
            self.stmt(s, loc, depth)

    def stmt(self, s: ast.stmt, loc: Dict[str, Any], depth: int) -> None:
        if isinstance(s, ast.Assign):
            if len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                name = s.targets[0].id
                v, info = self.eval(s.value, loc)
                if v is NOFOLD:
                    self.forget([name])
                else:
                    self.assign(name, v, info)
            else:
                self.forget(_assigned_names([s]))
        elif isinstance(s, ast.AnnAssign):
            if isinstance(s.target, ast.Name) and s.value is not None:
                v, info = self.eval(s.value, loc)
                if v is NOFOLD:
                    self.forget([s.target.id])
                else:
                    self.assign(s.target.id, v, info)
            else:
                self.forget(_assigned_names([s]))
        elif isinstance(s, ast.AugAssign):
            if isinstance(s.target, ast.Name) and s.target.id in self.env:
                name = s.target.id
                fake = ast.BinOp(left=ast.Name(id=name, ctx=ast.Load()), op=s.op,
                                 right=s.value)
                v, info = self.eval(fake, loc)
                if v is NOFOLD:
                    self.forget([name])
                else:
                    prev = self.infos.get(name) or FoldInfo()
                    self.env[name] = v
                    total = FoldInfo()
                    total.merge(prev)
                    total.merge(info)
                    self.infos[name] = total
            else:
                self.forget(_assigned_names([s]))
        elif isinstance(s, ast.For):
            self.for_loop(s, loc, depth)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            self.block(s.body, loc, depth + 1)
        elif isinstance(s, ast.Try):
            self.forget(_assigned_names([s]))
        elif isinstance(s, ast.If):
            test, _ = self.eval(s.test, loc)
            if test is NOFOLD:
                self.forget(_assigned_names(s.body + s.orelse))
            else:
                self.block(s.body if test else s.orelse, loc, depth + 1)
        elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.forget([s.name])
        elif isinstance(s, (ast.While, ast.AsyncFor)):
            self.forget(_assigned_names([s]))
        else:
            # any other statement that stores to a tracked name unbinds it
            stored = _assigned_names([s])
            if stored:
                self.forget(stored)

    def for_loop(self, s: ast.For, loc: Dict[str, Any], depth: int) -> None:
        items_v, iter_info = self.eval(s.iter, loc)
        if (items_v is NOFOLD or not isinstance(items_v, (str, bytes, tuple, list))
                or len(items_v) > _MAX_LOOP or s.orelse):
            self.forget(_assigned_names([s]))
            return
        body_names = set(_assigned_names(s.body))
        loop_info = FoldInfo()
        loop_info.merge(iter_info)
        f = _Folder({})
        for item in list(items_v):
            bound = dict(loc)
            try:
                f.bind(s.target, item, bound)
            except NoFold:
                self.forget(list(body_names))
                return
            ok = self.loop_body(s.body, bound, loop_info)
            if not ok:
                self.forget(list(body_names))
                return
        # names that came to hold a value inside the loop keep the info of
        # the loop's own assembly (iterated chr calls)
        for n in body_names:
            if n in self.env:
                tot = FoldInfo()
                tot.merge(self.infos.get(n) or FoldInfo())
                tot.merge(loop_info)
                self.infos[n] = tot

    def loop_body(self, body: List[ast.stmt], bound: Dict[str, Any], info: FoldInfo) -> bool:
        """Execute ``body`` once under the loop bindings. Only assignments and
        augmented assignments to plain names are supported; anything else
        makes the loop non-constant. Values computed from the loop variable
        are evaluated in the comprehension scope (``scope_depth`` 1) so their
        ``chr`` calls count as per-element."""
        for st in body:
            self.steps += 1
            if self.steps > _MAX_STEPS:
                return False
            if isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
                name = st.target.id
                if name not in self.env:
                    return False
                fake = ast.BinOp(left=ast.Name(id=name, ctx=ast.Load()), op=st.op,
                                 right=st.value)
                v, inf = self._eval_in_scope(fake, bound)
            elif (isinstance(st, ast.Assign) and len(st.targets) == 1
                  and isinstance(st.targets[0], ast.Name)):
                name = st.targets[0].id
                v, inf = self._eval_in_scope(st.value, bound)
            else:
                return False
            if v is NOFOLD:
                return False
            self.env[name] = v
            info.merge(inf)
        return True

    def _eval_in_scope(self, node: ast.AST, bound: Dict[str, Any]) -> Tuple[Any, FoldInfo]:
        merged = {**self.env, **bound}
        f = _Folder(merged)
        f.scope_depth = 1
        try:
            v = f.ev(node, {})
        except (NoFold, RecursionError, OverflowError, ValueError, MemoryError):
            return NOFOLD, f.info
        return v, f.info


def local_const_env(func: ast.AST, base: Optional[Dict[str, Any]] = None
                    ) -> Tuple[Dict[str, Any], Dict[str, FoldInfo]]:
    """Forward constant evaluation of ``func``'s body (assignments, tuple
    unpacking is not tracked; a ``for`` over a constant iterable is
    unrolled). Returns ``(env, infos)``."""
    le = _LocalEnv(base or {})
    body = getattr(func, "body", None)
    if isinstance(body, list):
        try:
            le.block(body, {})
        except (RecursionError, OverflowError, ValueError, MemoryError):
            pass
    return le.env, le.infos


# ---------------------------------------------------------------------------
# the obfuscation signal: assembled strings that feed a return / a comparison

def _parents(root: ast.AST) -> Dict[int, ast.AST]:
    m: Dict[int, ast.AST] = {}
    for p in ast.walk(root):
        for c in ast.iter_child_nodes(p):
            m[id(c)] = p
    return m


def _usage_of(node: ast.AST, parents: Dict[int, ast.AST]) -> str:
    """"returned" / "compared" / "" for the context an expression feeds."""
    cur = node
    while True:
        par = parents.get(id(cur))
        if par is None:
            return ""
        if isinstance(par, ast.Return):
            return "returned"
        if isinstance(par, ast.Compare):
            return "compared"
        if isinstance(par, (ast.Yield, ast.YieldFrom)):
            return "returned"
        if isinstance(par, ast.stmt):
            return ""
        cur = par


def _name_usage(func: ast.AST, name: str) -> str:
    """How a local name (or an ``alias.NAME`` imported constant) is used:
    returned / compared / ""."""
    parents = _parents(func)
    best = ""
    dotted = "." in name
    for n in ast.walk(func):
        if dotted:
            hit = isinstance(n, ast.Attribute) and _dotted(n) == name \
                and isinstance(n.ctx, ast.Load)
        else:
            hit = isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)
        if hit:
            u = _usage_of(n, parents)
            if u == "returned":
                return "returned"
            if u == "compared":
                best = "compared"
    return best


_FOLDABLE = (ast.Call, ast.BinOp, ast.JoinedStr, ast.ListComp, ast.GeneratorExp,
             ast.Subscript, ast.IfExp)


def find_assembled_strings(func: ast.AST, base: Optional[Dict[str, Any]] = None,
                           limit: int = 8,
                           base_infos: Optional[Dict[str, FoldInfo]] = None
                           ) -> List[Dict[str, Any]]:
    """Strings a function builds character-by-character from constants and
    then RETURNS or COMPARES: ``[{"text", "usage", "chr_calls", "lineno",
    "snippet"}]``. A ``chr``/``ord`` over a caller-supplied value never folds
    and is therefore never reported."""
    env, infos = local_const_env(func, base or {})
    parents = _parents(func)
    out: List[Dict[str, Any]] = []
    seen_text = set()

    def add(text: str, info: FoldInfo, usage: str, node: ast.AST) -> None:
        if not usage or len(out) >= limit or (text, usage) in seen_text:
            return
        seen_text.add((text, usage))
        try:
            snippet = ast.unparse(node)[:160]
        except Exception:
            snippet = ""
        out.append({"text": text[:400], "usage": usage, "chr_calls": info.char_count,
                    "lineno": getattr(node, "lineno", 0), "snippet": snippet})

    # 1) maximal foldable expressions anywhere in the body (top-down)
    def visit(node: ast.AST) -> None:
        if isinstance(node, _FOLDABLE):
            v, info = fold_value(node, env)
            if isinstance(v, str) and info.assembled:
                add(v, info, _usage_of(node, parents), node)
                return
        for ch in ast.iter_child_nodes(node):
            visit(ch)

    body = getattr(func, "body", None)
    for st in (body if isinstance(body, list) else []):
        visit(st)

    # 2) names assembled by assignment / accumulation loops (in the function,
    # or at module level via ``base_infos``), then used
    all_infos = dict(base_infos or {})
    all_infos.update(infos)
    for name, info in all_infos.items():
        v = env.get(name)
        if isinstance(v, str) and info.assembled:
            usage = _name_usage(func, name)
            if usage:
                cands = [n for n in ast.walk(func)
                         if isinstance(n, (ast.Assign, ast.AugAssign, ast.For))
                         and name in _assigned_names([n])]
                cands.sort(key=lambda n: 0 if isinstance(n, ast.For) else 1)
                node = cands[0] if cands else func
                add(v, info, usage, node)
    return out
