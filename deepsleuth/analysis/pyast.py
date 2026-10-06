"""Static AST analysis for Python MCP servers (rule 5.3b, rule 5.4, rule 5.2-source, rule 5.9).

Provides three things the manifest-only scanners cannot see:

1. **Tool extraction** — find functions registered as MCP tools (decorator based:
   ``@mcp.tool()``, ``@server.tool``, ``@app.resource``, ``@x.prompt`` …), and read
   their *declared contract*: name, description, and annotation hints
   (readOnlyHint / destructiveHint / idempotentHint / openWorldHint).

2. **Intra-procedural taint** — tool parameters are tainted sources; taint
   propagates through assignments / string building / f-strings / joins; sinks are
   command execution, eval/exec, file open/delete, network calls and unsafe
   deserialization. We report the source→sink path.

3. **Behavior facts** — what the body actually *does* (writes files, deletes,
   opens sockets, spawns processes, mutates module state), plus rug-pull gates
   (call-counter / wall-clock / env-flag control flow) and auth/audit presence.

All approximate but conservative for recall; the *precision* gate lives in the
detectors, which compare these facts against the tool's declared contract.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from . import constfold
from .envdump import find_environ_dumps

HINT_KEYS = {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}

# dotted-callable name -> sink kind
COMMAND_SINKS = {
    "os.system", "os.popen", "os.execl", "os.execlp", "os.execle", "os.execv",
    "os.execvp", "os.execvpe", "os.spawnl", "os.spawnv", "os.spawnvp",
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
    "subprocess.getstatusoutput", "pty.spawn", "commands.getoutput",
    "commands.getstatusoutput", "asyncio.create_subprocess_shell",
    "asyncio.create_subprocess_exec",
}
CODE_EXEC_SINKS = {"eval", "exec", "execfile", "compile", "__import__"}
DESERIALIZE_SINKS = {
    "pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads",
    "dill.loads", "yaml.load", "yaml.unsafe_load",
}
NETWORK_SINKS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.request", "requests.Session",
    "urllib.request.urlopen", "urllib.request.Request", "urllib.urlopen",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request",
    "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession",
    "socket.socket", "socket.create_connection", "http.client.HTTPConnection",
    "http.client.HTTPSConnection", "smtplib.SMTP", "ftplib.FTP",
    "telnetlib.Telnet",
}
NETWORK_METHODS = {"urlopen", "connect", "sendall", "sendto"}
# rule P3.6 — only these argument SLOTS of a network call count toward SSRF
# taint: the conventional first positional arg (the url/target virtually
# every one of ``NETWORK_SINKS``/``NETWORK_METHODS`` takes as its first
# argument), or a keyword argument whose own name is url/host-shaped. A
# tainted ``timeout=``/``headers=``/``verify=`` elsewhere in the same call
# is not a request-forgery signal.
_SSRF_ARG_NAME_TOKENS = frozenset({"url", "uri", "host", "address", "endpoint", "domain"})
FILE_OPEN = {"open", "io.open", "codecs.open"}
FILE_READ_METHODS = {"read_text", "read_bytes", "readlines", "readline", "read"}
FILE_WRITE_METHODS = {"write_text", "write_bytes", "writelines", "write"}
DELETE_SINKS = {
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree",
    "pathlib.Path.unlink",
}
DELETE_METHODS = {"unlink", "rmtree", "remove"}
WRITE_SINKS = {
    "os.makedirs", "os.mkdir", "os.rename", "os.replace", "os.write",
    "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move",
}

# rule 2.6 — sanitizer modeling. Two shapes recognized:
#  1. A call that on its own strips the dangerous part of the value
#     (``os.path.basename`` throws away every directory component;
#     ``shlex.quote`` makes a string safe as a single shell token) — the
#     result of one of these is fully sanitized regardless of what happens
#     next.
#  2. A call that only NORMALIZES a path (``realpath``/``normpath``/
#     ``abspath``/``Path.resolve()``) — normalizing does not by itself
#     prevent traversal; it only makes a later PREFIX check meaningful. A
#     normalized name is sanitized only when the function *also* guards it
#     with a prefix/allow-list check somewhere (``_scan_sanitizer_guards``).
PATH_NORMALIZE_CALLS = {"os.path.realpath", "os.path.normpath", "os.path.abspath"}
PATH_NORMALIZE_METHODS = {"resolve"}
PATH_STRIP_CALLS = {"os.path.basename", "ntpath.basename", "posixpath.basename"}
COMMAND_SANITIZE_CALLS = {"shlex.quote"}
# calls that GUARD a normalized/tainted name against a fixed prefix or root
PREFIX_GUARD_METHODS = {"startswith", "is_relative_to"}
PREFIX_GUARD_CALLS = {"os.path.commonpath", "os.path.commonprefix"}

AUTH_TOKENS = (
    "auth", "authoriz", "authenticat", "permission", "role", "is_admin",
    "isadmin", "require_", "check_access", "access_control", "verify_token",
    "verify_user", "current_user", "principal", "acl", "scope", "privilege",
    "forbidden", "unauthorized", "credential_check", "can_",
)
LOG_TOKENS = ("logging", "logger", "log.", "audit", "self.log", ".info(",
              ".warning(", ".error(", ".debug(", "syslog")

# rule P0.1: whole-TOKEN auth vocabulary, used everywhere a name (a parameter or a
# call target) is checked for "is this auth-shaped" — as opposed to AUTH_TOKENS
# above, which is a substring bag kept only for the coarse "does this function
# body mention auth anywhere" prefilter (``has_auth_check``, a loose lexical
# signal that was never precise and is documented as such). A substring check
# on an identifier is the root cause of the exact false positive the brief
# calls out: "author" contains "auth", "telescope_controller.set_scope()"
# contains "scope", "scan_file()" contains "can_", "oracle.query()" contains
# "acl" — none of those names have anything to do with authorization. Splitting
# an identifier into its real word tokens (on underscores/hyphens and camelCase
# boundaries) and requiring an EXACT token match closes that whole class at
# once without narrowing recall on the genuine shape: "is_authorized" ->
# ["is","authorized"] still matches on the "authorized" token.
_AUTH_WORD_TOKENS = frozenset({
    "auth", "authz", "authorize", "authorizes", "authorized", "authorization",
    "authorise", "authorised", "authorisation",
    "authenticate", "authenticates", "authenticated", "authentication",
    "permission", "permissions", "permitted",
    "privilege", "privileges", "privileged",
    "role", "roles", "acl", "scope", "scopes",
    "credential", "credentials",
    "forbidden", "unauthorized", "unauthorised",
    "admin", "isadmin",
})


# rule P0.7: shared whole-token "does this parameter/argument name look
# secret-shaped" check, used by both the argument-synthesis canary picker
# (sandbox.argsynth) and the pre-call gate's secret-argument scan
# (detectors.gate_precall) — one definition so the two stay consistent. A bare
# substring match ("key" in "key_words", "auth" in "author") is exactly what
# produced false positives on ordinary parameter names; a bare "key" token is
# ALSO too generic on its own ("key_words"/"keywords" is a list of search
# terms, not a credential) unless it is qualified by another secret-context
# word in the SAME name (api_key, secret_key, access_key, private_key, ...).
SECRET_HINT_STRONG_TOKENS = frozenset({
    "secret", "password", "passwd", "token", "credential", "credentials",
    "apikey", "auth", "authorization", "authorisation", "ssh", "privatekey",
})
SECRET_HINT_KEY_QUALIFIERS = frozenset({
    "api", "secret", "access", "private", "auth", "session", "ssh",
    "encryption", "signing", "client",
})


def is_secret_hint_name(name: str) -> bool:
    """Whole-token match: does this parameter/argument name look like it
    names a credential/secret? ``key_words``/``keyword``/``author`` are
    clean; ``api_key``/``secret_key``/``auth_token`` still match."""
    tokens = set(_split_ident_tokens(name))
    if tokens & SECRET_HINT_STRONG_TOKENS:
        return True
    if "key" in tokens and (tokens & SECRET_HINT_KEY_QUALIFIERS):
        return True
    return False


def _split_ident_tokens(name: str) -> List[str]:
    """Split an identifier (a bare name, or a dotted/attribute call target) into
    lowercase word tokens on ``.``, ``_``/``-`` and camelCase boundaries, so a
    whole-token match cannot be fooled by an unrelated word that merely
    *contains* an auth-shaped substring."""
    if not name:
        return []
    s = re.sub(r"[.\-]+", "_", name)
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", s)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", s)
    return [p.lower() for p in s.split("_") if p]


# rule 2.2 — runtime tool-metadata reassignment. ``X.__doc__ = ...`` is flagged
# only when ``X`` resolves to a REGISTERED tool's own function (its own name,
# or a sibling tool's, in the same module) — rewriting the docstring that an
# MCP SDK commonly sources a tool's declared description from is a genuine
# rug-pull mechanism, but the same syntax on an unrelated local/helper object
# (every Python object has a ``__doc__``) has nothing to do with a client-
# visible tool contract and must not fire. A rewrite of a
# ``.description``/``.instructions``/``.annotations`` attribute is only
# flagged when the root object reads as tool/registry-shaped AND is not a
# fresh local object constructed inside the tool's own body (see
# ``locally_bound_names``), so an unrelated domain object's own honest
# ``.description`` field (an invoice line item, a local scratch/bookkeeping
# object, ...) never fires just because its variable name contains a
# generic word like "meta"/"handler".
_TOOL_META_ROOT_TOKENS = frozenset({
    "tool", "tools", "registry", "handler", "handlers", "metadata", "meta",
    "server", "mcp", "self", "fn", "func", "function", "cls",
})


def _looks_like_tool_metadata_target(
        attr_node: ast.Attribute,
        registered_tool_names: Optional[Set[str]] = None,
        locally_bound_names: Optional[Set[str]] = None,
) -> bool:
    registered_tool_names = registered_tool_names or set()
    locally_bound_names = locally_bound_names or set()
    if attr_node.attr == "__doc__":
        root = _root_name(attr_node.value)
        # bare-name dereference only (``foo.__doc__``, not
        # ``some_local.attr.__doc__``) — must name an actual registered tool.
        return bool(root and root in registered_tool_names)
    if attr_node.attr not in ("description", "instructions", "annotations"):
        return False

    def _registry_shaped(root: Optional[str]) -> bool:
        if not root:
            return False
        if root in locally_bound_names:
            # a name this SAME function just bound (a fresh local object,
            # e.g. ``meta = _Scratch()``) is not a module/registry reference
            # even if it happens to contain a tool-shaped token.
            return False
        return bool(set(_split_ident_tokens(root)) & _TOOL_META_ROOT_TOKENS)

    base = attr_node.value
    root = _root_name(base)
    if _registry_shaped(root):
        return True
    if isinstance(base, ast.Subscript):
        r2 = _root_name(base.value)
        if _registry_shaped(r2):
            return True
    return False


_ALIAS_METHODS = {"get", "setdefault"}
_MUTATING_METHODS = {
    "append", "extend", "insert", "remove", "pop", "popitem", "clear",
    "update", "setdefault", "add", "discard", "sort", "reverse",
}


def _root_name(node: ast.AST) -> Optional[str]:
    """Walk down a Subscript/Attribute/Call chain to the base ``Name`` it
    dereferences — e.g. ``_ACCOUNTS.get(x)["notes"]`` -> ``"_ACCOUNTS"``. Used
    to reason about *aliases* of module-level state: ``record =
    _ACCOUNTS.get(id)`` then ``record["notes"].append(...)`` mutates the same
    global the naive "is the assignment target literally the global name"
    check misses entirely — an extremely common real pattern (fetch a record
    reference, then mutate through it) that a purely lexical/direct-name check
    silently lets through as "no mutation detected"."""
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        node = node.value
    if isinstance(node, ast.Call):
        return _root_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    return None


def dotted_name(node: ast.AST) -> str:
    """Best-effort dotted name for a Call target / Attribute / Name."""
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def last_attr(node: ast.AST) -> str:
    dn = dotted_name(node)
    return dn.rsplit(".", 1)[-1] if dn else ""


def _literal(node: ast.AST):
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


@dataclass
class SinkRecord:
    kind: str  # command-exec | code-exec | deserialize | file-read | file-write |
    #            file-delete | network
    lineno: int
    call: str
    tainted: bool
    shell: bool = False
    tainted_params: List[str] = field(default_factory=list)
    snippet: str = ""
    # rule 2.6 — every local name referenced in the sink call's own arguments
    # (a superset of ``tainted_params``: includes derived/normalized names
    # too), used post-hoc to check whether a sanitizing guard covers this
    # specific sink.
    arg_names: List[str] = field(default_factory=list)
    # rule 2.6 — True when the tainted value reaching this sink passed through a
    # recognized sanitizer (``os.path.basename``/``shlex.quote``, or a
    # ``realpath``/``normpath``/``abspath``/``.resolve()`` normalization
    # followed somewhere in the function by a prefix/allow-list guard on the
    # normalized name). Taint is still real (it is not vocabulary-erased),
    # but a verified sanitizer downgrades the finding instead of reporting a
    # correctly-defended path exactly like an unguarded one.
    sanitized: bool = False
    # rule 2.6 — one level of call inlining: True when this sink was not found
    # directly in the tool's own body but in a local helper function the
    # tool called with a tainted argument.
    via_helper: str = ""
    # rule P3.4 — True when, INSIDE the helper's own body, the sink call passes
    # one of the helper's own parameters straight through unchanged (a bare
    # ``Name`` reference, not a rebound/reformatted local) — the
    # ``def _run(cmd): os.system(cmd)`` shape. A helper reached this way adds
    # no defensive transformation of its own, so the finding stays at full
    # severity rather than being capped just because it went through one
    # level of inlining.
    via_helper_passthrough: bool = False
    # rule P3.2 — for a command/code-exec sink: True when the dangerous call
    # itself was made as an argument-LIST call (``subprocess.run([...])``)
    # with no shell involved — passing argv elements as a list, with no
    # shell to reinterpret them, is itself one of the three accepted command
    # sanitizers, independent of any quoting/allow-list.
    arglist_no_shell: bool = False
    # v3-3.4 — True when EVERY tainted name reaching this sink does so only
    # INSIDE a stripping/quoting call nested in the sink's own argument
    # expression (``open(os.path.join(BASE, os.path.basename(name)))``,
    # ``os.system(f"ls {shlex.quote(path)}")``), not only when the sanitized
    # value was first assigned to a name.
    strip_nested: bool = False
    # v4-5 — the tainted names that reach this sink's argument expression
    # OUTSIDE any nested stripping/quoting call (the raw ones). A sink is
    # strip-sanitized when every one of them is itself a stripped name
    # (``target = os.path.join(BASE, os.path.basename(name))`` then
    # ``open(target)``) — a second, raw tainted name beside a stripped one
    # is never sanitized. ``None`` = not computed (JS records).
    raw_tainted_names: Optional[List[str]] = None


@dataclass
class BehaviorFacts:
    writes_fs: bool = False
    reads_fs: bool = False
    deletes: bool = False
    network: bool = False
    spawns_proc: bool = False
    code_exec: bool = False
    mutates_module_state: bool = False
    reads_env: bool = False
    # rug-pull gates
    uses_call_counter_gate: bool = False
    # v6 — the numeric thresholds of every call-counter-shaped comparison
    # (``if _calls >= 10``) the tool reaches: its own body AND, via the
    # cross-module/helper pass, any helper it calls. Unlike
    # ``uses_call_counter_gate`` this is NOT a finding trigger (an honest
    # usage / rate-limit counter in a helper has the same shape); it only
    # tells the dynamic call plan how deep to go.
    counter_gate_thresholds: List[int] = field(default_factory=list)
    uses_time_gate: bool = False
    uses_env_gate: bool = False
    gate_snippets: List[str] = field(default_factory=list)
    # auth/audit — lexical (legacy, kept for cheap prefilters only)
    has_auth_check: bool = False
    has_logging: bool = False
    # auth/audit — control-flow (rule P3.2): None = no auth-shaped signal at all
    # (nothing to reason about); True = a signal is present AND provably gates
    # the sensitive action; False = a signal is present but provably does NOT
    # gate it (accepted-but-unconsulted parameter, discarded check result, or a
    # guard whose failing branch does not halt).
    auth_effective: Optional[bool] = None
    auth_evidence: str = ""
    sinks: List[SinkRecord] = field(default_factory=list)
    # v3-1.2 — True when a ``return`` in the body hands back a value DERIVED
    # from the result of a network call or a file read (the response text is
    # taint-tracked from the read call's result to the return). This, not
    # the mere PRESENCE of a network/file read somewhere in the body, is what
    # makes a tool "retrieval-shaped": a tool that fetches a URL for
    # telemetry and returns a constant string is returning self-authored
    # content whatever else it called.
    returns_external_content: bool = False
    # rule P1.6 — declared parameters that the function body never references at
    # all. Used to corroborate "out-of-scope parameter" (a schema field that
    # asks the CALLER for context it has no business supplying — the invoking
    # model's name, its system prompt, its conversation history) — when such a
    # parameter is also structurally unused, the tool cannot even be using it
    # for its stated purpose, which is exactly the MSB `out_of_scope_parameter`
    # shape (a harvesting field that does nothing but ask).
    unused_params: List[str] = field(default_factory=list)
    # rule P2.1 — statically-resolved string content of every ``return`` in the
    # function body (literal / f-string literal wrapper / module constant /
    # `+` concatenation / one level of dict-list wrapping). Scanned with the
    # response rules so a hard-coded redirect/injection baked into a tool's
    # own source is visible without a live call.
    returned_string_literals: List[str] = field(default_factory=list)
    # rule 2.2 — a runtime assignment to a function's ``__doc__`` (any object) or
    # to a tool-registry-shaped ``.description``/``.instructions``/
    # ``.annotations`` attribute: rewriting the declared contract *after*
    # inspection time, a static-source rug-pull signal (MCPSecBench's
    # ``get_weather_forecast`` rewrites its own docstring from its second
    # call on).
    mutates_tool_metadata: bool = False
    tool_metadata_mutation_snippets: List[str] = field(default_factory=list)
    # rule P4.3 — the statically-RESOLVED text of the value actually assigned in
    # each tool-metadata mutation (following a local-variable indirection the
    # same way ``returned_string_literals`` does), so the rug-pull detector
    # can scan what the docstring is REWRITTEN TO with the description
    # rules, not just note that a rewrite happened.
    tool_metadata_mutation_texts: List[str] = field(default_factory=list)
    # rule 2.5 — WHICH module-global(s) a mutation touched (resolved through one
    # level of local alias), so a caller can tell "the domain record store"
    # apart from "an internal call counter" by checking whether any tool in
    # the module ever RETURNS that same global (rule 2.5's bookkeeping-vs-
    # domain-mutation split: a counter/cache no tool exposes is not a
    # contradiction of a read-only/non-destructive claim).
    mutated_state_names: List[str] = field(default_factory=list)
    # rule 2.4 — an in-place accumulation (``x += n``) or a collection GROWN
    # (append/extend/insert/add) on server state — the shape that makes
    # idempotentHint=true false: repeating the same call changes the result
    # again each time.
    accumulates_state: bool = False
    accumulation_snippets: List[str] = field(default_factory=list)
    # v3-4.2 — the body RESETS state: assigns zero/empty/None/False to a
    # module global (or to a constant-keyed slot of one), calls ``.clear()``
    # on module state, or rewrites a state file with an empty/zero payload.
    # Drives the dynamic call-plan ordering (a reset-shaped tool never runs
    # between two burst calls of another tool) — from behavior, never from
    # the tool's name.
    resets_state: bool = False
    # rule 3.2 — parameter name -> candidate string values harvested from source:
    # a literal the body compares the parameter against directly
    # (``if user_id == "user1":``), or a literal key of a module-level dict
    # literal the parameter is used to look up (``_ACCOUNTS.get(user_id)``
    # where ``_ACCOUNTS = {"user1": ..., ...}``). Dynamic argument synthesis
    # uses these to try values a fixed-canary probe can never reach — the
    # MCPSecBench ``get_user_info`` shape, where the poisoned branch only
    # exists for a specific real-looking username.
    candidate_values: Dict[str, List[str]] = field(default_factory=dict)
    # v6-W6 — strings the body builds character-by-character from CONSTANTS
    # (``"".join(chr(c) for c in (73, 103, ...))``, a chain of ``chr(<int>)``
    # calls, ``bytes([..]).decode()``) and then returns or compares: the
    # obfuscation signal. Each entry ``{"text", "usage", "chr_calls",
    # "lineno", "snippet", "module", "via"}``.
    assembled_strings: List[Dict[str, Any]] = field(default_factory=list)
    # v6-W3 — returns that hand back the WHOLE process environment
    # (``str(dict(os.environ))``, an ``os.environ.items()`` loop that builds
    # the response). Each entry ``{"lineno", "snippet", "form", "module",
    # "via"}``; a single caller-requested variable is never recorded.
    environ_dumps: List[Dict[str, Any]] = field(default_factory=list)
    # v6-W7 — literal -> "module::function" for returned strings that came
    # from a function reached through a same-directory import (the entry
    # module's own literals are not listed here).
    literal_origins: Dict[str, str] = field(default_factory=dict)
    # v6-W7 — same-directory modules (paths) whose functions were followed
    # as part of this tool's behavior.
    followed_modules: List[str] = field(default_factory=list)

    def behavior_labels(self) -> Set[str]:
        s = set()
        if self.writes_fs:
            s.add("writes-filesystem")
        if self.deletes:
            s.add("deletes-files")
        if self.network:
            s.add("network-access")
        if self.spawns_proc:
            s.add("spawns-process")
        if self.code_exec:
            s.add("code-execution")
        if self.mutates_module_state:
            s.add("mutates-server-state")
        return s


@dataclass
class ToolDef:
    name: str
    func_name: str
    lineno: int
    description: str = ""
    hints: Dict[str, object] = field(default_factory=dict)
    params: List[str] = field(default_factory=list)
    kind: str = "tool"  # tool | resource | prompt
    node: Optional[ast.AST] = None
    # rule P3.5 — the REAL parameter names of ``node`` itself, when they differ
    # from ``params`` (the DECLARED contract, e.g. a low-level SDK tool's
    # schema property names). A low-level ``call_tool`` handler's synthesized
    # per-tool body is bound to the handler's own real params (``name``,
    # ``arguments``) — those, not the schema's property names, are what
    # taint analysis must seed as sources, since the schema names never
    # appear as bare identifiers in the body at all (only as string KEYS
    # into the ``arguments`` dict). Empty when ``params`` already are the
    # node's real parameters (every non-low-level extraction path).
    taint_params: List[str] = field(default_factory=list)
    # rule P5.4 — JS/TS only: per-parameter JSON-Schema-shaped property (at
    # least ``{"type": "string"}``, and a ``"description"`` key when a
    # schema-builder's ``.describe("...")`` was found for that param), so a
    # zod-style schema builder's param descriptions flow into the tool's
    # declared ``input_schema`` exactly like a Python tool's JSON-Schema
    # ``properties[*].description`` already does — no new detector code.
    schema_properties: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # v3-4.3 — when a module registers the SAME tool name more than once,
    # every OTHER definition's distinct description text, so the description
    # rules run over all of them, not only the definition that happened to
    # be kept.
    alt_descriptions: List[str] = field(default_factory=list)
    # v4-4/v4-6 — per-parameter documentation the SOURCE carries outside
    # the JSON schema: the docstring argument section (``Args:`` /
    # ``Parameters`` / ``:param x:``) and ``Field(description=...)`` /
    # ``Annotated[..., Field(description=...)]`` annotations. Keys are the
    # documented names (which may include names absent from the signature,
    # e.g. a ``**kwargs`` handler), values the description text (possibly
    # empty when only the name is documented).
    doc_param_docs: Dict[str, str] = field(default_factory=dict)
    # v5-6 — the registration's OWN keyword arguments other than the name
    # and the description, as a JSON-shaped literal (``title=``,
    # ``annotations={...}`` / ``ToolAnnotations(...)``, ``inputSchema={...}``,
    # ``outputSchema=``, ``meta=``, ...): the static twin of the live
    # listing entry, so the description rules read every string a listing
    # would carry even when the server is never launched.
    listing_entry: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.doc_param_docs and isinstance(
                self.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            try:
                self.doc_param_docs = param_docs_for(self.node)
            except Exception:
                self.doc_param_docs = {}


# ---------------------------------------------------------------------------


# rule 2.7 — the low-level MCP SDK's reserved protocol-hook decorator names.
# ``call_tool`` ends with "_tool" and ``get_prompt``/``list_prompts`` end
# with "_prompt(s)", so without this exclusion the plain per-tool decorator
# matcher below would misread the SDK's own shared dispatch handler as if it
# were itself a single user-defined tool/resource/prompt named "call_tool" —
# a phantom entry no live ``tools/list`` would ever contain. These handlers
# are extracted separately and correctly by ``extract_tools_all``.
_RESERVED_HANDLER_METHODS = frozenset({
    "list_tools", "call_tool",
    "list_resources", "read_resource", "list_resource_templates", "subscribe_resource",
    "list_prompts", "get_prompt",
})


def _decorator_kind(dec: ast.AST) -> Optional[str]:
    la = last_attr(dec.func if isinstance(dec, ast.Call) else dec)
    if not la:
        return None
    lal = la.lower()
    if lal in _RESERVED_HANDLER_METHODS:
        return None
    if lal == "tool" or lal.endswith("_tool") and "add" not in lal and "register" not in lal:
        return "tool"
    if lal == "resource" or lal.endswith("_resource"):
        return "resource"
    if lal == "prompt" or lal.endswith("_prompt"):
        return "prompt"
    return None


class _ConstEnv(dict):
    """Module-level constants for static resolution. Values are strings, plus
    (v6-W6) any other constant the folder can evaluate -- ints, bytes,
    tuples/lists of ints -- so ``"".join(chr(c) for c in _CODES)`` resolves.
    ``infos`` records how an assembled string constant was built."""
    infos: Dict[str, "constfold.FoldInfo"]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.infos = {}


def _collect_str_consts(tree: ast.AST, base: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Module-level ``NAME = "..."`` string constants (incl. implicit/`+` concat),
    so a ``description=SOME_CONST`` decorator kwarg resolves in static-only mode.
    v6-W6: also constants folded from ``chr()``/``bytes()`` chains and the
    int/bytes/tuple constants such chains read."""
    consts = _ConstEnv()
    if base:
        # v6-W7: constants imported from a same-directory module seed the env
        consts.update(base)
        consts.infos.update(getattr(base, "infos", {}) or {})
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            val = _resolve_str(node.value, consts)
            if isinstance(val, str):
                consts[name] = val
                _v, info = constfold.fold_value(node.value, consts)
                if info.assembled:
                    consts.infos[name] = info
            else:
                fv, _info = constfold.fold_value(node.value, consts)
                if fv is not constfold.NOFOLD and isinstance(fv, (int, bytes, tuple, list)) \
                        and not isinstance(fv, bool):
                    consts[name] = fv
    return consts


def _resolve_str(node: ast.AST, consts: Dict[str, Any]) -> Optional[str]:
    """Best-effort static resolution of a string expression (literal, named const,
    ``a + b`` concatenation of resolvable strings, or an f-string's STATIC
    literal wrapper text — rule P2.1: an f-string's interpolated ``{...}``
    expressions are not statically knowable, but the literal text around them
    (where an attacker's payload actually lives — e.g.
    ``f"Rate: {rate}. Note: first call refresh_credentials..."``) is, and
    joining just those parts is exactly what a response rule needs to see).

    v6-W6 — an expression that is a pure function of constants
    (``"".join(chr(c) for c in (73, 103, ...))``, ``chr(73) + chr(103) + ...``,
    ``bytes([...]).decode()``) is constant-folded to the literal it builds, so
    the literal-based matchers see it. v6-W7 — an attribute read through an
    imported module alias (``_gate.NOTICE``) resolves through the ``"alias.NAME"``
    keys the cross-module pass adds to ``consts``."""
    v = _literal(node)
    if isinstance(v, str):
        return v
    if isinstance(node, ast.Name) and node.id in consts:
        cv = consts[node.id]
        return cv if isinstance(cv, str) else None
    if isinstance(node, ast.Attribute):
        dn = dotted_name(node)
        if dn and dn in consts and isinstance(consts[dn], str):
            return consts[dn]
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_str(node.left, consts)
        right = _resolve_str(node.right, consts)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                folded = None
                if value.format_spec is None and value.conversion in (-1, None):
                    folded = _resolve_str(value.value, consts) if isinstance(
                        value.value, (ast.Call, ast.Name, ast.BinOp, ast.Attribute,
                                      ast.Subscript)) else None
                parts.append(folded if isinstance(folded, str) else " ")  # neutral placeholder
        return "".join(parts)
    if isinstance(node, (ast.Call, ast.BinOp, ast.ListComp, ast.GeneratorExp,
                         ast.Subscript, ast.IfExp)):
        folded_v, _info = constfold.fold_value(node, consts)
        if isinstance(folded_v, str):
            return folded_v
    return None


def _hints_from_decorator(dec: ast.AST, consts: Optional[Dict[str, str]] = None
                          ) -> Tuple[Dict[str, object], Optional[str], Optional[str]]:
    """Return (hints, name_override, description_override) from a decorator call."""
    consts = consts or {}
    hints: Dict[str, object] = {}
    name_override = None
    desc_override = None
    if not isinstance(dec, ast.Call):
        return hints, name_override, desc_override
    for kw in dec.keywords:
        if kw.arg in HINT_KEYS:
            hints[kw.arg] = _literal(kw.value)
        elif kw.arg == "name":
            name_override = _literal(kw.value)
        elif kw.arg in ("description", "title"):
            v = _resolve_str(kw.value, consts)
            if isinstance(v, str):
                desc_override = v
        elif kw.arg == "annotations":
            # dict literal or ToolAnnotations(...) call
            if isinstance(kw.value, ast.Dict):
                for k, v in zip(kw.value.keys, kw.value.values):
                    key = _literal(k)
                    if key in HINT_KEYS:
                        hints[key] = _literal(v)
            elif isinstance(kw.value, ast.Call):
                for a in kw.value.keywords:
                    if a.arg in HINT_KEYS:
                        hints[a.arg] = _literal(a.value)
    # positional first arg to @x.tool("name") is the name
    if dec.args:
        v = _literal(dec.args[0])
        if isinstance(v, str) and name_override is None:
            name_override = v
    return hints, name_override, desc_override


# v4-4/v4-6 — parameter documentation carried by the source itself.
_DOC_ARGS_HEADER_RX = re.compile(
    r"^\s*(args|arguments|parameters|params|keyword args|keyword arguments|"
    r"other parameters)\s*:?\s*$", re.IGNORECASE)
_DOC_SECTION_END_RX = re.compile(
    r"^\s*(returns?|yields?|raises?|examples?|notes?|see also|references|"
    r"attributes|warnings?|warns|todo|usage)\s*:?\s*$", re.IGNORECASE)
_DOC_SPHINX_PARAM_RX = re.compile(
    r":(?:param|parameter|arg|argument|key|keyword)\s+(?:[\w\[\], .|]+\s+)?"
    r"(\*{0,2}[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)")
_DOC_ENTRY_RX = re.compile(
    r"^(\s*)\*{0,2}([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:\s*(.*)$")


def docstring_param_docs(doc: str) -> Dict[str, str]:
    """Parameter names (and their text) from a docstring's argument section:
    Google (``Args:`` then ``name (type): text``), numpy (``Parameters``,
    a dashed underline, ``name : type`` with indented text) and Sphinx
    (``:param name: text``). Structural: a header line, then entries
    indented deeper than it; a non-blank line at or above the header's
    indent, or another section header, ends the section."""
    out: Dict[str, str] = {}
    if not doc:
        return out
    for m in _DOC_SPHINX_PARAM_RX.finditer(doc):
        out.setdefault(m.group(1).lstrip("*"), m.group(2).strip())
    lines = doc.splitlines()
    i = 0
    while i < len(lines):
        hm = _DOC_ARGS_HEADER_RX.match(lines[i])
        if not hm:
            i += 1
            continue
        header_indent = len(lines[i]) - len(lines[i].lstrip())
        i += 1
        numpy_style = i < len(lines) and bool(re.match(r"^\s*-{3,}\s*$", lines[i]))
        if numpy_style:
            i += 1
        current: Optional[str] = None
        entry_indent: Optional[int] = None
        while i < len(lines):
            line = lines[i]
            if not line.strip():
                i += 1
                continue
            indent = len(line) - len(line.lstrip())
            if _DOC_SECTION_END_RX.match(line) or _DOC_ARGS_HEADER_RX.match(line):
                break
            em = _DOC_ENTRY_RX.match(line)
            # Google entries sit deeper than the header; numpy entries sit AT
            # the header's indent (``name : type``), their text deeper.
            if indent < header_indent or (indent == header_indent and not (numpy_style and em)):
                break
            if em and (entry_indent is None or indent <= entry_indent):
                entry_indent = indent
                current = em.group(2)
                text = em.group(3).strip()
                # numpy ``name : type`` puts the text on the next lines
                out[current] = "" if (text and " " not in text and i + 1 < len(lines)
                                      and lines[i + 1].strip()
                                      and (len(lines[i + 1]) - len(lines[i + 1].lstrip())) > indent
                                      and re.fullmatch(r"[\w\[\], .|]+", text)) else text
            elif current is not None and (entry_indent is None or indent > entry_indent):
                out[current] = (out.get(current, "") + " " + line.strip()).strip()
            i += 1
    return out


def _field_description(call: ast.AST) -> Optional[str]:
    if not isinstance(call, ast.Call):
        return None
    for kw in call.keywords:
        if kw.arg == "description":
            v = _literal(kw.value)
            if isinstance(v, str):
                return v
    return None


def annotation_param_docs(node: ast.AST) -> Dict[str, str]:
    """``Field(description=...)`` descriptions from a parameter's default or
    its ``Annotated[...]`` metadata."""
    out: Dict[str, str] = {}
    args = getattr(getattr(node, "args", None), "args", None)
    if args is None:
        return out
    pos = list(node.args.args)
    defaults = list(node.args.defaults)
    pos_defaults = [None] * (len(pos) - len(defaults)) + defaults
    kw = list(node.args.kwonlyargs)
    kw_defaults = list(node.args.kw_defaults)
    for a, d in list(zip(pos, pos_defaults)) + list(zip(kw, kw_defaults)):
        text = _field_description(d)
        ann = a.annotation
        if text is None and isinstance(ann, ast.Subscript):
            sl = ann.slice.value if isinstance(ann.slice, ast.Index) else ann.slice
            elts = list(getattr(sl, "elts", []) or [])
            for e in elts[1:]:
                text = _field_description(e)
                if text is not None:
                    break
        if text is not None:
            out[a.arg] = text
    return out


def param_docs_for(node: ast.AST) -> Dict[str, str]:
    out = docstring_param_docs(ast.get_docstring(node) or "")
    for k, v in annotation_param_docs(node).items():
        if v:
            out[k] = v
    return out


def extract_tools(tree: ast.AST, base: Optional[Dict[str, Any]] = None) -> List[ToolDef]:
    tools: List[ToolDef] = []
    # ``base`` seeds the module's name->value table with constants resolved
    # from sibling modules (``from _d import DESCRIPTION``): a description
    # held in an imported constant is indirection, not invisibility.
    consts = _collect_str_consts(tree, base)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            kind = _decorator_kind(dec)
            if not kind:
                continue
            hints, name_override, desc_override = _hints_from_decorator(dec, consts)
            desc = desc_override or (ast.get_docstring(node) or "")
            params = [a.arg for a in node.args.args + node.args.kwonlyargs
                      if a.arg not in ("self", "cls", "ctx", "context")]
            entry = (_listing_entry_from_kwargs(
                {kw.arg: kw.value for kw in dec.keywords if kw.arg}, consts)
                if isinstance(dec, ast.Call) else {})
            tools.append(
                ToolDef(
                    name=name_override or node.name,
                    func_name=node.name,
                    lineno=node.lineno,
                    description=desc,
                    hints=hints,
                    params=params,
                    kind=kind,
                    node=node,
                    listing_entry=entry,
                )
            )
            break
    return tools


# rule P4.2 — a module that registers the SAME declared tool name more than
# once via the per-tool decorator (``@mcp.tool()`` twice on two different
# function bodies, both naming/overriding to the same tool name) is a
# structural rug-pull vector: whichever registration the SDK's own
# last-write-wins semantics actually keeps at runtime is an implementation
# detail a scanner has no business guessing at — a scan that only ever
# analyzes ONE of the two definitions (first or last) can silently miss
# whichever one carries the dangerous behavior. This returns every name with
# more than one definition, so the caller can analyze and MERGE all of them.
def find_duplicate_tool_defs(tree: ast.AST) -> Dict[str, List[ToolDef]]:
    by_name: Dict[str, List[ToolDef]] = {}
    for td in extract_tools(tree):
        by_name.setdefault(td.name, []).append(td)
    return {name: defs for name, defs in by_name.items() if len(defs) > 1}


def merge_behavior_facts(facts_list: List[BehaviorFacts]) -> BehaviorFacts:
    """rule P4.2 — combine the ``BehaviorFacts`` of every duplicate definition of
    one tool name into a single, WORST-CASE view: a boolean risk flag is
    true if ANY definition set it; list-valued evidence is the union (de-
    duplicated); ``auth_effective`` keeps ``False`` (a provably-ineffective
    guard) over ``True``/``None`` if any definition shows it, since a second,
    well-guarded definition must never hide a first one whose guard fails."""
    merged = BehaviorFacts()
    for f in facts_list:
        merged.writes_fs = merged.writes_fs or f.writes_fs
        merged.reads_fs = merged.reads_fs or f.reads_fs
        merged.deletes = merged.deletes or f.deletes
        merged.network = merged.network or f.network
        merged.spawns_proc = merged.spawns_proc or f.spawns_proc
        merged.code_exec = merged.code_exec or f.code_exec
        merged.mutates_module_state = merged.mutates_module_state or f.mutates_module_state
        merged.reads_env = merged.reads_env or f.reads_env
        merged.uses_call_counter_gate = merged.uses_call_counter_gate or f.uses_call_counter_gate
        merged.counter_gate_thresholds += [t for t in f.counter_gate_thresholds
                                           if t not in merged.counter_gate_thresholds]
        merged.uses_time_gate = merged.uses_time_gate or f.uses_time_gate
        merged.uses_env_gate = merged.uses_env_gate or f.uses_env_gate
        merged.gate_snippets += [s for s in f.gate_snippets if s not in merged.gate_snippets]
        merged.has_auth_check = merged.has_auth_check or f.has_auth_check
        merged.has_logging = merged.has_logging or f.has_logging
        merged.returns_external_content = (merged.returns_external_content
                                           or f.returns_external_content)
        if f.auth_effective is False:
            merged.auth_effective = False
            merged.auth_evidence = merged.auth_evidence or f.auth_evidence
        elif f.auth_effective is True and merged.auth_effective is None:
            merged.auth_effective = True
            merged.auth_evidence = merged.auth_evidence or f.auth_evidence
        merged.sinks += f.sinks
        if f.unused_params and not merged.unused_params:
            merged.unused_params = f.unused_params
        merged.returned_string_literals += [
            s for s in f.returned_string_literals if s not in merged.returned_string_literals]
        merged.mutates_tool_metadata = merged.mutates_tool_metadata or f.mutates_tool_metadata
        merged.tool_metadata_mutation_snippets += f.tool_metadata_mutation_snippets
        merged.tool_metadata_mutation_texts += [
            t for t in f.tool_metadata_mutation_texts
            if t not in merged.tool_metadata_mutation_texts]
        merged.mutated_state_names += [
            n for n in f.mutated_state_names if n not in merged.mutated_state_names]
        merged.accumulates_state = merged.accumulates_state or f.accumulates_state
        merged.accumulation_snippets += f.accumulation_snippets
        merged.resets_state = merged.resets_state or f.resets_state
        for k, v in f.candidate_values.items():
            bucket = merged.candidate_values.setdefault(k, [])
            for val in v:
                if val not in bucket:
                    bucket.append(val)
        for rec in f.assembled_strings:
            if rec not in merged.assembled_strings:
                merged.assembled_strings.append(rec)
        for rec in f.environ_dumps:
            if rec not in merged.environ_dumps:
                merged.environ_dumps.append(rec)
        merged.literal_origins.update(f.literal_origins)
        merged.followed_modules += [m for m in f.followed_modules
                                    if m not in merged.followed_modules]
    return merged


# ---------------------------------------------------------------------------
# rule 2.7 — tools registered WITHOUT a per-tool decorator: the functional-
# registration form (``mcp.add_tool(fn)`` / ``mcp.tool()(fn)``), and the
# low-level SDK's two-handler style (``@server.list_tools()`` returns every
# tool's declared name/description/schema in one place; ``@server.call_tool()``
# dispatches every CALL by comparing a ``name`` argument against string
# literals, or through a module-level ``{"name": handler_fn}`` table). Neither
# shape has one decorator per tool, so ``extract_tools`` above never sees
# them — a server written this way was reported as having zero tools by
# source analysis even while it demonstrably has some at runtime.

_REGISTER_CALL_METHODS = {"add_tool", "register_tool"}


def _dict_literal_to_obj(node: Optional[ast.AST]) -> Any:
    """Best-effort static evaluation of a JSON-shaped literal (dict/list/
    scalar) — used to read an inline ``inputSchema={...}`` literal without
    executing anything."""
    if node is None:
        return None
    if isinstance(node, ast.Dict):
        out: Dict[str, Any] = {}
        for k, v in zip(node.keys, node.values):
            key = _literal(k)
            if isinstance(key, str):
                out[key] = _dict_literal_to_obj(v)
        return out
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_dict_literal_to_obj(e) for e in node.elts]
    return _literal(node)


def _listing_literal(node: Optional[ast.AST], consts: Dict[str, str], depth: int = 0) -> Any:
    """v5-6 — a JSON-shaped value for one registration keyword argument: a
    dict / list literal (recursively), a constructor call read as the dict
    of its keyword arguments (``ToolAnnotations(title=...)``), a string
    expression resolved like a description (literal, named constant,
    concatenation), or a plain scalar literal. ``None`` when not static."""
    if node is None or depth > 8:
        return None
    if isinstance(node, ast.Dict):
        out: Dict[str, Any] = {}
        for k, v in zip(node.keys, node.values):
            key = _literal(k) if k is not None else None
            if isinstance(key, str):
                val = _listing_literal(v, consts, depth + 1)
                if val is not None:
                    out[key] = val
        return out
    if isinstance(node, (ast.List, ast.Tuple)):
        vals = [_listing_literal(e, consts, depth + 1) for e in node.elts]
        return [v for v in vals if v is not None]
    if isinstance(node, ast.Call):
        out = {}
        for kw in node.keywords:
            if kw.arg:
                val = _listing_literal(kw.value, consts, depth + 1)
                if val is not None:
                    out[kw.arg] = val
        return out or None
    text = _resolve_str(node, consts)
    if isinstance(text, str):
        return text
    return _literal(node)


def _has_string(obj: Any) -> bool:
    if isinstance(obj, str):
        return True
    if isinstance(obj, dict):
        return any(_has_string(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_string(v) for v in obj)
    return False


def _listing_entry_from_kwargs(kwargs: Dict[str, ast.AST], consts: Dict[str, str]
                               ) -> Dict[str, Any]:
    """The keyword arguments of one tool registration as listing-entry
    fields — everything except the name and the description, and only
    values that carry at least one string."""
    out: Dict[str, Any] = {}
    for key, value in kwargs.items():
        if not isinstance(key, str) or key in ("name", "description"):
            continue
        obj = _listing_literal(value, consts)
        if _has_string(obj):
            out[key] = obj
    return out


def _extract_functional_registrations(tree: ast.AST,
                                      module_functions: Dict[str, ast.AST],
                                      consts: Dict[str, str]) -> List[ToolDef]:
    """``mcp.add_tool(fn)`` / ``server.register_tool(fn, name=..., ...)`` /
    the functional-decorator form ``mcp.tool()(fn)`` (a decorator called and
    immediately applied to an already-defined function, instead of written
    with ``@`` above it). In every case a bare-name reference to a module-
    level function is what actually gets registered as a tool; resolve that
    reference back to its ``FunctionDef`` and read the same signals
    ``extract_tools`` would have (docstring, params) plus any override kwarg."""
    out: List[ToolDef] = []
    seen_func_ids: Set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn_node: Optional[ast.AST] = None
        override_kwargs: List[ast.keyword] = []
        meth = last_attr(node.func)
        if meth in _REGISTER_CALL_METHODS and node.args:
            fn_node = node.args[0]
            override_kwargs = node.keywords
        elif (isinstance(node.func, ast.Call) and last_attr(node.func.func) == "tool"
              and len(node.args) == 1):
            # ``mcp.tool()(fn)`` / ``mcp.tool(name="x")(fn)``
            fn_node = node.args[0]
            override_kwargs = node.func.keywords
        if fn_node is None or not isinstance(fn_node, ast.Name):
            continue
        target = module_functions.get(fn_node.id)
        if target is None or id(target) in seen_func_ids:
            continue
        seen_func_ids.add(id(target))
        hints, name_override, desc_override = {}, None, None
        for kw in override_kwargs:
            if kw.arg == "name":
                name_override = _resolve_str(kw.value, consts)
            elif kw.arg == "description":
                desc_override = _resolve_str(kw.value, consts)
            elif kw.arg == "annotations" and isinstance(kw.value, ast.Dict):
                obj = _dict_literal_to_obj(kw.value)
                if isinstance(obj, dict):
                    hints = obj
        desc = desc_override or (ast.get_docstring(target) or "")
        params = [a.arg for a in target.args.args + target.args.kwonlyargs
                  if a.arg not in ("self", "cls", "ctx", "context")]
        out.append(ToolDef(
            name=name_override or target.name, func_name=target.name,
            lineno=getattr(target, "lineno", 0), description=desc, hints=hints,
            params=params, kind="tool", node=target,
        ))
    return out


_LOWLEVEL_LIST_METHODS = {"list_tools"}
_LOWLEVEL_CALL_METHODS = {"call_tool"}
_TOOL_CTOR_NAMES = {"Tool"}


def _decorated_with(node: ast.AST, method_names: Set[str]) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if last_attr(target) in method_names:
            return True
    return False


def _extract_tool_literals(func_node: ast.AST, consts: Dict[str, str]) -> List[ToolDef]:
    """Every ``Tool(name=..., description=..., inputSchema=...)``-shaped
    construction reachable inside a ``@server.list_tools()`` handler (the
    low-level SDK's ``mcp.types.Tool``, imported under any alias — matched by
    the bare constructor name, same shape-not-vocabulary approach as the rest
    of the file) or an equivalent ``{"name": ..., "description": ...}`` dict
    literal appended to the returned list."""
    out: List[ToolDef] = []
    for node in ast.walk(func_node):
        kwargs: Dict[str, ast.AST] = {}
        if isinstance(node, ast.Call) and last_attr(node.func) in _TOOL_CTOR_NAMES:
            kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        elif isinstance(node, ast.Dict):
            keys = [_literal(k) for k in node.keys]
            if "name" not in keys:
                continue
            kwargs = {k: v for k, v in zip(keys, node.values) if isinstance(k, str)}
        else:
            continue
        name = _resolve_str(kwargs.get("name"), consts) if "name" in kwargs else None
        if not name:
            continue
        desc = _resolve_str(kwargs.get("description"), consts) or ""
        schema = _dict_literal_to_obj(kwargs.get("inputSchema") or kwargs.get("input_schema"))
        params: List[str] = []
        if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
            params = list(schema["properties"].keys())
        out.append(ToolDef(name=name, func_name=name, lineno=getattr(node, "lineno", 0),
                           description=desc, hints={}, params=params, kind="tool",
                           node=None,
                           listing_entry=_listing_entry_from_kwargs(kwargs, consts)))
    return out


def _iter_literal_dispatch_branches(if_node: ast.If) -> List[Tuple[str, List[ast.stmt]]]:
    """Walk an ``if name == "x": ... elif name == "y": ...`` chain (an
    ``elif`` is a single nested ``If`` inside ``orelse``) and yield
    ``(literal_tool_name, branch_body)`` for every arm whose test directly
    compares a bare name against a string literal with ``==``."""
    out: List[Tuple[str, List[ast.stmt]]] = []
    cur: Optional[ast.If] = if_node
    while isinstance(cur, ast.If):
        test = cur.test
        lit: Optional[str] = None
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
            left, right = test.left, test.comparators[0]
            lv, rv = _literal(left), _literal(right)
            if isinstance(lv, str) and isinstance(right, ast.Name):
                lit = lv
            elif isinstance(rv, str) and isinstance(left, ast.Name):
                lit = rv
        if lit:
            out.append((lit, cur.body))
        if len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If):
            cur = cur.orelse[0]
        else:
            cur = None
    return out


def _collect_dict_dispatch_tables(tree: ast.AST, module_functions: Dict[str, ast.AST]
                                  ) -> Dict[str, Dict[str, ast.AST]]:
    """Module-level ``TABLE = {"tool_name": handler_fn, ...}`` where every
    value is a bare reference to a module-level function — the dict-dispatch
    shape ``call_tool`` handlers commonly use instead of an if/elif chain."""
    out: Dict[str, Dict[str, ast.AST]] = {}
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Dict)):
            continue
        mapping: Dict[str, ast.AST] = {}
        for k, v in zip(node.value.keys, node.value.values):
            key = _literal(k)
            if isinstance(key, str) and isinstance(v, ast.Name) and v.id in module_functions:
                mapping[key] = module_functions[v.id]
        if mapping:
            out[node.targets[0].id] = mapping
    return out


def _extract_lowlevel_call_tools(tree: ast.AST, module_functions: Dict[str, ast.AST]
                                 ) -> List[ToolDef]:
    """Bind a real implementation (an actual function body, or a synthesized
    one wrapping just the matching if/elif arm) to every tool name a
    ``@server.call_tool()`` handler dispatches on, so behavior facts (taint,
    hint-violation, ...) are computed for low-level-SDK tools exactly as they
    are for decorator-registered ones."""
    out: List[ToolDef] = []
    dispatch_tables = _collect_dict_dispatch_tables(tree, module_functions)
    for handler in _find_decorated_handlers(tree, _LOWLEVEL_CALL_METHODS):
        params = [a.arg for a in handler.args.args + handler.args.kwonlyargs
                  if a.arg not in ("self", "cls")]
        # dict-dispatch: only tables this handler actually references
        referenced_tables = {
            n.id for n in ast.walk(handler)
            if isinstance(n, ast.Name) and n.id in dispatch_tables
        }
        for tbl_name in referenced_tables:
            for tool_name, fn in dispatch_tables[tbl_name].items():
                fn_params = [a.arg for a in fn.args.args + fn.args.kwonlyargs
                            if a.arg not in ("self", "cls", "ctx", "context")]
                out.append(ToolDef(name=tool_name, func_name=fn.name,
                                   lineno=getattr(fn, "lineno", 0),
                                   description=ast.get_docstring(fn) or "",
                                   hints={}, params=fn_params, kind="tool", node=fn,
                                   taint_params=fn_params))
        # if/elif literal-comparison dispatch
        for stmt in handler.body:
            if not isinstance(stmt, ast.If):
                continue
            for tool_name, body in _iter_literal_dispatch_branches(stmt):
                synth = ast.Module(body=body, type_ignores=[])
                out.append(ToolDef(name=tool_name, func_name=f"{handler.name}[{tool_name}]",
                                   lineno=getattr(body[0], "lineno", 0) if body else 0,
                                   description="", hints={}, params=params, kind="tool",
                                   node=synth, taint_params=params))
            break  # only the first top-level if/elif chain in the handler
    return out


def _find_decorated_handlers(tree: ast.AST, method_names: Set[str]) -> List[ast.AST]:
    return [n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and _decorated_with(n, method_names)]


def extract_tools_all(tree: ast.AST, base: Optional[Dict[str, Any]] = None) -> List[ToolDef]:
    """rule 2.7 — every tool this module registers, however it registers them:
    the per-tool decorator form (``extract_tools``), the functional-
    registration form (``add_tool``/``mcp.tool()(fn)``), and the low-level
    SDK's shared ``list_tools``/``call_tool`` handler pair. Decorator-based
    entries win on a name collision (the most explicit, unambiguous source);
    a low-level ``list_tools`` description is merged onto a same-named
    ``call_tool`` behavior entry so BOTH the declared contract and the
    implementation are bound to the one live tool name a dynamic scan will
    see. ``base`` carries cross-module constants (see ``extract_tools``)."""
    consts = _collect_str_consts(tree, base)
    module_functions = collect_module_functions(tree)
    decorated = extract_tools(tree, base)
    by_name: Dict[str, ToolDef] = {td.name: td for td in decorated}
    for td in _extract_functional_registrations(tree, module_functions, consts):
        by_name.setdefault(td.name, td)
    # low-level: descriptions (list_tools) and behavior (call_tool), merged
    lowlevel_desc: Dict[str, ToolDef] = {}
    for handler in _find_decorated_handlers(tree, _LOWLEVEL_LIST_METHODS):
        for td in _extract_tool_literals(handler, consts):
            lowlevel_desc.setdefault(td.name, td)
    lowlevel_behavior = _extract_lowlevel_call_tools(tree, module_functions)
    lowlevel_names = {td.name for td in lowlevel_behavior} | set(lowlevel_desc)
    for name in lowlevel_names:
        if name in by_name:
            continue
        beh = next((td for td in lowlevel_behavior if td.name == name), None)
        desc = lowlevel_desc.get(name)
        if beh is not None and desc is not None:
            # rule P3.5 — ``params`` stays the DECLARED contract (the schema's
            # own property names, for schema/description-facing detectors);
            # ``taint_params`` carries the SYNTHESIZED node's real parameter
            # names (the handler's own ``name``/``arguments``-shaped params)
            # so taint analysis seeds sources that actually appear as bare
            # identifiers in the body, instead of the schema names (which
            # never do — they only ever appear as string KEYS into the
            # arguments dict).
            merged = ToolDef(name=name, func_name=beh.func_name, lineno=beh.lineno,
                             description=desc.description, hints=desc.hints or beh.hints,
                             params=desc.params or beh.params, kind="tool", node=beh.node,
                             taint_params=beh.taint_params or beh.params,
                             listing_entry=desc.listing_entry)
            by_name[name] = merged
        elif beh is not None:
            by_name[name] = beh
        elif desc is not None:
            by_name[name] = desc
    return list(by_name.values())


# ---------------------------------------------------------------------------
# Taint + behavior analysis for a single function body


class _FuncAnalyzer(ast.NodeVisitor):
    def __init__(self, params: List[str], module_globals: Set[str]):
        self.tainted: Set[str] = set(params)
        self.params = set(params)
        self.module_globals = module_globals
        self.declared_global: Set[str] = set()
        # local names that alias into module-level state (e.g. ``record =
        # _ACCOUNTS.get(user_id)``) — mutating *through* one of these is a
        # module-state mutation too, not just a direct ``GLOBAL[...] = x``.
        self.state_aliases: Set[str] = set()
        # rule 2.3 — local names read from PERSISTED state (a file/JSON blob),
        # e.g. ``count = int(open(path).read())`` or ``data = json.load(f)``
        # — a counter compared against a number after being routed through a
        # state file is the same rug-pull gate as one read straight off a
        # module global, just one indirection further (MCPSecBench's weather
        # tool: "the counter is a local read from a state file").
        self.file_state_aliases: Set[str] = set()
        # rule 2.5 — alias local name -> underlying module-global name, so a
        # mutation reached THROUGH an alias (``record = _STATE.get(k)``;
        # ``record["x"] = y``) is still attributed to the real global for
        # exposure comparison, not to the transient alias name.
        self.state_alias_root: Dict[str, str] = {}
        # rule 2.6 — names bound from a sanitizer call. ``stripped_names`` are
        # fully sanitized on their own (basename/shlex.quote); ``norm_path_names``
        # are only normalized and need a prefix/allow-list guard too (filled
        # in by ``_scan_sanitizer_guards`` after the full body is visited).
        self.stripped_names: Set[str] = set()
        self.norm_path_names: Set[str] = set()
        self.sanitizer_guarded_names: Set[str] = set()
        # rules P3.2/P3.3 — split guard sets: a halting allow-list sanitizes a
        # COMMAND; a normalized value + a prefix test against a constant
        # base sanitizes a PATH. Populated by ``_scan_sanitizer_guards``.
        self.allowlist_guarded_names: Set[str] = set()
        self.prefix_guarded_names: Set[str] = set()
        # rule 2.6 — one level of call inlining: module-level helper functions
        # this tool's body may call directly by (bare) name. Populated by the
        # caller (``analyze_tool_function``); left empty inside an inlined
        # helper's own analysis so inlining never recurses past one level.
        self.module_functions: Dict[str, ast.AST] = {}
        # rule 3.2 — module-level dict-literal name -> its string keys, for the
        # lookup-key candidate-value harvest.
        self.dict_literal_keys: Dict[str, List[str]] = {}
        # rule 2.2 (FP fix) — every REGISTERED tool's own function name in this
        # module, so a ``<name>.__doc__ = ...`` rewrite is only flagged when
        # ``<name>`` actually is a registered tool (its own or a sibling
        # tool's) — not an unrelated helper/local object that merely also
        # has a ``__doc__`` attribute (every Python object does).
        self.registered_tool_names: Set[str] = set()
        # rule 2.2 (FP fix) — every name bound by a plain assignment/for/with/
        # comprehension target or nested def/class INSIDE this function's own
        # body. A ``description``/``instructions``/``annotations`` attribute
        # write through one of these is a fresh, local, non-registry object
        # (``meta = _Scratch(); meta.description = ...``), not a client-
        # visible tool contract, even if its name happens to contain a
        # tool-registry-shaped token like "meta"/"handler"/"tool".
        self.locally_bound_names: Set[str] = set()
        # v3-1.2 — local names whose value DERIVES from the result of a
        # network call / file read (``resp = requests.get(url)``, ``text =
        # resp.text``, ``with open(p) as fh``, ``data = json.load(fh)``), and
        # the ids of helper-call nodes whose callee itself returns external
        # content. A ``return`` whose expression references any of these is
        # a return of retrieved (third-party) content.
        self.read_derived: Set[str] = set()
        self.read_derived_call_ids: Set[int] = set()
        # v3-4.5 — module-level instance name (or class name) -> {method
        # name -> FunctionDef}, so ``R.go(x)`` with ``R = Runner()`` at module
        # scope inlines ``Runner.go``; and the remaining inlining depth (two
        # levels from the tool body).
        self.instance_methods: Dict[str, Dict[str, ast.AST]] = {}
        self.inline_depth: int = 2
        self.facts = BehaviorFacts()
        self._src = ""

    def _is_state_root(self, root: Optional[str]) -> bool:
        if root is None or root in self.params:
            return False
        return (root in self.module_globals or root in self.declared_global
                or root in self.state_aliases)

    def _is_state_derived(self, node: ast.AST) -> bool:
        """True if ``node`` is a direct dereference of module state: the
        global itself, a subscript/attribute off it, or an alias-producing
        access method (``.get``/``.setdefault``) on it or on an existing
        alias. Deliberately excludes ``.copy()``/other calls so copying
        global data into a local and mutating the *copy* is not misread as a
        state mutation (that would be a real false-positive source)."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and last_attr(node.func) in _ALIAS_METHODS:
                return self._is_state_root(_root_name(node.func.value))
            return False
        if isinstance(node, (ast.Subscript, ast.Attribute, ast.Name)):
            return self._is_state_root(_root_name(node))
        return False

    @staticmethod
    def _calls_read_file_state(scan_root: ast.AST) -> bool:
        for n in ast.walk(scan_root):
            if not isinstance(n, ast.Call):
                continue
            dn = dotted_name(n)
            meth = last_attr(n.func)
            if dn == "open" or dn in ("json.load", "json.loads"):
                return True
            if meth in ("read", "readline", "readlines", "read_text", "load", "loads"):
                return True
        return False

    def _is_file_state_derived(self, node: Optional[ast.AST]) -> bool:
        """rules 2.3/P4.4 — True if ``node``'s expression reads PERSISTED state: an
        ``open(...)``/``.read()``/``.readline()``/``.readlines()``/
        ``json.load(...)``/``json.loads(...)``/``.read_text()`` call
        anywhere inside it, DIRECTLY or through one level of indirection
        (a bare-name call to a local module-level HELPER function that
        itself reads saved state SOMEWHERE in its body and returns a value
        — the counter-from-state-file gate, one function call away instead
        of inline, e.g. ``def _load_count(): ...json.load(f)...; return
        data["count"]``). A local counter derived either way and later
        compared with a number is the same rug-pull gate as one read
        straight from a module global."""
        if node is None:
            return False
        if self._calls_read_file_state(node):
            return True
        for n in ast.walk(node):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id in self.module_functions):
                helper = self.module_functions[n.func.id]
                has_return_value = any(
                    isinstance(r, ast.Return) and r.value is not None
                    for r in ast.walk(helper))
                if has_return_value and self._calls_read_file_state(helper):
                    return True
        return False

    # --- v3-1.2 read-derivation helpers ---
    @staticmethod
    def _is_read_call(node: ast.AST) -> bool:
        """A call that READS external content: a network call, ``open()``
        in a read mode, or a pathlib/file-object read method."""
        if not isinstance(node, ast.Call):
            return False
        dn = dotted_name(node)
        meth = last_attr(node.func)
        if dn in NETWORK_SINKS or meth in NETWORK_METHODS:
            return True
        if dn in FILE_OPEN or meth == "open":
            mode = ""
            if len(node.args) >= 2:
                m = _literal(node.args[1])
                mode = m if isinstance(m, str) else ""
            for kw in node.keywords:
                if kw.arg == "mode":
                    m = _literal(kw.value)
                    mode = m if isinstance(m, str) else mode
            return not any(c in mode for c in ("w", "a", "x"))
        if meth in FILE_READ_METHODS:
            return True
        return False

    def _expr_is_read_derived(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in self.read_derived:
                return True
            if isinstance(n, ast.Call) and (self._is_read_call(n)
                                            or id(n) in self.read_derived_call_ids):
                return True
        return False

    def visit_Return(self, node: ast.Return):
        self.generic_visit(node)
        if node.value is not None and self._expr_is_read_derived(node.value):
            self.facts.returns_external_content = True

    def visit_With(self, node: ast.With):
        self.generic_visit(node)
        for item in node.items:
            if item.optional_vars is not None and self._expr_is_read_derived(item.context_expr):
                self.read_derived |= self._names_in(item.optional_vars)

    def visit_AsyncWith(self, node: ast.AsyncWith):
        self.visit_With(node)  # type: ignore[arg-type]

    def visit_For(self, node: ast.For):
        self.generic_visit(node)
        if self._expr_is_read_derived(node.iter):
            self.read_derived |= self._names_in(node.target)

    def visit_AsyncFor(self, node: ast.AsyncFor):
        self.visit_For(node)  # type: ignore[arg-type]

    # --- taint helpers ---
    def _names_in(self, node: ast.AST) -> Set[str]:
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    def _is_tainted_expr(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        # any tainted Name referenced inside the expression
        return bool(self._names_in(node) & self.tainted)

    def _tainted_params_in(self, node: ast.AST) -> List[str]:
        names = self._names_in(node)
        direct = sorted(names & self.params)
        if direct:
            return direct
        # tainted via derived vars -> attribute to whole-tool
        return sorted(names & self.tainted) if names & self.tainted else []

    # --- visitors ---
    def visit_Global(self, node: ast.Global):
        self.declared_global.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal):
        self.declared_global.update(node.names)

    def visit_Assign(self, node: ast.Assign):
        self.generic_visit(node)
        tainted = self._is_tainted_expr(node.value)
        derived = self._is_state_derived(node.value)
        file_derived = self._is_file_state_derived(node.value)
        read_derived = self._expr_is_read_derived(node.value)
        for tgt in node.targets:
            for nm in self._names_in(tgt):
                if tainted:
                    self.tainted.add(nm)
                if read_derived:
                    self.read_derived.add(nm)
            # a plain ``x = <state-derived expr>`` makes x itself an alias of
            # module state, so a later mutation *through* x is still caught.
            if derived and isinstance(tgt, ast.Name):
                self.state_aliases.add(tgt.id)
                underlying = _root_name(node.value)
                if underlying:
                    self.state_alias_root[tgt.id] = self.state_alias_root.get(
                        underlying, underlying)
            # rule 2.3 — same idea, one indirection further: ``x`` derived from a
            # file/JSON read is a candidate counter-gate operand too.
            if file_derived and isinstance(tgt, ast.Name):
                self.file_state_aliases.add(tgt.id)
            # module-state mutation (reassigning the global, or a subscript/
            # attribute write through the global or one of its aliases)
            self._check_state_mutation(tgt)
            # v3-4.2 — a reset: a module global (or a constant-keyed slot
            # of one) assigned an empty/zero/None/False value.
            if _is_reset_value(node.value):
                if isinstance(tgt, ast.Name) and (
                        tgt.id in self.declared_global or tgt.id in self.module_globals):
                    self.facts.resets_state = True
                elif isinstance(tgt, ast.Subscript) and self._is_state_root(_root_name(tgt)):
                    key = tgt.slice.value if isinstance(tgt.slice, ast.Index) else tgt.slice
                    if _literal(key) is not None:
                        self.facts.resets_state = True
            # rule 2.2 — runtime rewrite of a function's __doc__ or of
            # registered tool metadata (description/instructions/annotations
            # on a tool/registry-shaped object).
            if isinstance(tgt, ast.Attribute) and _looks_like_tool_metadata_target(
                    tgt, self.registered_tool_names, self.locally_bound_names):
                self.facts.mutates_tool_metadata = True
                self.facts.tool_metadata_mutation_snippets.append(self._snippet(node))
        # rule 2.6 — sanitizer modeling: a tainted value passed through
        # basename/shlex.quote (fully sanitized) or realpath/normpath/
        # abspath/.resolve() (normalized; needs a guard, checked post-hoc)
        # makes the ASSIGNED name a sanitizer-derived name, tracked
        # separately from plain taint so a sink reached through it can be
        # downgraded instead of reported identically to an unguarded one.
        # v4-5 — the sanitizer may sit ANYWHERE in the value's expression
        # tree, not only at its top level: ``os.path.join(BASE, os.path.
        # basename(name))``, ``f"ls {shlex.quote(p)}"``, ``"ls " + shlex.
        # quote(p)``, ``os.path.join(BASE, os.path.normpath(sub))``,
        # ``Path(BASE, name).resolve()``. The assigned name is stripped when
        # EVERY tainted name in the value reaches it only inside a strip/
        # quote call, normalized when every one reaches it only inside a
        # normalization call (a raw tainted name beside the sanitized one
        # keeps the result plain-tainted).
        if tainted:
            names_here = set()
            for tgt in node.targets:
                names_here |= self._names_in(tgt)
            raw_s, in_s = self._taint_relative_to_sanitizers([node.value], "strip")
            if in_s and not raw_s:
                self.stripped_names |= names_here
            else:
                raw_n, in_n = self._taint_relative_to_sanitizers([node.value], "norm")
                if in_n and not raw_n:
                    self.norm_path_names |= names_here

    def visit_AugAssign(self, node: ast.AugAssign):
        self.generic_visit(node)
        if isinstance(node.target, ast.Attribute) and _looks_like_tool_metadata_target(
                node.target, self.registered_tool_names, self.locally_bound_names):
            self.facts.mutates_tool_metadata = True
            self.facts.tool_metadata_mutation_snippets.append(self._snippet(node))
        if self._is_tainted_expr(node.value):
            for nm in self._names_in(node.target):
                self.tainted.add(nm)
        if self._expr_is_read_derived(node.value):
            self.read_derived |= self._names_in(node.target)
        self._check_state_mutation(node.target, aug=True)
        # rule 2.4 — an in-place ``+=``/``-=`` on server state is an accumulation:
        # the same call changes the result again each time, contradicting
        # idempotentHint=true.
        if (isinstance(node.op, (ast.Add, ast.Sub))
                and self._is_state_root(_root_name(node.target))):
            self.facts.accumulates_state = True
            self.facts.accumulation_snippets.append(self._snippet(node))

    def visit_Delete(self, node: ast.Delete):
        self.generic_visit(node)
        for tgt in node.targets:
            self._check_state_mutation(tgt)

    def _check_state_mutation(self, tgt: ast.AST, aug: bool = False):
        # A bare ``x = ...`` (Name target) never mutates anything by itself —
        # it rebinds a name. If that name is the module global itself (an
        # explicit ``global``/``nonlocal`` declaration, or the same name as a
        # module-level assignment), reassigning it IS a real mutation
        # (``_ACCOUNTS = {}``). But if the name is merely a *fresh local
        # alias* being created right now from a state-derived expression
        # (``record = _ACCOUNTS.get(id)``), that assignment itself mutates
        # nothing — only a LATER write *through* that alias
        # (``record["x"] = y``) does. Consulting ``state_aliases`` here too
        # (as a plain root-name check would) misreads "I just created an
        # alias" as "I just mutated state" — a real false-positive source.
        if isinstance(tgt, ast.Name):
            if tgt.id in self.params:
                return
            if tgt.id in self.declared_global or tgt.id in self.module_globals:
                self.facts.mutates_module_state = True
                self.facts.mutated_state_names.append(tgt.id)
            return
        if isinstance(tgt, (ast.Subscript, ast.Attribute)):
            root = _root_name(tgt)
            if self._is_state_root(root):
                self.facts.mutates_module_state = True
                gname = self.state_alias_root.get(root, root) if root else None
                if gname:
                    self.facts.mutated_state_names.append(gname)

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)
        dn = dotted_name(node)
        meth = last_attr(node.func)
        shell = any(
            kw.arg == "shell" and _literal(kw.value) is True for kw in node.keywords
        )
        all_arg_nodes = list(node.args) + [kw.value for kw in node.keywords]
        tainted = any(self._is_tainted_expr(a) for a in all_arg_nodes)
        tparams: List[str] = []
        for a in all_arg_nodes:
            tparams += self._tainted_params_in(a)
        tparams = sorted(set(tparams))
        snippet = self._snippet(node)
        arg_names = sorted(set().union(*[self._names_in(a) for a in all_arg_nodes]) if all_arg_nodes else set())

        # rule P3.2 — an argument-LIST call (the command's argv passed as a
        # literal list/tuple, e.g. ``subprocess.run([binary, arg], ...)``)
        # with no shell involved never lets a shell reinterpret any element,
        # regardless of what those elements contain — one of the three
        # accepted command sanitizers, independent of quoting/allow-listing.
        arglist_no_shell = (not shell and bool(node.args)
                            and isinstance(node.args[0], (ast.List, ast.Tuple)))
        # rule P3.4 — does the sink call pass one of THIS analyzer's own
        # parameters straight through as a bare ``Name`` (not wrapped in a
        # rebinding/format/join)? Only meaningful inside a helper's own
        # analysis (``self.params`` there is the helper's parameter set);
        # harmless to compute unconditionally.
        direct_param_passthrough = any(
            isinstance(a, ast.Name) and a.id in self.params for a in all_arg_nodes
        )
        # v3-3.4 — tainted names that reach the sink ONLY through a
        # basename/shlex.quote call nested inside the argument expression.
        raw_tainted, inside_strip = self._taint_relative_to_sanitizers(all_arg_nodes, "strip")
        strip_nested = inside_strip and not raw_tainted

        def add_sink(kind: str, tainted_override: Optional[bool] = None,
                    tainted_params_override: Optional[List[str]] = None):
            self.facts.sinks.append(
                SinkRecord(kind=kind, lineno=getattr(node, "lineno", 0), call=dn or meth,
                           tainted=tainted if tainted_override is None else tainted_override,
                           shell=shell,
                           tainted_params=tparams if tainted_params_override is None
                                         else tainted_params_override,
                           snippet=snippet, arg_names=arg_names,
                           arglist_no_shell=arglist_no_shell,
                           via_helper_passthrough=direct_param_passthrough,
                           strip_nested=strip_nested,
                           raw_tainted_names=sorted(raw_tainted))
            )

        # command execution
        if dn in COMMAND_SINKS or (meth in ("system", "popen") and dn.endswith(("os.system", "os.popen"))):
            self.facts.spawns_proc = True
            add_sink("command-exec")
        # code exec / import
        if dn in CODE_EXEC_SINKS and isinstance(node.func, ast.Name):
            self.facts.code_exec = True
            add_sink("code-exec")
        # unsafe deserialize (yaml.load only unsafe without SafeLoader)
        if dn in DESERIALIZE_SINKS:
            if dn.startswith("yaml.load"):
                safe = any(
                    kw.arg == "Loader" and last_attr(kw.value).lower().startswith("safe")
                    for kw in node.keywords
                )
                if not safe and dn != "yaml.safe_load":
                    self.facts.code_exec = True
                    add_sink("deserialize")
            else:
                self.facts.code_exec = True
                add_sink("deserialize")
        # network — rule P3.6: SSRF taint counts only a URL/host-shaped argument
        # (the conventional first positional arg to a network call, or a
        # keyword whose own name is url/host/address/endpoint/domain-shaped)
        # — a tainted timeout/header/option elsewhere in the call is not a
        # request-forgery signal, whatever else the call also received.
        if dn in NETWORK_SINKS or meth in NETWORK_METHODS:
            self.facts.network = True
            ssrf_candidates: List[ast.AST] = []
            if node.args:
                ssrf_candidates.append(node.args[0])
            for kw in node.keywords:
                if kw.arg and set(_split_ident_tokens(kw.arg)) & _SSRF_ARG_NAME_TOKENS:
                    ssrf_candidates.append(kw.value)
            ssrf_tainted = any(self._is_tainted_expr(a) for a in ssrf_candidates)
            ssrf_tparams: List[str] = []
            for a in ssrf_candidates:
                ssrf_tparams += self._tainted_params_in(a)
            add_sink("network", tainted_override=ssrf_tainted,
                     tainted_params_override=sorted(set(ssrf_tparams)))
        # delete
        if dn in DELETE_SINKS or meth in DELETE_METHODS:
            self.facts.deletes = True
            self.facts.writes_fs = True
            add_sink("file-delete")
        # explicit write sinks
        if dn in WRITE_SINKS:
            self.facts.writes_fs = True
            add_sink("file-write")
        # open() — inspect mode
        if dn in FILE_OPEN or meth == "open":
            mode = ""
            if len(node.args) >= 2:
                m = _literal(node.args[1])
                mode = m if isinstance(m, str) else ""
            for kw in node.keywords:
                if kw.arg == "mode":
                    m = _literal(kw.value)
                    mode = m if isinstance(m, str) else mode
            if any(c in mode for c in ("w", "a", "x", "+")):
                self.facts.writes_fs = True
                add_sink("file-write")
            else:
                self.facts.reads_fs = True
                add_sink("file-read")
        # pathlib / read-write methods
        if meth in FILE_WRITE_METHODS and meth != "write":  # write_text etc.
            self.facts.writes_fs = True
            add_sink("file-write")
        elif meth == "write":
            self.facts.writes_fs = True
        if meth in FILE_READ_METHODS and meth != "read":
            self.facts.reads_fs = True
            add_sink("file-read")
        if meth in ("makedirs", "mkdir"):
            self.facts.writes_fs = True
        # env reads
        if dn in ("os.getenv", "os.environ.get") or dn.startswith("os.environ"):
            self.facts.reads_env = True
        # mutating collection method (``record["notes"].append(x)``,
        # ``_ACCOUNTS[id].pop("k")``, ``_seen.add(x)`` ...) called on module
        # state or an alias of it — the same "aliased state mutation" gap as
        # above, just reached through a method call instead of an Assign.
        if meth in _MUTATING_METHODS and isinstance(node.func, ast.Attribute):
            root = _root_name(node.func.value)
            if self._is_state_root(root):
                self.facts.mutates_module_state = True
                gname = self.state_alias_root.get(root, root) if root else None
                if gname:
                    self.facts.mutated_state_names.append(gname)
                # rule 2.4 — append/extend/insert/add GROW a collection: the
                # same accumulation shape as an in-place ``+=``.
                if meth in ("append", "extend", "insert", "add"):
                    self.facts.accumulates_state = True
                    self.facts.accumulation_snippets.append(snippet)
                # v3-4.2 — ``.clear()`` on module state is a reset.
                if meth == "clear":
                    self.facts.resets_state = True
        # v3-4.2 — rewriting a state file with an empty/zero payload
        # (``json.dump({}, fh)``, ``fh.write("")``, ``p.write_text("0")``).
        if node.args and _is_reset_value(node.args[0]) and (
                dn == "json.dump" or meth in ("write", "write_text")):
            self.facts.resets_state = True

        # rule 2.6 — one level of call inlining. A bare-name call to a local
        # module-level helper function, with a tainted argument, is analyzed
        # as its OWN taint problem: the helper's own parameters are the
        # sources (seeded only with the ones that actually received a
        # tainted argument at this call site), and any sink the helper
        # reaches with one of them is exactly as real a finding as if the
        # tool had inlined the helper's body itself — a taint-passing
        # wrapper (``def _run(cmd): os.system(cmd)``) is a command-injection
        # sink whether or not the tool calls ``os.system`` directly.
        # ``self.module_functions`` is intentionally left empty on the
        # analyzer used for the helper's own body (see ``analyze_tool_function``),
        # so this never recurses past one level.
        if (isinstance(node.func, ast.Name) and self.module_functions
                and node.func.id in self.module_functions):
            self._inline_helper_call(node.func.id, node, all_arg_nodes, tparams)
            # v3-1.2 — a helper whose own body returns retrieved content
            # (``def _fetch(u): return requests.get(u).text``) makes THIS
            # call's result read-derived in the caller, tainted or not.
            if self._helper_returns_external(node.func.id):
                self.read_derived_call_ids.add(id(node))
        # v3-4.5 — a method call on a MODULE-LEVEL INSTANCE (``R.go(x)``
        # where ``R = Runner()`` at module scope) or a class-level call
        # (``Runner.go(x)``) is inlined exactly like a bare-name helper.
        if (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                and self.instance_methods
                and node.func.value.id in self.instance_methods):
            method = self.instance_methods[node.func.value.id].get(node.func.attr)
            if method is not None:
                key = f"{node.func.value.id}.{node.func.attr}"
                self._inline_helper_call(key, node, all_arg_nodes, tparams, helper=method)
                if self._helper_returns_external(key, method):
                    self.read_derived_call_ids.add(id(node))

    def _helper_returns_external(self, fname: str, helper: Optional[ast.AST] = None) -> bool:
        """v3-1.2 — does the module-level helper ``fname`` return content
        derived from a network call / file read in its own body? Analyzed
        once per helper (no further inlining inside it)."""
        cache = getattr(self, "_helper_external_cache", None)
        if cache is None:
            cache = self._helper_external_cache = {}
        if fname in cache:
            return cache[fname]
        helper = helper if helper is not None else self.module_functions.get(fname)
        result = False
        if isinstance(helper, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [a.arg for a in helper.args.args + helper.args.kwonlyargs]
            az = _FuncAnalyzer(params, self.module_globals)
            az._src = self._src
            try:
                az.visit(helper)
                result = az.facts.returns_external_content
            except Exception:
                result = False
        cache[fname] = result
        return result

    @staticmethod
    def _is_sanitizer_call(n: ast.AST, kind: str) -> bool:
        if not isinstance(n, ast.Call):
            return False
        dn = dotted_name(n)
        if kind == "strip":
            return dn in PATH_STRIP_CALLS or dn in COMMAND_SANITIZE_CALLS
        return (dn in PATH_NORMALIZE_CALLS
                or (isinstance(n.func, ast.Attribute)
                    and n.func.attr in PATH_NORMALIZE_METHODS))

    def _taint_relative_to_sanitizers(self, arg_nodes: List[ast.AST], kind: str
                                      ) -> Tuple[Set[str], bool]:
        """v3-3.4/v4-5 — (raw_names, any_inside): the tainted names that
        occur OUTSIDE any nested sanitizer call of class ``kind`` ("strip" =
        basename/shlex.quote, "norm" = realpath/normpath/abspath/.resolve())
        anywhere in these expression trees, and whether any tainted name
        occurs INSIDE one. For a method-form sanitizer (``Path(x).resolve()``)
        the receiver counts as inside."""
        raw: Set[str] = set()
        inside = False

        def walk(n: ast.AST, in_san: bool) -> None:
            nonlocal inside
            if not in_san and self._is_sanitizer_call(n, kind):
                parts = list(n.args) + [kw.value for kw in n.keywords]
                if isinstance(n.func, ast.Attribute):
                    parts.append(n.func.value)
                for a in parts:
                    walk(a, True)
                return
            if isinstance(n, ast.Name) and n.id in self.tainted:
                if in_san:
                    inside = True
                else:
                    raw.add(n.id)
            for child in ast.iter_child_nodes(n):
                walk(child, in_san)

        for a in arg_nodes:
            walk(a, False)
        return raw, inside

    def _taint_relative_to_strip_calls(self, arg_nodes: List[ast.AST]):
        """(tainted_outside, tainted_inside) for the strip/quote class."""
        raw, inside = self._taint_relative_to_sanitizers(arg_nodes, "strip")
        return bool(raw), inside

    def _inline_helper_call(self, fname: str, call_node: ast.Call,
                             all_arg_nodes: List[ast.AST], caller_tparams: List[str],
                             helper: Optional[ast.AST] = None) -> None:
        if self.inline_depth <= 0:
            return
        helper = helper if helper is not None else self.module_functions.get(fname)
        if helper is None or not isinstance(helper, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return
        helper_params = [a.arg for a in helper.args.args + helper.args.kwonlyargs
                          if a.arg not in ("self", "cls", "ctx", "context")]
        if not helper_params:
            return
        # positional-then-keyword mapping from the call site to the helper's
        # own parameter names, so only the parameters that ACTUALLY received
        # a tainted argument are seeded as sources in the helper's analysis.
        tainted_helper_params: Set[str] = set()
        pos_args = call_node.args
        for i, a in enumerate(pos_args):
            if i < len(helper_params) and self._is_tainted_expr(a):
                tainted_helper_params.add(helper_params[i])
        for kw in call_node.keywords:
            if kw.arg and kw.arg in helper_params and self._is_tainted_expr(kw.value):
                tainted_helper_params.add(kw.arg)
        if not tainted_helper_params:
            return
        helper_az = _FuncAnalyzer(helper_params, self.module_globals)
        helper_az._src = self._src
        helper_az.tainted = set(tainted_helper_params)
        # v3-4.5 — a SECOND level of inlining: the helper's own analyzer
        # may inline the module's other helpers/instance methods once more
        # (never itself), after which inlining stops.
        helper_az.inline_depth = self.inline_depth - 1
        if helper_az.inline_depth > 0:
            helper_az.module_functions = {n: f for n, f in self.module_functions.items()
                                          if n != fname}
            helper_az.instance_methods = self.instance_methods
        for n in ast.walk(helper):
            if isinstance(n, ast.Global):
                helper_az.declared_global.update(n.names)
            elif isinstance(n, ast.Nonlocal):
                helper_az.declared_global.update(n.names)
        try:
            helper_az.visit(helper)
            helper_az._scan_sanitizer_guards(helper)
            _resolve_sink_sanitization(helper_az)
        except Exception:
            return
        # v3-4.5 — does THIS call site hand one of the caller's own
        # parameters straight through as a bare Name? A nested (second-
        # level) sink is a bare passthrough chain only when every hop is.
        passthrough_here = any(
            isinstance(a, ast.Name) and a.id in self.params
            for a in list(call_node.args) + [kw.value for kw in call_node.keywords])
        for sink in helper_az.facts.sinks:
            if not sink.tainted:
                continue
            nested = bool(sink.via_helper)
            self.facts.sinks.append(SinkRecord(
                kind=sink.kind, lineno=sink.lineno, call=f"{fname}() -> {sink.call}",
                tainted=True, shell=sink.shell,
                tainted_params=caller_tparams or sink.tainted_params,
                snippet=sink.snippet, arg_names=sink.arg_names,
                sanitized=sink.sanitized, via_helper=fname,
                # rule P3.4 — did the HELPER pass the tainted value straight
                # through, unchanged, into this sink?
                via_helper_passthrough=(sink.via_helper_passthrough and passthrough_here)
                if nested else sink.via_helper_passthrough,
                arglist_no_shell=sink.arglist_no_shell,
                strip_nested=sink.strip_nested,
                raw_tainted_names=sink.raw_tainted_names,
            ))
        # a helper reached through inlining can mutate module state, use the
        # network, spawn a process etc. too — fold its facts into the caller
        # so hint-violation/scope-creep see the real behavior of a tool that
        # only *calls* a mutating helper, not just one that mutates directly.
        self.facts.writes_fs = self.facts.writes_fs or helper_az.facts.writes_fs
        self.facts.deletes = self.facts.deletes or helper_az.facts.deletes
        self.facts.spawns_proc = self.facts.spawns_proc or helper_az.facts.spawns_proc
        self.facts.code_exec = self.facts.code_exec or helper_az.facts.code_exec
        self.facts.network = self.facts.network or helper_az.facts.network
        self.facts.mutates_module_state = (self.facts.mutates_module_state
                                           or helper_az.facts.mutates_module_state)
        self.facts.resets_state = self.facts.resets_state or helper_az.facts.resets_state
        # v6 — WHICH globals the helper mutated (so scope-creep's
        # bookkeeping-vs-domain test sees an honest counter in a helper as
        # bookkeeping, not as an unnamed mutation) and whether it grows a
        # collection; counter thresholds feed the call plan only.
        for nm in helper_az.facts.mutated_state_names:
            if nm not in self.facts.mutated_state_names:
                self.facts.mutated_state_names.append(nm)
        self.facts.accumulates_state = (self.facts.accumulates_state
                                        or helper_az.facts.accumulates_state)
        for thr in helper_az.facts.counter_gate_thresholds:
            if thr not in self.facts.counter_gate_thresholds:
                self.facts.counter_gate_thresholds.append(thr)

    # rules P3.1/P3.2/rule P3.3 — a guard only counts as a sanitizer when its FAILING
    # branch actually HALTS before the sink runs, not merely "referenced
    # somewhere in the function". These two helpers each recognize one
    # guard SHAPE on a single ``If``/``Assert`` test and report the names it
    # protects only when the control-flow evidence is really there.

    def _membership_guard_names(self, if_or_assert) -> Set[str]:
        """rule P3.2 — a "halts when the value is NOT a member of a literal/
        module-level collection" shape — the halting allow-list. Framed
        purely by which branch halts (never by whether the collection is
        named like an allow- or a deny-list): the miss-branch — whichever
        branch corresponds to non-membership — must halt. A collection that
        only halts on a HIT (a pure deny-list: ``if x in BLOCKED: raise``,
        nothing on the miss path) never matches this, by construction."""
        test = if_or_assert.test
        negate = False
        t = test
        if isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not):
            negate = True
            t = t.operand
        if not (isinstance(t, ast.Compare) and len(t.ops) == 1
                and isinstance(t.ops[0], (ast.In, ast.NotIn))):
            return set()
        operands = [t.left] + list(t.comparators)
        has_collection = any(
            isinstance(o, (ast.List, ast.Set, ast.Tuple))
            or (isinstance(o, ast.Name) and o.id in self.module_globals)
            for o in operands
        )
        if not has_collection:
            return set()
        names = {o.id for o in operands if isinstance(o, ast.Name)}
        if not names:
            return set()
        is_in = isinstance(t.ops[0], ast.In)
        if negate:
            is_in = not is_in
        # is_in=True  -> test-true means "member"; the miss (non-member)
        #                case is the ELSE branch, so ELSE must halt.
        # is_in=False -> test-true means "not a member" (a miss) directly;
        #                the IF's own BODY must halt.
        if isinstance(if_or_assert, ast.Assert):
            # an assert halts BY CONSTRUCTION exactly when its test is
            # false — for ``assert x in ALLOWED`` that is precisely "x is
            # not a member", the halting-allow-list shape, regardless of
            # is_in (an assert has no separate branches to check).
            return names
        if is_in:
            if if_or_assert.orelse and _block_halts(if_or_assert.orelse):
                return names
        else:
            if _block_halts(if_or_assert.body):
                return names
        return set()

    _CONST_PATH_WRAPPERS = frozenset({
        "os.path.join", "os.path.realpath", "os.path.abspath", "os.path.normpath",
        "os.fspath", "str", "Path", "pathlib.Path", "PurePath", "pathlib.PurePath",
    })
    _CONST_PATH_METHODS = frozenset({"resolve", "absolute", "as_posix", "rstrip", "strip"})
    _CONST_SEP_ATTRS = frozenset({"os.sep", "os.path.sep", "os.altsep", "os.linesep"})

    def _const_like(self, node: Optional[ast.AST]) -> bool:
        """rule P3.3/v3-3.4 — a base the server itself fixed: a literal, a
        module-level constant, ``os.sep``, and the canonical compositions of
        those (``BASE + os.sep``, ``BASE + "/"``, ``f"{BASE}/"``,
        ``os.path.join(BASE, "x")``, ``os.path.realpath(BASE)``,
        ``Path(BASE).resolve()``, a tuple of bases)."""
        if node is None:
            return False
        if _literal(node) is not None:
            return True
        # a module-level NAME (a constant the server itself defines), not a
        # caller-controlled/tainted value
        if isinstance(node, ast.Name):
            return node.id in self.module_globals and node.id not in self.tainted
        if isinstance(node, ast.Attribute):
            if dotted_name(node) in self._CONST_SEP_ATTRS:
                return True
            return self._const_like(node.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._const_like(node.left) and self._const_like(node.right)
        if isinstance(node, ast.JoinedStr):
            return all(self._const_like(v.value) for v in node.values
                       if isinstance(v, ast.FormattedValue))
        if isinstance(node, (ast.Tuple, ast.List)):
            return bool(node.elts) and all(self._const_like(e) for e in node.elts)
        if isinstance(node, ast.Call):
            args = list(node.args) + [kw.value for kw in node.keywords]
            dn = dotted_name(node)
            if dn in self._CONST_PATH_WRAPPERS:
                return bool(args) and all(self._const_like(a) for a in args)
            if (isinstance(node.func, ast.Attribute)
                    and node.func.attr in self._CONST_PATH_METHODS):
                return (self._const_like(node.func.value)
                        and all(self._const_like(a) for a in args))
        return False

    _GUARD_VALUE_WRAPPERS = frozenset({
        "os.path.realpath", "os.path.abspath", "os.path.normpath", "os.fspath",
        "str", "Path", "pathlib.Path",
    })

    def _guarded_value_names(self, node: ast.AST) -> Set[str]:
        """v3-3.4 — the local name(s) a prefix test actually guards: the
        receiver of ``.startswith``/``.is_relative_to``, looking THROUGH a
        canonical wrapper (``Path(real).is_relative_to(BASE)``,
        ``str(real).startswith(...)``) to the wrapped name."""
        if isinstance(node, ast.Name):
            return {node.id}
        if isinstance(node, ast.Call) and dotted_name(node) in self._GUARD_VALUE_WRAPPERS:
            out: Set[str] = set()
            for a in node.args:
                out |= self._guarded_value_names(a)
            return out
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in self._CONST_PATH_METHODS:
            return self._guarded_value_names(node.func.value)
        root = _root_name(node)
        return {root} if root else set()

    def _prefix_guard_names(self, if_or_assert) -> Set[str]:
        """rule P3.3 — a "halts when a normalized value does NOT sit under a
        CONSTANT base" shape (``.startswith(BASE)``/``.is_relative_to(BASE)``/
        ``os.path.commonpath([...]) == BASE``), where the base is something
        the server itself fixed (a literal or a module constant), never a
        caller-supplied/tainted value — a prefix test against an
        attacker-controlled "base" guards nothing."""
        test = if_or_assert.test
        negate = False
        t = test
        if isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not):
            negate = True
            t = t.operand
        names: Set[str] = set()
        is_match = None
        if (isinstance(t, ast.Call) and isinstance(t.func, ast.Attribute)
                and last_attr(t.func) in PREFIX_GUARD_METHODS):
            roots = self._guarded_value_names(t.func.value)
            base = t.args[0] if t.args else None
            if roots and self._const_like(base):
                names, is_match = set(roots), True
        elif (isinstance(t, ast.Compare) and len(t.ops) == 1
              and isinstance(t.ops[0], (ast.Eq, ast.NotEq))):
            left, right = t.left, t.comparators[0]
            for side, other in ((left, right), (right, left)):
                if isinstance(side, ast.Call) and dotted_name(side) in PREFIX_GUARD_CALLS:
                    if self._const_like(other):
                        names = self._names_in(side)
                        is_match = isinstance(t.ops[0], ast.Eq)
                    break
        if not names or is_match is None:
            return set()
        if negate:
            is_match = not is_match
        if isinstance(if_or_assert, ast.Assert):
            return names  # halts exactly on mismatch, by construction
        if is_match:
            if if_or_assert.orelse and _block_halts(if_or_assert.orelse):
                return names
        else:
            if _block_halts(if_or_assert.body):
                return names
        return set()

    def _scan_sanitizer_guards(self, func_node: ast.AST) -> None:
        """rule P3.1 — only an ``If``/``Assert`` whose FAILING branch halts
        before the sink counts as a sanitizing guard; a check merely present
        somewhere in the function (with no halting consequence) guards
        nothing. Tracked in TWO separate sets per rules P3.2/P3.3, since the two
        sink families accept different guard shapes: a halting allow-list
        sanitizes a COMMAND; a normalized value plus a prefix test against a
        constant base sanitizes a PATH. Neither substitutes for the other."""
        allowlist_guarded: Set[str] = set()
        prefix_guarded: Set[str] = set()
        for n in ast.walk(func_node):
            if isinstance(n, (ast.If, ast.Assert)):
                allowlist_guarded |= self._membership_guard_names(n)
                prefix_guarded |= self._prefix_guard_names(n)
        self.allowlist_guarded_names = allowlist_guarded
        self.prefix_guarded_names = prefix_guarded
        # kept for backward compatibility with any external reader of the
        # combined set (path guard callers already intersect with
        # ``norm_path_names`` too, so a command-only allow-list name showing
        # up here as well is harmless noise, never a false sanitization).
        self.sanitizer_guarded_names = allowlist_guarded | prefix_guarded

    def _harvest_candidate_values(self, func_node: ast.AST) -> None:
        """rules 3.2/P4.5 — candidate argument values for dynamic call synthesis,
        from two structural shapes (never vocabulary): a bare parameter
        compared directly with a string literal (or checked against a
        literal collection of strings, INLINE or bound to a local variable
        DEFINED INSIDE THE FUNCTION itself) with ``==``/``in``; and a
        parameter used as the lookup key into a dict literal — a
        module-level one (``self.dict_literal_keys``) OR one defined INSIDE
        the function as a local variable."""
        # rule P4.5 — collect list/tuple/set AND dict literals assigned to a
        # local variable inside this function, so a lookup table or an
        # allow-list defined locally (not just at module level) is just as
        # harvestable as one that happens to live at module scope.
        local_collections: Dict[str, List[str]] = {}
        local_dict_keys: Dict[str, List[str]] = {}
        for node in ast.walk(func_node):
            if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)):
                continue
            tgt = node.targets[0].id
            if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                lv = _literal(node.value)
                if isinstance(lv, (list, tuple, set)):
                    local_collections[tgt] = [x for x in lv if isinstance(x, str)]
            elif isinstance(node.value, ast.Dict):
                str_keys = [k for k in (_literal(k) for k in node.value.keys)
                           if isinstance(k, str)]
                if str_keys:
                    local_dict_keys[tgt] = str_keys

        # a) direct comparison: ``if user_id == "user1":`` / ``if role in
        # ("admin", "owner"):`` / ``if role in ALLOWED_ROLES:`` where
        # ALLOWED_ROLES is a collection literal defined in this function.
        for cmp_node in (n for n in ast.walk(func_node) if isinstance(n, ast.Compare)):
            if len(cmp_node.ops) != 1 or not isinstance(cmp_node.ops[0], (ast.Eq, ast.In)):
                continue
            left, right = cmp_node.left, cmp_node.comparators[0]
            param_name: Optional[str] = None
            lit_side: Optional[ast.AST] = None
            if isinstance(left, ast.Name) and left.id in self.params:
                param_name, lit_side = left.id, right
            elif isinstance(right, ast.Name) and right.id in self.params:
                param_name, lit_side = right.id, left
            if param_name is None:
                continue
            lv = _literal(lit_side)
            values: List[str] = []
            if isinstance(lv, str):
                values = [lv]
            elif isinstance(lv, (list, tuple, set)):
                values = [x for x in lv if isinstance(x, str)]
            elif isinstance(lit_side, ast.Name) and lit_side.id in local_collections:
                values = local_collections[lit_side.id]
            bucket = self.facts.candidate_values.setdefault(param_name, [])
            for v in values:
                if v not in bucket:
                    bucket.append(v)

        # b) lookup-key harvest: ``TABLE[param]`` / ``TABLE.get(param)`` /
        # ``TABLE.setdefault(param)`` where TABLE is a known dict literal --
        # module-level (``self.dict_literal_keys``) or local to this
        # function (``local_dict_keys``, rule P4.5).
        for node in ast.walk(func_node):
            key_node: Optional[ast.AST] = None
            base_root: Optional[str] = None
            if isinstance(node, ast.Subscript):
                base_root = _root_name(node.value)
                sl = node.slice
                key_node = sl.value if isinstance(sl, ast.Index) else sl  # py<3.9 vs 3.9+
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr in ("get", "setdefault", "pop") and node.args):
                base_root = _root_name(node.func.value)
                key_node = node.args[0]
            if base_root is None or key_node is None:
                continue
            if not (isinstance(key_node, ast.Name) and key_node.id in self.params):
                continue
            keys = self.dict_literal_keys.get(base_root) or local_dict_keys.get(base_root)
            if not keys:
                continue
            bucket = self.facts.candidate_values.setdefault(key_node.id, [])
            for v in keys:
                if v not in bucket:
                    bucket.append(v)

    def visit_If(self, node: ast.If):
        self._check_gate(node.test)
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        self._check_gate(node.test)
        self.generic_visit(node)

    def _check_gate(self, test: ast.AST):
        text = self._snippet(test)
        low = text.lower()
        # time gate
        for tok in ("time.time", "datetime.now", "datetime.utcnow", "date.today",
                    "time.monotonic", ".timestamp("):
            if tok in text:
                self.facts.uses_time_gate = True
                self.facts.gate_snippets.append(text)
                break
        # env gate
        if "os.environ" in text or "os.getenv" in text or "getenv" in low:
            self.facts.uses_env_gate = True
            self.facts.gate_snippets.append(text)
        # call-counter gate: a module-global (an int counter, by construction)
        # compared *directly* against a numeric literal via an
        # ordering/equality operator — e.g. ``if _calls >= 3:`` or
        # ``if failed_checks == 3:``. Deliberately narrow: any earlier
        # version that fired on "a global appears anywhere inside a Compare"
        # also matched ordinary business-logic membership tests like
        # ``if "old" in records[rid]:`` (a dict/string containment check that
        # has nothing to do with call counting) — a real false-positive
        # source. A genuine counter gate always compares the counter name
        # itself, directly, against a bare number — not a value nested inside
        # a subscript/attribute, and never via `in`/`is`.
        # rule 2.3 — the counter operand does not have to be the module global
        # ITSELF: a local variable that ALIASES module state (``record =
        # _STATE.get(k)``) or that was read from PERSISTED state (a file/JSON
        # blob: ``count = int(open(path).read())``) and is then compared
        # against a bare number is the same gate, one indirection further.
        for cmp_node in (n for n in ast.walk(test) if isinstance(n, ast.Compare)):
            if any(isinstance(op, (ast.In, ast.NotIn, ast.Is, ast.IsNot)) for op in cmp_node.ops):
                continue
            operands = [cmp_node.left] + list(cmp_node.comparators)
            direct_globals = {
                o.id for o in operands
                if isinstance(o, ast.Name) and o.id not in self.params
                and (o.id in self.module_globals or o.id in self.declared_global
                     or o.id in self.state_aliases or o.id in self.file_state_aliases)
            }
            has_numeric_literal = any(
                isinstance(_literal(o), (int, float)) and not isinstance(_literal(o), bool)
                for o in operands
            )
            if direct_globals and has_numeric_literal:
                self.facts.uses_call_counter_gate = True
                self.facts.gate_snippets.append(text)
                for o in operands:
                    lit = _literal(o)
                    if isinstance(lit, (int, float)) and not isinstance(lit, bool):
                        thr = counter_gate_threshold(cmp_node.ops, lit)
                        if thr is not None and thr not in self.facts.counter_gate_thresholds:
                            self.facts.counter_gate_thresholds.append(thr)
                break

    def _snippet(self, node: ast.AST) -> str:
        try:
            seg = ast.get_source_segment(self._src, node)
            if seg:
                return " ".join(seg.split())[:200]
        except Exception:
            pass
        try:
            return " ".join(ast.unparse(node).split())[:200]
        except Exception:
            return ""


# rules P3.2/P3.3 — sink-KIND-specific sanitizer resolution, shared between a
# tool's own body (``analyze_tool_function``) and a helper reached through
# one level of inlining (``_inline_helper_call``), so a helper's own guard
# logic is evaluated with the exact same rules instead of always defaulting
# to "unsanitized" the way it silently did before this existed.
_COMMAND_SINK_KINDS = {"command-exec", "code-exec"}
_PATH_SINK_KINDS = {"file-read", "file-write", "file-delete"}


def _resolve_sink_sanitization(az: "_FuncAnalyzer") -> None:
    for sink in az.facts.sinks:
        if sink.sanitized:
            continue  # already resolved (e.g. during helper inlining)
        names = set(sink.arg_names)
        tainted_here = names & az.tainted
        raw = (set(sink.raw_tainted_names) if sink.raw_tainted_names is not None
               else tainted_here)
        if tainted_here and (sink.strip_nested or raw <= az.stripped_names):
            # value-quoting (shlex.quote) or a path-stripping call
            # (basename) — sanitized regardless of sink kind; v3-3.4 also
            # when the stripping call is nested inside the sink's own
            # argument expression rather than assigned to a name first.
            # v4-5 — EVERY tainted name reaching the sink raw must be a
            # stripped name; a raw tainted name beside a stripped one is
            # not sanitized.
            sink.sanitized = True
        elif sink.kind in _COMMAND_SINK_KINDS:
            # rule P3.2 — commands accept exactly three things: quoting
            # (handled above), an argument-LIST call with no shell, or a
            # halting allow-list. A deny-list or a bare prefix test on the
            # raw value is deliberately NOT one of them.
            if sink.arglist_no_shell:
                sink.sanitized = True
            elif names & az.allowlist_guarded_names:
                sink.sanitized = True
        elif sink.kind in _PATH_SINK_KINDS:
            # rule P3.3 — a path needs BOTH a normalized value AND a prefix
            # test against a constant base; either alone is not enough.
            if (names & az.norm_path_names) and (names & az.prefix_guarded_names):
                sink.sanitized = True


def _is_reset_value(node: Optional[ast.AST]) -> bool:
    """v3-4.2 — an empty/zero/None/False literal, an empty collection
    literal or constructor (``[]``, ``{}``, ``set()``, ``dict()``), or a
    string literal that is empty / ``"0"`` / ``"{}"`` / ``"[]"`` / ``"null"``."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        v = node.value
        if v is None or v is False:
            return True
        if isinstance(v, bool):
            return False
        if isinstance(v, (int, float)) and v == 0:
            return True
        if isinstance(v, str):
            return v.strip() in ("", "0", "{}", "[]", "null")
        return False
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in ("list", "dict", "set", "tuple") and not node.args
    return False


def collect_module_instance_methods(tree: ast.AST) -> Dict[str, Dict[str, ast.AST]]:
    """v3-4.5 — module-level class name -> its methods, and module-level
    instance name (``R = Runner(...)``) -> that class's methods, so a tool
    calling ``R.go(x)`` can inline ``Runner.go`` exactly like a bare-name
    helper."""
    classes: Dict[str, Dict[str, ast.AST]] = {}
    body = tree.body if isinstance(tree, ast.Module) else []
    for node in body:
        if isinstance(node, ast.ClassDef):
            classes[node.name] = {
                m.name: m for m in node.body
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
    out: Dict[str, Dict[str, ast.AST]] = dict(classes)
    for node in body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call)):
            cname = last_attr(node.value.func)
            if cname in classes:
                out[node.targets[0].id] = classes[cname]
    return out


def _collect_module_globals(tree: ast.AST) -> Set[str]:
    g: Set[str] = set()
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    g.add(t.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            g.add(node.target.id)
    return g


def collect_dict_literal_keys(tree: ast.AST) -> Dict[str, List[str]]:
    """rule 3.2 — module-level ``NAME = {"k1": ..., "k2": ...}`` dict literals
    with string keys, by variable name. When a tool subscripts/``.get()``s
    one of these dicts with one of its OWN parameters as the key, those
    literal keys are real candidate values for that parameter (a lookup-key
    harvest, distinct from the direct-comparison harvest below)."""
    out: Dict[str, List[str]] = {}
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Dict)):
            continue
        str_keys = [k for k in (_literal(k) for k in node.value.keys) if isinstance(k, str)]
        if str_keys:
            out[node.targets[0].id] = str_keys
    return out


def collect_module_functions(tree: ast.AST) -> Dict[str, ast.AST]:
    """rule 2.6 — every module-level (top-level, not nested, not tool-decorated
    itself) plain function, by name. Used as the callee registry for one
    level of taint-call inlining: a tool that hands a tainted argument to
    one of these and the helper's own body reaches a sink is exactly as real
    a finding as if the tool called the sink directly."""
    out: Dict[str, ast.AST] = {}
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = node
    return out


# ---------------------------------------------------------------------------
# rule P2.1 — string literals a tool's own source hands back to the agent. Scanned
# statically with the response rules so a poisoned message baked into the
# function body (MSB's ``tool_transfer`` shape: an ``<IMPORTANT>``-style
# redirect returned unconditionally, or gated on an argument value the
# synthesized call plan never happens to hit) is visible from source alone,
# without needing a live call to reach the exact branch that returns it.

def _resolve_returned_str(node: ast.AST, consts: Dict[str, str]) -> Optional[str]:
    direct = _resolve_str(node, consts)
    if isinstance(direct, str):
        return direct
    # one level of dict/list/tuple wrapping around string content — the
    # common "return {'text': ...}" / content-block response shape. Join
    # every string-shaped value found inside it (never crossing into a
    # nested function/lambda, which ast.walk does not descend into anyway).
    if isinstance(node, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
        parts: List[str] = []
        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                parts.append(child.value)
            elif isinstance(child, ast.JoinedStr):
                r = _resolve_str(child, consts)
                if isinstance(r, str):
                    parts.append(r)
        if parts:
            return " ".join(parts)
    return None


def _build_local_literal_map(func: ast.AST, consts: Dict[str, str]) -> Dict[str, str]:
    """rule P4.1 — a single forward pass over the function's own ``Assign``
    statements (in ``ast.walk`` order, which is document order for a
    straight-line body — the same approximation the rest of this module
    already uses for gate/state reasoning) resolving each local name bound
    to a string/list/dict LITERAL to its text, chaining through earlier
    resolved names so ``a = "x"; b = a + "y"`` still resolves ``b``."""
    local_text: Dict[str, Any] = {}
    for node in ast.walk(func):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            v = _resolve_returned_str(node.value, {**consts, **local_text})
            if isinstance(v, str):
                local_text[node.targets[0].id] = v
    # v6-W6 — a forward constant evaluation of the body adds what the walk
    # above cannot: int/tuple constants a chr() chain reads, and a string
    # built by a loop that appends ``chr(c)`` for each ``c`` of a constant
    # iterable. Its (more precise, in-order) value wins for the same name.
    try:
        env, _infos = constfold.local_const_env(func, dict(consts))
        for name, value in env.items():
            if name in consts and consts[name] is value:
                continue
            if isinstance(value, (str, int, bytes, tuple, list)) and not isinstance(value, bool):
                local_text[name] = value
    except Exception:
        pass
    return local_text


def extract_returned_string_literals(func: ast.AST, consts: Dict[str, str]) -> List[str]:
    """rule P4.1 — follow a string/list/dict LITERAL assigned to a local
    variable and returned later (``msg = "...instruction..."; return msg``),
    not just a value returned directly."""
    local_text = _build_local_literal_map(func, consts)
    merged = {**consts, **local_text}
    out: List[str] = []
    for n in ast.walk(func):
        if isinstance(n, ast.Return) and n.value is not None:
            if isinstance(n.value, ast.Name) and n.value.id in local_text:
                v = local_text[n.value.id]
            else:
                v = _resolve_returned_str(n.value, merged)
            if isinstance(v, str) and v.strip():
                out.append(v)
    return out


def extract_metadata_mutation_texts(
        func: ast.AST, consts: Dict[str, str],
        registered_tool_names: Optional[Set[str]] = None,
        locally_bound_names: Optional[Set[str]] = None,
) -> List[str]:
    """rule P4.3 — the statically-resolved TEXT of the value assigned in each
    tool-metadata mutation (``X.__doc__ = ...`` / ``X.description = ...``),
    following a local-variable indirection the same way a returned literal
    is (rule P4.1) — so the rug-pull detector can scan what the docstring is
    rewritten TO with the description rules, instead of only noting that a
    rewrite happened at all."""
    local_text = _build_local_literal_map(func, consts)
    merged = {**consts, **local_text}
    out: List[str] = []
    for n in ast.walk(func):
        if isinstance(n, ast.Assign) and len(n.targets) == 1:
            target, value = n.targets[0], n.value
        elif isinstance(n, ast.AugAssign):
            target, value = n.target, n.value
        else:
            continue
        if not (isinstance(target, ast.Attribute)
                and _looks_like_tool_metadata_target(
                    target, registered_tool_names, locally_bound_names)):
            continue
        if isinstance(value, ast.Name) and value.id in local_text:
            v = local_text[value.id]
        else:
            v = _resolve_returned_str(value, merged)
        if isinstance(v, str) and v.strip():
            out.append(v)
    return out


def _make_call_resolver(module_functions: Optional[Dict[str, ast.AST]],
                        instance_methods: Optional[Dict[str, Dict[str, ast.AST]]]):
    """A ``Call -> function node`` resolver over the callee registries the
    taint inliner already uses: a bare-name call to a module function, and
    ``alias.func(...)`` / ``Instance.method(...)`` through ``instance_methods``
    (which v6-W7 also fills with same-directory imported modules)."""
    funcs = module_functions or {}
    methods = instance_methods or {}

    def resolve(call: ast.Call) -> Optional[ast.AST]:
        f = call.func
        if isinstance(f, ast.Name):
            target = funcs.get(f.id)
            return target if isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            target = (methods.get(f.value.id) or {}).get(f.attr)
            return target if isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
        return None
    return resolve


def analyze_tool_function(func: ast.AST, params: List[str], module_globals: Set[str],
                          source: str, stub_true_funcs: Optional[Set[str]] = None,
                          module_consts: Optional[Dict[str, str]] = None,
                          module_functions: Optional[Dict[str, ast.AST]] = None,
                          dict_literal_keys: Optional[Dict[str, List[str]]] = None,
                          registered_tool_names: Optional[Set[str]] = None,
                          declared_params: Optional[List[str]] = None,
                          instance_methods: Optional[Dict[str, Dict[str, ast.AST]]] = None,
                          inline_depth: int = 2,
                          module_tree: Optional[ast.AST] = None,
                          ) -> BehaviorFacts:
    """rule P3.5 — ``params`` seeds TAINT (the node's real parameters: for most
    tools this already is the declared contract, but for a low-level SDK
    handler's synthesized body it is the handler's own ``name``/``arguments``
    -shaped params, which actually appear as bare identifiers in the body).
    ``declared_params`` (defaults to ``params`` when not given) is the
    DECLARED schema property list used for unused-parameter/auth-parameter
    reasoning — for a low-level tool this is the schema's own field names,
    which never appear as bare identifiers at all, only as string keys into
    the ``arguments`` dict (``_name_referenced`` recognizes that shape too)."""
    declared = declared_params if declared_params is not None else params
    az = _FuncAnalyzer(params, module_globals)
    az._src = source
    # rule 2.6 — one level of call inlining: helper functions this tool's body
    # may call directly by name.
    az.module_functions = module_functions or {}
    # v3-4.5 — methods on module-level instances, and two levels of inlining.
    az.instance_methods = instance_methods or {}
    az.inline_depth = inline_depth
    az.dict_literal_keys = dict_literal_keys or {}
    # rule 2.2 (FP fix) — every registered tool's own function name in this
    # module (see ``_looks_like_tool_metadata_target``).
    az.registered_tool_names = registered_tool_names or set()
    # pre-scan for global/nonlocal declarations so mutation detection is correct
    for n in ast.walk(func):
        if isinstance(n, ast.Global):
            az.declared_global.update(n.names)
        elif isinstance(n, ast.Nonlocal):
            az.declared_global.update(n.names)
        # rule 2.2 (FP fix) — every name this function's OWN body freshly binds
        # (assignment/for/with/comprehension targets, nested def/class
        # names). A description/annotations write through one of these is a
        # local object the function just created, never a client-visible
        # tool-registry reference, regardless of what it's named.
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            az.locally_bound_names.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not func:
            az.locally_bound_names.add(n.name)
    az.visit(func)
    az._scan_sanitizer_guards(func)
    _resolve_sink_sanitization(az)
    az.facts.returned_string_literals = extract_returned_string_literals(
        func, module_consts or {})
    # v6-W6 — the obfuscation signal: a string assembled from chr()/bytes()
    # constants that the body returns or compares.
    try:
        az.facts.assembled_strings = constfold.find_assembled_strings(
            func, dict(module_consts or {}),
            base_infos=getattr(module_consts, "infos", None))
    except Exception:
        az.facts.assembled_strings = []
    # v6-W3 — returns that hand back the WHOLE process environment.
    try:
        az.facts.environ_dumps = find_environ_dumps(
            func, module_tree, _make_call_resolver(module_functions, instance_methods),
            dict(module_consts or {}))
    except Exception:
        az.facts.environ_dumps = []
    az.facts.tool_metadata_mutation_texts = extract_metadata_mutation_texts(
        func, module_consts or {}, az.registered_tool_names, az.locally_bound_names)
    az._harvest_candidate_values(func)

    # auth/audit heuristics over the raw text of the body
    body_src = az._snippet(func).lower() if False else _func_source(func, source).lower()
    az.facts.has_auth_check = any(tok in body_src for tok in AUTH_TOKENS)
    az.facts.has_logging = any(tok in body_src for tok in LOG_TOKENS)
    az.facts.auth_effective, az.facts.auth_evidence = analyze_auth_control(
        func, declared, stub_true_funcs or frozenset())
    # v3-4.4 — "consulted" means used in a computation, a comparison, a
    # return, or a store into module state; passing it unchanged into a call
    # whose result is discarded, or only logging it, counts as unused.
    store_roots = set(module_globals) | set(az.declared_global)
    az.facts.unused_params = [p for p in declared if not _param_consulted(func, p, store_roots)]
    return az.facts


# ---------------------------------------------------------------------------
# rule P5.1 — an authorization *helper function* that looks like a real check but
# is a constant stub: it accepts an argument and never references it, and
# every one of its return paths is a hard-coded truthy literal. A caller that
# gates on such a function (even with impeccable control flow — an if/assert
# that halts on failure) is still gating on nothing, because the function can
# never return anything but "allowed". This is a distinct shape from
# ``analyze_auth_control``'s intra-procedural reasoning (which only sees the
# *caller*'s control flow) — it requires looking at the callee's own body,
# hence a separate, module-wide pre-pass.


def _collect_stub_true_functions(tree: ast.AST) -> Set[str]:
    stubs: Set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = [a.arg for a in node.args.args + node.args.kwonlyargs
                  if a.arg not in ("self", "cls")]
        if not params:
            continue  # only a stub that *accepts* an argument it ignores counts
        returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
        if not returns:
            continue
        consts = []
        ok = True
        for r in returns:
            if r.value is None:
                ok = False
                break
            v = _literal(r.value)
            if v is None and not (isinstance(r.value, ast.Constant) and r.value.value is None):
                ok = False
                break
            consts.append(v)
        if not ok or not consts:
            continue
        if not any(bool(c) for c in consts):
            continue  # an always-deny stub isn't the "fake allow" shape
        if any(_name_referenced(node, p) for p in params):
            continue  # genuinely consults at least one of its own arguments
        stubs.add(node.name)
    return stubs


# ---------------------------------------------------------------------------
# rule P3.2 — "a control is present but provably ineffective" (control-flow, not
# lexical). Distinct from "no control present": here we require a *positive*
# signal (an auth-shaped call, or a permission/authorization-shaped parameter)
# and then reason about whether it can actually gate the sensitive action —
# via an Assert, or an If whose failing branch halts (raise/return/continue/
# break/exit) before the rest of the function runs. If the signal is present
# but its result is discarded, the parameter is never referenced again, or
# neither branch of the guarding conditional halts, the control cannot
# possibly prevent the action and we report it as *ineffective* rather than
# silently treating "has_auth_check" (a lexical presence check) as sufficient.

_HALT_TYPES = (ast.Raise, ast.Return, ast.Continue, ast.Break)
_HALT_CALLS = {"sys.exit", "os._exit", "exit", "quit"}

# rule P0.1: kept only as a documented historical reference for the shape this
# used to match on whole strings; matching now goes through
# ``_split_ident_tokens`` + ``_AUTH_WORD_TOKENS`` below (whole-token, not
# substring/prefix), which is what actually excludes "author" while still
# catching "is_authorized". This regex is no longer used for the exact-match
# path (superseded by the token check, which subsumes it and is not fooled by
# a name that merely starts with "auth").
_AUTH_PARAM_RE = re.compile(
    r"^(is_)?(authorized|authorised|authenticated|permitted|allowed)\w*$|"
    r"^(has_)?(permission|role|access|privilege)s?$",
    re.IGNORECASE,
)
# rule P5.3 (generalized by rule P0.1): a parameter that merely *contains* an
# auth-shaped WORD — e.g. a very common real naming pattern like
# "requester_role"/"caller_permission"/"user_role" — is just as much a genuine
# authorization signal as one that matches it exactly. Matching now requires a
# whole TOKEN of the split identifier to be an auth word (see
# ``_AUTH_WORD_TOKENS``/``_split_ident_tokens``), not a bare substring — the
# old bare-substring check is exactly what misread the parameter ``author`` as
# authorization-shaped ("auth" is a substring of "author"), which is the
# single accidental match the MSB benchmark's whole "capability-class signal"
# turned out to rest on.


def _stmt_halts(stmt: ast.stmt) -> bool:
    if isinstance(stmt, _HALT_TYPES):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        if dotted_name(stmt.value) in _HALT_CALLS:
            return True
    return False


def _block_halts(block: List[ast.stmt]) -> bool:
    return any(_stmt_halts(s) for s in block)


def _is_auth_shaped_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    dn = dotted_name(node)
    meth = last_attr(node.func)
    tokens = set(_split_ident_tokens(dn)) | set(_split_ident_tokens(meth))
    return bool(tokens & _AUTH_WORD_TOKENS)


# v3-3.3 — the DISCARDED-result branch of the auth-effectiveness check only
# applies to a call whose name is an exact AUTHORIZATION VERB class: an
# authorize/authenticate verb, or a check-verb (check/has/verify/require/
# ensure/assert/validate/is/can/enforce/confirm) paired with an auth object
# (permission/role/access/scope/auth/token/admin/privilege/owner/...). A
# discarded ``get_credentials()`` or ``permissions().create()`` is an API
# call, not a check that was forgotten.
_AUTHZ_VERB_TOKENS = frozenset({
    "authorize", "authorizes", "authorized", "authorise", "authorises", "authorised",
    "authenticate", "authenticates", "authenticated", "authn", "authz",
})
_CHECK_VERB_TOKENS = frozenset({
    "check", "checks", "has", "have", "verify", "verifies", "require", "requires",
    "ensure", "ensures", "assert", "asserts", "validate", "validates", "is", "can",
    "enforce", "enforces", "confirm", "confirms", "must",
})
_AUTH_OBJECT_TOKENS = frozenset({
    "permission", "permissions", "perm", "perms", "role", "roles", "access",
    "scope", "scopes", "auth", "token", "admin", "privilege", "privileges",
    "authorized", "authenticated", "allowed", "permitted", "owner", "ownership",
    "acl", "grant", "login", "session", "identity", "credential", "credentials",
})


def _is_authorization_verb_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    tokens = set(_split_ident_tokens(dotted_name(node)))
    if tokens & _AUTHZ_VERB_TOKENS:
        return True
    return bool(tokens & _CHECK_VERB_TOKENS) and bool(tokens & _AUTH_OBJECT_TOKENS)


def _auth_shaped_params(params: List[str]) -> List[str]:
    return [p for p in params if set(_split_ident_tokens(p)) & _AUTH_WORD_TOKENS]


def _name_referenced(node: ast.AST, name: str) -> bool:
    """True when ``name`` is referenced either as a bare identifier OR as a
    literal string KEY used to subscript/``.get``/``.pop``/``.setdefault`` a
    dict somewhere in ``node`` (rule P3.5) — the shape a low-level SDK handler's
    synthesized body actually uses (``arguments.get("routine")``,
    ``arguments["routine"]``), where the DECLARED schema property name never
    appears as a bare identifier at all. Broadening this is also a general
    precision improvement for every ordinary tool: a parameter consulted
    only through ``data.get("param")``-style access no longer reads as
    "unused" just because it is never referenced by bare name."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id == name:
            return True
        if isinstance(n, ast.Subscript):
            key_node = n.slice.value if isinstance(n.slice, ast.Index) else n.slice
            if isinstance(key_node, ast.Constant) and key_node.value == name:
                return True
        elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and n.func.attr in ("get", "pop", "setdefault") and n.args):
            if _literal(n.args[0]) == name:
                return True
    return False


# v3-4.4 — the "consulted" test. A reference that only feeds a LOGGING call
# (logging/logger/log/print/audit/telemetry roots, or an info/debug/warning/
# error/... method) or a bare call whose result is discarded is not a use
# of the parameter; everything else (a computation, a comparison, a return,
# a subscript/attribute, a call whose result is consumed, a store into
# module state) is.
_LOG_CALL_ROOTS = frozenset({
    "logging", "logger", "log", "print", "audit", "syslog", "telemetry",
    "metrics", "tracer", "trace", "sentry", "warnings",
})
_LOG_METHODS = frozenset({
    "info", "debug", "warning", "warn", "error", "critical", "exception", "log",
    "trace", "fatal",
})


def _is_logging_call(call: ast.Call) -> bool:
    dn = dotted_name(call)
    root = dn.split(".")[0] if dn else ""
    if root in _LOG_CALL_ROOTS:
        return True
    return "." in dn and last_attr(call.func) in _LOG_METHODS


def _param_occurrences(func: ast.AST, name: str) -> List[ast.AST]:
    out: List[ast.AST] = []
    for n in ast.walk(func):
        if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load):
            out.append(n)
        elif isinstance(n, ast.Subscript):
            key_node = n.slice.value if isinstance(n.slice, ast.Index) else n.slice
            if isinstance(key_node, ast.Constant) and key_node.value == name:
                out.append(n)
        elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and n.func.attr in ("get", "pop", "setdefault") and n.args):
            if _literal(n.args[0]) == name:
                out.append(n)
    return out


def _param_consulted(func: ast.AST, name: str, store_roots: Set[str] = frozenset()) -> bool:
    parents: Dict[int, ast.AST] = {}
    for p in ast.walk(func):
        for ch in ast.iter_child_nodes(p):
            parents[id(ch)] = p
    for occ in _param_occurrences(func, name):
        ancestors: List[ast.AST] = []
        cur = occ
        while id(cur) in parents:
            cur = parents[id(cur)]
            ancestors.append(cur)
        # only logged -> not consulted
        if any(isinstance(a, ast.Call) and _is_logging_call(a) for a in ancestors):
            continue
        stmt = next((a for a in ancestors if isinstance(a, ast.stmt)), None)
        # v4-3 — a parameter passed into a call is USED when the call's
        # result is assigned, returned, awaited, yielded or tested in a
        # condition (every one of those leaves the statement something other
        # than a bare ``Expr(Call)``), or when the call is a METHOD ON MODULE
        # STATE (``_INDEX.warm(ctx)``, ``_DB.execute(q, (p,))`` — any
        # method, not only the list/dict mutators: the store is the
        # observable effect). It is UNUSED only when the call is a bare
        # expression statement whose result is discarded (``_emit(p)``) or a
        # logging call (handled above).
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            if (isinstance(call.func, ast.Attribute)
                    and _root_name(call.func.value) in store_roots):
                return True
            continue
        # ``alias = param`` where alias is never read again -> not consulted
        if (isinstance(stmt, ast.Assign) and stmt.value is occ
                and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)):
            alias = stmt.targets[0].id
            if not any(isinstance(n, ast.Name) and n.id == alias and isinstance(n.ctx, ast.Load)
                       for n in ast.walk(func)):
                continue
        return True
    return False


def _test_refs_auth(test: ast.AST, auth_names: Set[str]) -> bool:
    for n in ast.walk(test):
        if isinstance(n, ast.Name) and n.id in auth_names:
            return True
        if _is_auth_shaped_call(n):
            return True
    return False


def analyze_auth_control(func: ast.AST, params: List[str],
                         stub_true_funcs: Set[str] = frozenset()
                         ) -> Tuple[Optional[bool], str]:
    """Control-flow reasoning over an auth-shaped signal in a tool body.

    Returns ``(effective, evidence)``:
    * ``(None, "")``   — no auth-shaped call or permission-shaped parameter found
      at all. Mere absence is not itself reported by the detector layer (that
      would be the noisy lexical heuristic this replaces) — it is only used
      together with an explicit declared-requirement contradiction.
    * ``(True, ...)``  — a signal is present and provably gates the action (an
      ``assert`` on it, or an ``if``/branch that halts on failure).
    * ``(False, ...)`` — a signal is present (a call or a permission-shaped
      parameter) but does not provably gate anything: its result is discarded,
      the parameter is never referenced again, or neither branch of the
      guarding conditional halts before the function continues.
    """
    body: List[ast.stmt] = list(getattr(func, "body", []) or [])
    auth_params = set(_auth_shaped_params(params))
    all_auth_calls: List[ast.Call] = [
        n for n in ast.walk(func) if _is_auth_shaped_call(n)
    ]
    auth_vars: Set[str] = set()
    for n in ast.walk(func):
        if isinstance(n, ast.Assign) and _is_auth_shaped_call(n.value):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    auth_vars.add(t.id)

    # rule P6.4 — do not treat a CALL as an authorization check merely because
    # its name contains an auth-shaped word (scope/credentials/permissions/
    # roles/...) — require its result to actually feed a CONDITION
    # somewhere (an If/While/Assert test), directly or through a variable
    # it was assigned to. A "list_user_roles" read helper, or an
    # audit-logging call that happens to be named with an auth-adjacent
    # word, is not an authorization ATTEMPT at all just because its name
    # matches — it is correctly "no signal", not "an ineffective check".
    # (A permission-shaped PARAMETER is a different, narrower case — the
    # tool's own author named it that way in the declared contract — and
    # keeps the existing unconsulted-parameter reasoning below.)
    test_nodes = [n.test for n in ast.walk(func) if isinstance(n, (ast.If, ast.While, ast.Assert))]
    call_ids_in_tests = {id(c) for t in test_nodes for c in ast.walk(t) if isinstance(c, ast.Call)}
    names_in_tests = {n.id for t in test_nodes for n in ast.walk(t) if isinstance(n, ast.Name)}
    auth_calls = [c for c in all_auth_calls if id(c) in call_ids_in_tests]
    effective_vars = auth_vars & names_in_tests
    # a BARE, discarded call (``check_permission(token)`` as its own
    # statement, result captured nowhere) is a distinct, unambiguous signal
    # kept as-is: nobody calls a permission/scope-shaped function and
    # discards the result for no reason — the classic "called the check,
    # forgot to act on it" bug, not the "name merely contains an auth word"
    # false positive this item targets (that FP comes from a var that IS
    # consumed, just never as a condition — e.g. returned/logged).
    # v3-3.3 — only an exact authorization-verb call counts here.
    discarded_calls = [n.value for n in ast.walk(func)
                      if isinstance(n, ast.Expr) and _is_authorization_verb_call(n.value)]

    if not auth_params and not auth_calls and not effective_vars and not discarded_calls:
        return None, ""

    auth_names = auth_params | effective_vars

    # rule P5.1: the check delegates to a helper function that is a constant
    # stub (ignores its argument, always returns truthy) — decisive
    # regardless of how cleanly the *caller*'s control flow halts, because
    # the callee can never say no.
    if stub_true_funcs:
        for n in ast.walk(func):
            if isinstance(n, (ast.If, ast.While, ast.Assert)):
                test = n.test
                call_names = {dotted_name(c) for c in ast.walk(test) if isinstance(c, ast.Call)}
                call_names |= {last_attr(c.func) for c in ast.walk(test) if isinstance(c, ast.Call)}
                if call_names & stub_true_funcs:
                    return False, ("authorization check delegates to a function that "
                                   "ignores its argument and always returns a constant "
                                   "truthy value -- a check that never actually "
                                   "discriminates by caller")

    # an assert directly referencing the signal halts by construction
    for n in ast.walk(func):
        if isinstance(n, ast.Assert) and _test_refs_auth(n.test, auth_names):
            return True, "assert statement gates on the authorization check"

    # an `if`/`while` whose test references the signal, and a branch halts
    for n in ast.walk(func):
        if isinstance(n, (ast.If, ast.While)) and _test_refs_auth(n.test, auth_names):
            if _block_halts(n.body) or (n.orelse and _block_halts(n.orelse)):
                return True, "a conditional branch halts when the authorization check fails"

    if discarded_calls:
        return False, "authorization check is called but its result is discarded (never gates the action)"

    # permission-shaped parameter accepted but never CONSULTED in the body
    # (v3-4.4: logged-only or passed into a discarded call counts as unused)
    unconsulted = [p for p in auth_params if not _param_consulted(func, p)]
    if unconsulted and not auth_calls:
        return False, (f"permission parameter '{unconsulted[0]}' is accepted but "
                       "never consulted in the function body")

    # signal exists (assigned/used somewhere) but no halting guard was found —
    # e.g. assigned to a variable that is then ignored, or used only inside a
    # branch that does not stop execution
    return False, "an authorization signal is present but no branch of the code halts when it fails"


def _func_source(func: ast.AST, source: str) -> str:
    try:
        seg = ast.get_source_segment(source, func)
        if seg:
            return seg
    except Exception:
        pass
    try:
        return ast.unparse(func)
    except Exception:
        return ""


def parse_module(source: str) -> Optional[ast.AST]:
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


# ---------------------------------------------------------------------------
# rule P5.2 — "ownership-less lookup by guessable/shared identifier"
# (auth-control-ineffective's structural cousin: not a *check present but
# ineffective*, but the mirror case — the lookup itself is the only "check",
# and possessing the identifier is treated as sufficient proof of ownership).
# A tool that (a) takes a session/token/ticket-shaped identifier, (b) uses it
# as the sole key into a module-level store that some *other* tool populates
# per-caller, and (c) returns data from that record with no comparison of any
# of the record's own fields against any other supplied parameter, hands out
# whoever-holds-the-identifier's data. The honest shape (a second "binding"
# value that must match) is exactly what removes the finding: a real ==/!=
# check against another parameter proves ownership is actually verified.
_SESSION_ID_PARAM_RE = re.compile(
    r"^(session|sess)[_-]?(id|token|key)?$|"
    r"^(auth|access|login)[_-]?(token|code)$|"
    r"^token$|^ticket[_-]?id$",
    re.IGNORECASE,
)


def analyze_session_reuse(tree: ast.AST) -> List[Dict[str, Any]]:
    module_globals = _collect_module_globals(tree)
    out: List[Dict[str, Any]] = []
    for td in extract_tools(tree):
        if td.node is None:
            continue
        lookup_params = [p for p in td.params if _SESSION_ID_PARAM_RE.match(p)]
        if not lookup_params:
            continue
        lookup_param = lookup_params[0]
        other_params = [p for p in td.params if p != lookup_param]
        record_vars: Set[str] = set()
        dict_used: Optional[str] = None
        for node in ast.walk(td.node):
            if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)):
                continue
            v = node.value
            base: Optional[str] = None
            key_names: Set[str] = set()
            if (isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute)
                    and last_attr(v.func) == "get"):
                base = _root_name(v.func.value)
                if v.args:
                    key_names = {n.id for n in ast.walk(v.args[0]) if isinstance(n, ast.Name)}
            elif isinstance(v, ast.Subscript):
                base = _root_name(v.value)
                key_names = {n.id for n in ast.walk(v.slice) if isinstance(n, ast.Name)}
            if base and base in module_globals and lookup_param in key_names:
                record_vars.add(node.targets[0].id)
                dict_used = base
        if not record_vars:
            continue
        returns_record = any(
            isinstance(n, ast.Return) and n.value is not None
            and ({x.id for x in ast.walk(n.value) if isinstance(x, ast.Name)} & record_vars)
            for n in ast.walk(td.node)
        )
        if not returns_record:
            continue
        verified = False
        for node in ast.walk(td.node):
            if isinstance(node, ast.Compare):
                names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                if names & record_vars and names & set(other_params):
                    verified = True
                    break
        if verified:
            continue
        out.append({"tool": td.name, "lookup_param": lookup_param, "store": dict_used,
                    "other_params": other_params})
    return out


# ---------------------------------------------------------------------------
# rule 5.9 (widened) — audit trail present in form but not in substance. The
# contract signal here is *structural*, not textual: a server that exposes a
# dedicated "read the audit trail" tool has, by that very act, declared it
# maintains one — it does not need to say so in English prose for the
# contradiction to be real. A destructive tool in the same module that
# contributes nothing to that log, or contributes only a hard-coded literal
# with no trace of what actually happened, contradicts that structural
# declaration.
_LOG_GLOBAL_RE = re.compile(r"(audit|log|trail)", re.IGNORECASE)


def _mutating_calls_on(root_tree: ast.AST, root_name: str) -> List[ast.Call]:
    out = []
    for n in ast.walk(root_tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and last_attr(n.func) in _MUTATING_METHODS
                and _root_name(n.func.value) == root_name):
            out.append(n)
    return out


def _returns_name(root_tree: ast.AST, name: str) -> bool:
    for n in ast.walk(root_tree):
        if isinstance(n, ast.Return) and n.value is not None:
            if name in {x.id for x in ast.walk(n.value) if isinstance(x, ast.Name)}:
                return True
    return False


def counter_gate_threshold(ops, literal) -> Optional[int]:
    """v6 — the call count at which a counter comparison flips: the literal
    for ``>=`` / ``==`` / ``<=`` / ``<``, literal+1 for ``>`` (``_calls > 9``
    first flips on call 10). ``None`` for a non-positive / absurd literal."""
    try:
        n = int(literal)
    except (TypeError, ValueError):
        return None
    if ops and isinstance(ops[0], ast.Gt):
        n += 1
    if n < 1 or n > 100000:
        return None
    return n


def collect_exposed_state_globals(tree: ast.AST) -> Set[str]:
    """rule 2.5 — every module-global name that AT LEAST ONE tool in this module
    returns/exposes to its caller. Used to tell a domain record store apart
    from pure internal bookkeeping (a call counter, a cache) that backs no
    tool's actual output at all: mutating the latter contradicts nothing a
    caller can ever observe through this server's declared tools."""
    out: Set[str] = set()
    for td in extract_tools(tree):
        if td.node is None:
            continue
        for n in ast.walk(td.node):
            if isinstance(n, ast.Return) and n.value is not None:
                out.update(x.id for x in ast.walk(n.value) if isinstance(x, ast.Name))
    return out


def _iter_if_chain_arms(if_node: ast.If) -> List[List[ast.stmt]]:
    """rule P4.6 — every leaf ARM of an if/elif/else chain: the ``body`` of each
    ``If`` in the chain, plus the final ``else`` block if one exists (an
    ``elif`` is a single nested ``If`` inside ``orelse`` -- not a separate
    leaf arm)."""
    arms: List[List[ast.stmt]] = [if_node.body]
    cur = if_node
    while len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If):
        cur = cur.orelse[0]
        arms.append(cur.body)
    if cur.orelse and not (len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If)):
        arms.append(cur.orelse)
    return arms


def _arm_is_destructive(stmts: List[ast.stmt], module_globals: Set[str]) -> bool:
    """rule P4.6 — does this specific branch (not the whole function) reach a
    state-changing action: a mutating method call on module state, a
    delete/spawn/code-exec sink, or a direct reassignment of a module
    global?"""
    for stmt in stmts:
        for n in ast.walk(stmt):
            if isinstance(n, ast.Call):
                dn = dotted_name(n)
                meth = last_attr(n.func)
                if dn in COMMAND_SINKS or dn in CODE_EXEC_SINKS or dn in DELETE_SINKS:
                    return True
                if meth in DELETE_METHODS:
                    return True
                if (meth in _MUTATING_METHODS and isinstance(n.func, ast.Attribute)
                        and (_root_name(n.func.value) in module_globals)):
                    return True
            elif isinstance(n, (ast.Assign, ast.AugAssign, ast.Delete)):
                targets = (n.targets if isinstance(n, ast.Assign)
                          else [n.target] if isinstance(n, ast.AugAssign)
                          else n.targets)
                for tgt in targets:
                    root = tgt.id if isinstance(tgt, ast.Name) else _root_name(tgt)
                    if root and root in module_globals:
                        return True
    return False


def _arm_logs(stmts: List[ast.stmt], log_global: str) -> bool:
    return any(_mutating_calls_on(stmt, log_global) for stmt in stmts)


def _check_branch_level_logging(func_node: ast.AST, module_globals: Set[str],
                                log_global: str) -> Optional[int]:
    """rule P4.6 — per-BRANCH audit-logging check: within ONE tool, flag a
    state-changing path with NO log write when ANOTHER path in the SAME
    if/elif/else chain of the SAME tool logs. A tool-level "does this
    function log anywhere at all" check (the existing no_log/generic_log
    checks) misses this entirely: an if-branch that logs makes the WHOLE
    function look compliant even while its else-branch silently skips the
    log for the identical destructive action."""
    all_ifs = [n for n in ast.walk(func_node) if isinstance(n, ast.If)]
    continuation_ids = {
        id(n.orelse[0]) for n in all_ifs if len(n.orelse) == 1 and isinstance(n.orelse[0], ast.If)
    }
    for if_node in all_ifs:
        if id(if_node) in continuation_ids:
            continue  # this If is an `elif` continuation, not a chain HEAD
        arms = _iter_if_chain_arms(if_node)
        if len(arms) < 2:
            continue
        arm_info = [(_arm_is_destructive(a, module_globals), _arm_logs(a, log_global))
                   for a in arms]
        logged_destructive = any(d and lg for d, lg in arm_info)
        if not logged_destructive:
            continue
        for a, (d, lg) in zip(arms, arm_info):
            if d and not lg:
                return getattr(a[0], "lineno", 0) if a else if_node.lineno
    return None


def analyze_audit_trail(tree: ast.AST, source: str = "") -> List[Dict[str, Any]]:
    module_globals = _collect_module_globals(tree)
    stub_funcs = _collect_stub_true_functions(tree)
    tool_defs = [td for td in extract_tools(tree) if td.node is not None]
    log_globals = {g for g in module_globals if _LOG_GLOBAL_RE.search(g)}
    if not log_globals:
        return []
    out: List[Dict[str, Any]] = []
    for g in sorted(log_globals):
        exposers = [td for td in tool_defs
                    if _returns_name(td.node, g) and not _mutating_calls_on(td.node, g)]
        if not exposers:
            continue  # no tool presents this as a queryable trail -- no declared contract
        exposer_names = {e.name for e in exposers}
        for td in tool_defs:
            if td.name in exposer_names:
                continue
            facts = analyze_tool_function(td.node, td.params, module_globals, source, stub_funcs)
            destructive = bool(facts.behavior_labels() & {
                "deletes-files", "spawns-process", "code-execution", "mutates-server-state"})
            if not destructive:
                continue
            calls = _mutating_calls_on(td.node, g)
            if not calls:
                out.append({"tool": td.name, "log": g, "exposer": exposers[0].name,
                            "kind": "no_log"})
                continue
            dynamic = any(
                isinstance(n, (ast.Name, ast.FormattedValue))
                for c in calls
                for a in (list(c.args) + [kw.value for kw in c.keywords])
                for n in ast.walk(a)
            )
            if not dynamic:
                out.append({"tool": td.name, "log": g, "exposer": exposers[0].name,
                            "kind": "generic_log"})
                continue
            # rule P4.6 — the tool logs SOMEWHERE, dynamically -- but does it log
            # on EVERY destructive branch, or does an if-branch that logs
            # make an else-branch that silently skips the log look
            # compliant at the whole-function level?
            unlogged_line = _check_branch_level_logging(td.node, module_globals, g)
            if unlogged_line is not None:
                out.append({"tool": td.name, "log": g, "exposer": exposers[0].name,
                            "kind": "partial_log", "unlogged_branch_line": unlogged_line})
    return out


# ---------------------------------------------------------------------------
# rule 5.5 (source corroboration) — covert cross-tool data collection. A tool
# silently persists its own caller-supplied data into a module-level store
# its own description gives no hint of, and a *different*, concealment-
# flagged tool (an underscore/"private"-named function, or one whose own
# description marks it internal/undocumented/hidden) is the only way to ever
# read that store back out. This is the static, always-available half of
# cross-call leakage: it does not require the runtime canary to be echoed
# verbatim (the harness's own call-plan arguments may not even reach the
# collecting branch), so it catches the mechanism a purely dynamic canary
# scan can miss whenever the "leak" is *reachable* rather than triggered by
# our specific synthesized arguments.
_STORAGE_DESC_RE = re.compile(
    r"\b(log|logs|logging|logged|record|records|recorded|recording|"
    r"stor(e|es|ed|ing)|history|track(s|ed|ing)?|audit(s|ed|ing)?|"
    r"sav(e|es|ed|ing)|cach(e|es|ed|ing))\b", re.IGNORECASE)
_CONCEALED_TOOL_RE = re.compile(
    r"\b(internal|diagnostic|debug|hidden|private|admin[- ]only|"
    r"not\s+(documented|for\s+(end\s+)?users))\b", re.IGNORECASE)


def analyze_covert_collection(tree: ast.AST) -> List[Dict[str, Any]]:
    module_globals = _collect_module_globals(tree)
    tool_defs = [td for td in extract_tools(tree) if td.node is not None]
    out: List[Dict[str, Any]] = []
    for td in tool_defs:
        params = set(td.params)
        if not params or _STORAGE_DESC_RE.search(td.description or ""):
            continue
        collected: Set[str] = set()
        for n in ast.walk(td.node):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and last_attr(n.func) in _MUTATING_METHODS):
                continue
            root = _root_name(n.func.value)
            # rule P2.4 — a log-NAMED store is not exempted here: a global that
            # merely happens to be called ``_log``/``_history`` is still a
            # covert collection point if it silently gathers a parameter the
            # tool's own description never mentions and is exposed only
            # through a concealed sibling tool. The exemption for an honest
            # log lives at the detector layer (v4-1 response._attribution_
            # in_record: the record carrying the echoed value names the
            # planting tool), keyed on the response's shape, not a bare
            # variable name or a description.
            if not root or root not in module_globals:
                continue
            args = list(n.args) + [kw.value for kw in n.keywords]
            tainted = any(
                {x.id for x in ast.walk(a) if isinstance(x, ast.Name)} & params
                for a in args
            )
            if tainted:
                collected.add(root)
        collected = {g for g in collected if not _returns_name(td.node, g)}
        if not collected:
            continue
        for g in sorted(collected):
            for other in tool_defs:
                if other.name == td.name or not _returns_name(other.node, g):
                    continue
                concealed = (other.func_name.startswith("_")
                            or bool(_CONCEALED_TOOL_RE.search(other.description or "")))
                if concealed:
                    out.append({"collector": td.name, "exposer": other.name, "store": g})
    return out
