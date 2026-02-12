"""Server pinning (identity + tool-list hash across proxy runs).

The proxy fronts one downstream server per invocation, launched repeatedly
over time from the same client config. A server whose declared handshake
identity or live tool-name set silently changes between one proxy session
and the next — or that shares its declared name with a DIFFERENT configured
target entry — is exactly the shadow-server/impersonation shape
``detectors/identity.py`` cannot see on its own: it only ever looks at one
server, in one session, in isolation. This module gives the proxy frontend
durable state across sessions: a hash of the handshake identity plus the
live tool-name list, persisted to a small JSON store, checked and updated
on every startup tool listing.

Purely structural and fully deterministic — no vocabulary, no payload matching,
just "does this configured target's declared identity/tool-set match what
we pinned last time, and does any OTHER configured target already claim the
SAME declared name?".
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional

from .context import ScanContext
from .detectors._util import mk
from .models import Finding

_DEFAULT_STORE = os.environ.get(
    "DEEPSLEUTH_PIN_STORE",
    os.path.join(os.path.expanduser("~"), ".deepsleuth", "server_pins.json"),
)


def _tools_hash(ctx: ScanContext) -> str:
    names = sorted(c.name for c in ctx.tools if c.name)
    return hashlib.sha1("|".join(names).encode("utf-8")).hexdigest()[:16]


def _tool_fingerprint(c) -> str:
    """A tool's declared DESCRIPTION and SCHEMA, not just its name:
    a rug-pull that keeps the same tool name but silently rewrites what it
    does or what arguments it takes must not hash identically to the
    unchanged tool."""
    blob = json.dumps(
        {"tool description": c.description or "",
         "schema": c.input_schema or {},
         "hints": c.hints or {}},
        sort_keys=True, default=str,
    )
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


def _tool_fingerprints(ctx: ScanContext) -> Dict[str, str]:
    return {c.name: _tool_fingerprint(c) for c in ctx.tools if c.name}


def _identity_name(ctx: ScanContext) -> Optional[str]:
    if ctx.server_info and isinstance(ctx.server_info, dict):
        n = ctx.server_info.get("name")
        if isinstance(n, str) and n.strip():
            return n.strip()
    return None


def _load(store_path: str) -> Dict[str, Any]:
    try:
        with open(store_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(store_path: str, data: Dict[str, Any]) -> None:
    try:
        d = os.path.dirname(store_path)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = store_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, store_path)
    except Exception:
        pass  # pinning is best-effort state; never let it crash the proxy


def check_and_update_pin(ctx: ScanContext, store_path: Optional[str] = None) -> List[Finding]:
    """Compare this target's CURRENT handshake identity + tool-name-set
    against its own last-seen pin, and against every OTHER pinned target's
    declared identity. Always (best-effort) updates the store afterward, so
    the very first run of a target only establishes its pin and never fires.
    """
    out: List[Finding] = []
    path = store_path or _DEFAULT_STORE
    pin_key = ctx.target.target_id or ctx.target.server_name or "default"
    name = _identity_name(ctx)
    thash = _tools_hash(ctx)
    fingerprints = _tool_fingerprints(ctx)
    if name is None and not ctx.tools:
        return out  # nothing observed yet (e.g. a static-only pass) — no pin to check

    store = _load(path)
    prior = store.get(pin_key)
    if isinstance(prior, dict):
        prior_name = prior.get("name")
        prior_hash = prior.get("tools_hash")
        prior_fps: Dict[str, str] = prior.get("tool_fingerprints") or {}
        changed_name = prior_name is not None and name is not None and prior_name != name
        # rule P6.8 — report WHAT changed (per-tool, description/schema included
        # via the fingerprint, not just the flat name-list hash), so an
        # ADDED tool (informational — the safest kind of change) is told
        # apart from a REMOVED or MODIFIED one (still high — exactly the
        # rug-pull shape: same name, quietly different description/schema).
        added = sorted(set(fingerprints) - set(prior_fps)) if prior_fps else []
        removed = sorted(set(prior_fps) - set(fingerprints)) if prior_fps else []
        modified = sorted(
            n for n in (set(fingerprints) & set(prior_fps))
            if prior_fps.get(n) != fingerprints.get(n)
        ) if prior_fps else []
        # backward-compatible fallback: no per-tool fingerprints were ever
        # pinned before (an older store, or a prior static-only pass with no
        # live tool list) — fall back to the coarse name-set hash so a real
        # change is still caught, just without per-tool detail.
        legacy_changed_tools = (not prior_fps and bool(prior_hash)
                                and prior_hash != thash)
        changed_tools = bool(added or removed or modified) or legacy_changed_tools
        if changed_name or changed_tools:
            what = []
            if changed_name:
                what.append("its declared handshake identity changed")
            if removed:
                what.append(f"tool(s) removed: {removed}")
            if modified:
                what.append(f"tool(s) with a changed description/schema: {modified}")
            if added:
                what.append(f"tool(s) added: {added}")
            if legacy_changed_tools:
                what.append("its live tool-name set changed")
            # rule P6.8 — an ADDED tool, with nothing removed/modified/identity-
            # shifted, is the safest kind of change (a server growing its
            # capability set is ordinary, not a rug-pull signature) —
            # informational rather than high.
            only_addition = (added and not removed and not modified
                             and not changed_name and not legacy_changed_tools)
            sev = "low" if only_addition else "high"
            conf = "low" if only_addition else "medium"
            out.append(mk(
                ctx, detector_id="server-pin-changed", category="tool-shadowing",
                evidence_location="server-identity", severity=sev,
                confidence=conf, detection_method="server-identity-pin",
                rationale=(
                    "This configured server's pinned identity/tool-list from a "
                    "prior session no longer matches what it presents now: "
                    + "; ".join(what) + ". A downstream server silently "
                    "swapped for a different one, or that rug-pulled its own "
                    "tool list/description/schema, between sessions is exactly "
                    "the shape a client that trusts a server purely by its "
                    "declared name cannot see on its own."
                    + (" Only new tool(s) were added — a growing capability "
                       "set is ordinary and reported as informational."
                       if only_addition else "")
                ),
                evidence={"pin_key": pin_key, "prior_name": prior_name,
                          "current_name": name, "prior_tools_hash": prior_hash,
                          "current_tools_hash": thash, "added": added,
                          "removed": removed, "modified": modified},
                source_kind="dynamic-runtime", tool_name=None,
            ))
    # name-collision: a DIFFERENT configured target already pinned under the
    # SAME declared identity — two independently configured servers
    # presenting as the same entity.
    if name:
        for other_key, rec in sorted(store.items()):
            if other_key == pin_key or not isinstance(rec, dict):
                continue
            if rec.get("name") == name:
                out.append(mk(
                    ctx, detector_id="server-identity-collision",
                    category="tool-shadowing", evidence_location="server-identity",
                    severity="high", confidence="medium",
                    detection_method="server-identity-pin",
                    rationale=(
                        f"Declared handshake identity '{name}' is shared with a "
                        f"DIFFERENT configured server entry ('{other_key}') already "
                        "pinned under this exact name — two independently "
                        "configured targets presenting as the same server. A "
                        "client that trusts a server purely by its declared "
                        "name cannot tell these apart."
                    ),
                    evidence={"pin_key": pin_key, "name": name, "colliding_key": other_key},
                    source_kind="dynamic-runtime", tool_name=None,
                ))
                break

    store[pin_key] = {"name": name, "tools_hash": thash, "tool_count": len(ctx.tools),
                      "tool_fingerprints": fingerprints}
    _save(path, store)
    return out
