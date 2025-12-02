"""v6-W3 — whole-environment serialization as a static disclosure sink.

A tool whose body RETURNS the whole process environment (``str(dict(os.environ))``,
``json.dumps(dict(os.environ))``, an ``os.environ.items()`` loop that builds the
response, ``printenv``) hands the agent -- and anyone the agent talks to --
every secret the server process holds. The dynamic child environment carries no
decoy canary, so no live scan can see it; this detector keys on the SOURCE SHAPE
(``analysis/envdump.py``) instead of canary luck.

Whole vs. single is the whole rule: a tool returning ONE caller-requested
variable (``os.environ.get(name)``) is clean; a tool handing the environment to
a child process is clean (a consumer, not a disclosure).

Grading (contract-vs-behavior, via the shared calibration layer):

* the description DECLARES environment dumping (it names the environment /
  environment variables)  -> the declared-capability lane: low/low note, never
  a graded disclosure finding (v3-1.1 / rule P3.7: a declaration is recorded, it
  does not turn the shape into an attack -- and it is not allowed to discount
  anything either, which is why this lane exists beside, not instead of, the
  graded one for undeclared dumps);
* the description does NOT declare it -> information-disclosure, high severity,
  medium confidence on the shape alone; ``calibration`` raises confidence to
  high when the tool carries a description that says nothing about the
  environment (a contradiction between contract and behavior).
"""
from __future__ import annotations

import re
from typing import List

from ..context import ScanContext
from ..models import Finding
from .base import CAP_SOURCE, Detector, register
from ._util import mk

# the description names the environment as something the tool returns/dumps
_DECLARES_ENV_RE = re.compile(
    r"\b(?:environment(?:\s+variables?)?|environ\b|env(?:ironment)?[\s_-]?vars?|"
    r"process[\s_-]?env(?:ironment)?|printenv|\benv\b)", re.IGNORECASE)


def _declares_environment(desc: str) -> bool:
    return bool(_DECLARES_ENV_RE.search(desc or ""))


def _run(ctx: ScanContext) -> List[Finding]:
    out: List[Finding] = []
    for c in ctx.all_contracts():
        if not c.source or c.source.facts is None:
            continue
        dumps = getattr(c.source.facts, "environ_dumps", None) or []
        if not dumps:
            continue
        desc = c.description or ""
        declared = _declares_environment(desc)
        forms = sorted({d.get("form", "") for d in dumps if d.get("form")})
        ev = {"forms": forms,
              "sites": [{"line": d.get("lineno"), "code": d.get("snippet", "")[:160],
                         "module": d.get("module") or c.source.module_path,
                         "via": d.get("via") or ""} for d in dumps[:4]],
              "module": c.source.module_path, "declared_in_description": declared,
              "description_excerpt": desc[:200]}
        if declared:
            out.append(mk(
                ctx, detector_id="environ-dump", category="information-disclosure",
                evidence_location="source", severity="low", confidence="low",
                detection_method="declared-capability",
                rationale=(f"Tool '{c.name}' returns the whole process environment "
                           f"({', '.join(forms) or 'environment mapping'}) and its own "
                           "description declares it deals in the environment -- recorded "
                           "in the declared-capability lane as a note, not graded as an "
                           "undisclosed disclosure."),
                evidence=ev, source_kind="static-code", tool_name=c.name,
                raw={"declared_capability": True, "environ_dump": True},
            ))
            continue
        out.append(mk(
            ctx, detector_id="environ-dump", category="information-disclosure",
            evidence_location="source", severity="high", confidence="medium",
            detection_method="environ-dump-source",
            rationale=(f"Tool '{c.name}' returns the WHOLE process environment "
                       f"({', '.join(forms) or 'environment mapping'}) rather than a "
                       "single caller-requested variable -- every secret the server "
                       "process holds (cloud keys, tokens, connection strings) is handed "
                       "to the caller, and the tool's description does not say it deals "
                       "in the environment."),
            evidence=ev, source_kind="static-code", tool_name=c.name,
            raw={"environ_dump": True, "description_mismatch": bool(desc.strip())},
        ))
    return out


register(Detector(
    id="environ-dump", category="information-disclosure", evidence_location="source",
    phase="tool listing", run=_run, requires={CAP_SOURCE},
    rationale=("Serializing the whole process environment into a response discloses "
               "every secret the server holds; the shape (the mapping itself reaching "
               "a return, as opposed to one requested variable) is visible in source "
               "even though no canary is ever planted in the child environment."),
))
