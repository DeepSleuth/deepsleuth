# Architecture

deepsleuth is **one detection core with two frontends**. Detection logic is
never entangled with a frontend: detectors are pure functions over a shared
`ScanContext`, and the only thing a frontend does is *populate* that context and
choose which phases to run.

```
                         ┌──────────────────────── detection CORE ───────────────────────┐
                         │  normalize.py  analysis/{pyast,jsast,textrules,editdist}.py     │
                         │  context.py (ScanContext, canaries, cross-call state tracker)   │
                         │  detectors/*  (registry)     runner.py (phased execution)       │
                         │  pinning.py (proxy server-identity pins, rule 4.2)                  │
                         │  models.py (the Finding)      reporter.py (stable findings JSON)       │
                         └───────▲───────────────────────────────────────────────▲────────┘
                                 │ same Context, same detectors                   │
        ┌────────────────────────┴───────────┐                    ┌──────────────┴───────────────────┐
        │ Frontend B — scanner.py            │                    │ Frontend A — proxy.py             │
        │ target_loader → sandbox(Docker) →  │                    │ inline stdio gateway + gate.py    │
        │ mcpclient drive plan → all phases  │                    │ 3 interposition points; proxy-eval │
        └────────────────────────────────────┘                    └───────────────────────────────────┘
```

## The shared context and phases

`ScanContext` (`context.py`) holds: declared metadata (`tools`/`resources`/
`prompts` as `ToolContract`s), captured `server_info`, source facts bound per tool,
package manifests, the list of `CallRecord`s, a later re-listing for diffing, and
the `CrossCallState` tracker (planted canaries + decoy-file markers).

Detectors run in **phases** (`runner.py`), so each frontend triggers them at the
right moment:

| Phase | When | Detectors |
|---|---|---|
| `listing` | metadata/source/package available | poisoning, cross-tool-redirect/param-tampering/output-substitution/out-of-scope-param, taint, hint-vs-behavior/scope-creep, rug-pull-source, identity, supply-chain, auth |
| `precall` | one pending `tools/call` | the gate pre-call detector |
| `response` | a response captured | response-injection, response-redirect, canary/credential leak, over-sharing |
| `multicall` | ≥2 calls / a re-listing | rug-pull runtime diff (incl. idempotent-declared-tool response diff) |

`cross-server-name-overlap` (rule 4.1) is a separate cross-target pass run once
over every `ScanContext` in a multi-server scan, not a per-phase detector —
see `detectors/crossserver.compare_tool_names`.

A detector declares a `requires` capability set (`manifest`/`source`/`dynamic`/
`package`/`identity`); the runner skips it cleanly when that layer is absent, so a
static-only run (no Docker) never crashes and simply reports reduced coverage.

If a detector raises, the runner records a `severity: none` `detector-error`
finding (coverage stays visible) and continues — one detector can never break a
scan (rule 3.2).

