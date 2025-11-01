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

## v4: detection vs. calibration (`calibration.py`)

Detectors run at **full sensitivity** and always emit their finding — recall is
never lost to an internal threshold. Immediately after each phase's detectors
run, `runner.run_phase` calls the single shared **calibration** layer
(`calibration.py`), which sets each finding's `confidence` from a deterministic
contract-vs-behavior **contradiction** signal (+ corroboration across evidence
locations on the same tool) and never deletes a finding or touches `severity`.
Because this hook lives inside `run_phase` — which both `scanner.py` (Frontend
B, via `run_all`) and `proxy.py`/`gate_precall` (Frontend A, live and
`proxy-eval`) call for every phase — calibration is applied identically
everywhere without either frontend having to remember to invoke it.

A tool whose own description openly declares the exact dangerous capability a
sink reaches (running a command, fetching a caller-supplied URL) is reported
in a separate, low-severity **capability lane** instead of as an injection/ssrf
finding (rule P3.7, `detectors/taint.py`, `detection_method: declared-capability`)
— an honest tool stating its own job is not treated identically to one hiding
the same behavior.

A finding's `evidence_location`/`category`/`severity` says *what* was found;
`confidence` (set by calibration) says *how sure we are it's real*, and the
gate acts on both together (the ACTIONABLE bar: `severity ∈ {medium,high,
critical} AND confidence ∈ {medium,high}`). Some mechanisms are self-proving —
a planted canary surfacing in an unrelated response, a decisive agent-directed
directive in a tool's own output, a hint contradicted by observed behavior, a
tainted source→sink path — calibration passes these through untouched
(`calibration.UNCONDITIONAL_DETECTOR_IDS`). Others (auth/audit "claimed but
absent", supply-chain hook shape, tool-poisoning corroboration) get their
confidence computed centrally instead of scattered per-detector.

## Frontend B — batch / sandbox scanner (`scanner.py`)

1. `target_loader.py` normalizes the target into a `Target` (launch spec +
   discovered source + package manifests).
2. Static context is built: Python modules parsed (`analysis/pyast.py` —
   decorator-registered, functionally-registered, and low-level-SDK
   `list_tools`/`call_tool`-dispatched tools alike, rule 2.7) and JS/TS modules
   text-scanned (`analysis/jsast.py`, rule 2.8); tools extracted, behavior facts
   computed (taint with one level of call inlining + sanitizer modeling,
   rule 2.6), contracts synthesized from source.
3. If dynamic is enabled and Docker is present, `sandbox/docker_sandbox.py`
   launches the server **non-root, `--network none`, read-only rootfs, tmpfs home
   seeded with decoy secret files, CPU/mem/pids/time limits**. `mcpclient` drives a
   deterministic call plan (`sandbox/argsynth.py`): a burst phase (each tool called
   several times in a row, reset-like tools deferred to the end, rule 3.1), the
   round-robin passes with schema-derived arguments and planted canaries, then
   a small capped tail of extra calls trying source-harvested candidate values,
   every remaining schema `enum` value, and relative/`../` path variants
   (rules 3.2/3.3). Every response is captured; every listed resource and prompt
   is also **read** (`resources/read`/`prompts/get`, rule 3.4) and folded into the
   same call log the response detectors scan; tools are re-listed for the
   rug-pull diff.
4. All phases run; findings are deduped `(target, tool, mechanism)` and emitted in
   stable order.

