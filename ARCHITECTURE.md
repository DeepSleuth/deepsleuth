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

