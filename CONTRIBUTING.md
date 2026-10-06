# Contributing

Thanks for your interest in improving deepsleuth.

## Getting started

```bash
git clone https://github.com/DeepSleuth/deepsleuth-mcp.git
cd deepsleuth
python -m deepsleuth --help
python tests/run_all.py
```

The scanner has **zero required dependencies** — please keep it that
way; anything third-party must remain an optional extra.

## Adding a detector

See ARCHITECTURE.md ("Adding a detector"). Short version:

1. Create `deepsleuth/detectors/<name>.py` as a pure function over the
   `ScanContext`.
2. Register it with its phase, category and required capabilities.
3. Add a unit test plus a fixture, and a `DETECTORS.md` entry with the
   detector's known blind spots.
4. Keep full sensitivity; confidence is the calibration layer's job.

## Ground rules

- Determinism is a hard constraint: no randomness, no wall-clock, no
  network in outputs. Same input, byte-identical findings.
- One detector can never break a scan: catch and record, never crash.
- Tests run without pytest: `python tests/run_all.py`.
