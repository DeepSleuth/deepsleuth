# Benchmarks

Scored on 2026-10-04. Every file under [`benchmarks/data/`](benchmarks/data/) was
regenerated from this code: one `*_per_target.json` with the raw findings per
target and one `*_summary.json` per dataset. Each summary states the mechanical
rule used for the mechanism-strict column, so the numbers below can be recomputed
without any hand judgment.

> **In-sample disclosure (read this first).** All four datasets are in-sample:
> the detectors were developed with knowledge of every one of them, including the
> 27-case "held-out" split of the visibility bench, so the figures below measure
> fit plus mechanism quality, not clean generalization. Only the real-server
> corpus and the three unseen corpora further down were never used for tuning.
> A truly unseen held-out set remains an open item.

## Definitions

- **Loose** — any finding on the target, of any grade.
- **Actionable** — severity medium or higher *and* confidence medium or higher;
  the grades the gate acts on (confirm or block).
- **Mechanism-strict** — an actionable finding from the detector that names the
  planted mechanism, by the fixed mapping written in the dataset's summary file.
- **Withheld or blocked** — an actionable finding at high or critical severity,
  which the default proxy policy withholds (listing) or blocks (call/response).
- **False positive** — a benign target with an actionable finding; the count of
  benign targets with any finding at all is given beside it.

