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

## Headline

| Dataset | Loose | Actionable | Mechanism-strict | False positives (actionable / any) |
|---|---|---|---|---|
| MCPTox (485 malicious), each description alone | 392 (80.8%) | 345 (71.1%) | 345 (71.1%) | benign half: 1 / 1 of its 362 clean tools |
| MCPTox, each description scanned with its server's tool list | 457 (94.2%) | 425 (87.6%) | 425 (87.6%) | — |
| MCPSecBench (9 malicious / 6 benign, live servers) | 9/9 | 9/9 | **8/9** | 0 / 1 of 6 |
| MSB (90 malicious / 21 benign, static) | 72/90 (80.0%) | 66/90 (73.3%) | **66/90 (73.3%)**; `name_overlap` 18/18 when each variant is scanned with its clean twin | 1 / 1 of 21 |
| Visibility bench, all 60 (41 / 19) | 41/41 | 39/41 | **37/41** | **0** / 3 of 19 |
| Visibility bench, 27-case split (18 / 9) | 18/18 | 16/18 | 15/18 | **0** / 1 of 9 |

The MCPTox benign half is new: the dataset ships the clean tool lists of its 45
source servers (362 tools), scanned here per server. The published run still
scans each poisoned description alone; the second MCPTox row shows the same
scanner given the context the sibling rule was built for. This round moved the
two rows in opposite directions (alone 358 to 345, with the tool list 395 to
425); the version history below explains why.

## Precision on real servers (never used for tuning)

168 live server listings with 1,544 tools, captured from live public registries during our own measurement runs. There is
no ground truth; the servers are overwhelmingly ordinary.

| Version | Tools with any finding | Tools actionable | Tools withheld by the default policy | Servers with an actionable finding |
|---|---|---|---|---|
| original (`3253f8b`) | 110 | 110 | 104 | 42 |
| round 1 (`5ae56ca`) | 87 | 87 | 78 | 41 |
| precision round (`742158b`) | 83 | 48 | 37 | 22 |
| first mechanism round (`d2cba73`) | 64 | 24 | 21 | 15 |
| second mechanism round (`3654815`) | 64 | 24 | 21 | 15 |
| **this version (`334bee9`)** | **63 (4.1%)** | **19 (1.2%)** | **16 (1.0%)** | **12 (7%)** |

Other corpora never used for tuning: MCP-Universe (13 Python servers, 159
tools) 5 tools actionable, two of them genuine command runners; sentinel-scan-cli
fixtures 11/20 malicious caught (9/20 in the previous version), 0/20 clean
flagged; mcp-shield JavaScript demo 3/5 poisoned tools caught.

