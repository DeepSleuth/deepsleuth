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

## Version history, same scoring

| Version | MCPTox actionable, alone (of 485) | MCPSecBench strict (of 9) | MSB strict (of 90) | Visibility strict (of 41) | Visibility FP (of 19) | Real-server tools withheld |
|---|---|---|---|---|---|---|
| original | 111 | 6 | 0 | 32 | 2 | 104 |
| round 1 | 394 | 6 | 42 | 37 | 0 | 78 |
| precision round | 359 | 6 | 54 | 35 | 1 | 37 |
| first mechanism round | 358 | 7 | 66 | 37 | 2 | 21 |
| second mechanism round | 358 | 7 | 66 | 37 | 0 | 21 |
| **this version** | **345** | **8** | **66** | **37** | **0** | **16** |

The precision round traded about eight points of MCPTox recall for cutting
real-server withholds in half; the first mechanism round kept that recall and
halved the withholds again while restoring the two detections the precision round had lost
(a declared command runner's injection, and a label-shaped response redirect).
The second mechanism round changed no recall figure and removed both visibility
false positives. One visibility case that had been flagged only by an audit-echo
finding identical to its benign twin's is now, correctly, no longer counted as
actionable (40 to 39), while mechanism-strict stays at 37.

The third mechanism round (this version) is a trade, and it is reported as one.
It changed how a reference to another tool is graded: a clause that relates two
tools other than the described one is now actionable, and a strong obligation
word escalates a reference only when the other tool is the object of a call. It
also narrowed the shadowing rule to objects shaped like a tool or a server, and
taught the exfiltration and secret-store wording families to separate a
description of what a tool does from an instruction to the agent.

- **Gained:** five fewer real-server withholds (21 to 16); two more MCPSecBench
  tools caught (7 to 9 actionable); two more sentinel fixtures (9 to 11); and
  30 more MCPTox detections when a description is scanned with its server's
  tool list (395 to 425: 38 gained, 8 lost, all through the cross-tool rule).
- **Lost:** 13 MCPTox detections when a description is scanned alone (358 to
  345: 11 gained, 24 lost). Of the 24, 17 are still reported, at low grade, by
  the cross-tool rule; 7 had been caught only by the old, broader shadowing
  rule and now produce no finding. 17 of the 24 are caught once the tool list
  is present.

The round as first built stood at 341 alone. A follow-up replaced the
word-order test in the obligation-word rule with the object test and brought
that to 345 without bringing any real-server flag back. The remaining gap to
the previous version is real and is not hidden by the in-listing figure.

## Head to head

Figures for the five public scanners come from the same measurement runs, where they
were measured on data their authors had not tuned against. deepsleuth's row is
this version, in-sample. The comparison is therefore not like for like.

| Scanner | MCPTox loose | MCPTox strict | MCPSecBench strict (of 9) | MCPSecBench FP (of 6) | MSB loose (of 90) | MSB strict | MSB FP (of 21) | Visibility strict (of 41) |
|---|---|---|---|---|---|---|---|---|
| **deepsleuth** | **80.8%** | **71.1%** | **8** | 0 | 72 | **66** | 1 | **37** |
| Snyk Agent Scan | 74.8% | 64.1% | 0 | 0 | 74 | 0 | 16 | 0 |
| mcp-armor | 35.3% | 20.8% | 1 | 2 | 19 | 0 | 0 | 0 |
| sentinel-scan-cli | 25.4% | 2.5% | 2 | 0 | 16 | 0 | 4 | 0 |
| NVIDIA SkillSpector (static) | 22.5% | 2.5% | 1 | 0 | 2 | 0 | 1 | 0 |
| Cisco mcp-scanner | 20.4% | 3.1% | 0 | 0 | 0 | 0 | 0 | 0 |

