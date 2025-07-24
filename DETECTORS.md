# Detectors

One entry per detector: id(s), category, evidence location, phase, the **mechanism
rationale** (why the shape is suspicious in general — never a hardcoded name/string/
payload), and **known blind spots** (be honest — this is what security testing should probe).

All text detection runs over the normalized representation (`normalize.py`: NFKC,
zero-width/bidi strip + flag, homoglyph→ASCII, base64/hex decode, whitespace
collapse, lowercase, light stemming) so casing/spacing/unicode/encoding variation
does not defeat a rule. The mechanism rule families (`analysis/textrules.py`) match
verb/concept classes with gaps, not literal sentences.

**v4 architecture note:** every detector below runs at full sensitivity and always
emits a finding when its mechanism matches — `confidence` (low/medium/high) is no
longer decided ad hoc inside each detector for the auth/audit, supply-chain-hook,
and tool-poisoning-corroboration cases; it is set centrally, once, by the shared
additive calibration layer (`calibration.py`, see `ARCHITECTURE.md`) from a
contract-vs-behavior contradiction signal. Calibration never deletes a finding or
changes its severity — see each entry below for which detectors are `severity`
self-proving (calibration passes them through unconditionally) vs. calibrated.

---

## `desc-poisoning` (+ `desc-obfuscation`, `schema-poisoning`, `name-obfuscation`)
- **Category:** `tool-poisoning` / `agent-config-poisoning` · **Evidence:** `description`, `schema`, `name` · **Phase:** listing
- **Mechanism (rule 5.1).** A description/schema field is supposed to *describe* a tool;
  instead it carries instructions aimed at the agent. Fires on mechanism families —
  agent-directed imperatives, override-instructions, concealment, exfiltration,
  next-action redirect, preference/priority manipulation, gratuitous
  sensitive-resource references — and separately flags *obfuscation*
  (zero-width/bidi/homoglyph/encoded/HTML-comment) as a concealment mechanism in its
  own right, regardless of what it decodes to.
- **v3 precision fix — clause-bridging false positives (V3-2).** The held-out
  evaluator found the v2 engine still fired on ubiquitous, honest phrasing: "You
  must provide a valid API key to use this tool" scored 6 (agent_directive +
  preference_manipulation + sensitive_reference) and fired `high`. Root cause was
  two structural bugs in `analysis/textrules.py`, not any one fixture's wording:
  (1) the gap between a modal ("must") and its action verb was `.{0,30}` — wide
  enough to bridge an entire unrelated clause — and the verb lists included "use"/
  "include"/"append", the exact words that show up in routine "use this tool to..."/
  "include your token in every request" documentation; (2) `SENSITIVE` mixed
  unambiguous secret-*store* paths (`id_rsa`, `.ssh`, `.env`, cloud metadata
  endpoints) with ambiguous auth-*concept* words (`api key`, `session token`,
  `credential`) that are ordinary, honest parameter names in countless tools. Fixed
  by tightening the modal→verb gap to `.{0,15}`, dropping "use"/"include"/"append"
  from `agent_directive`'s verb lists (folding data into an outbound channel is
  `exfiltration`'s job, which already requires the specific channel+secret noun
  pairing), splitting `SENSITIVE` into `SENSITIVE_STRONG` (secret stores — what
  `read_sensitive` keys on) vs. `SENSITIVE_WEAK` (auth-concept words — only ever
  feed the low-weight, drop-if-alone `sensitive_reference` family), and requiring
  `preference_manipulation`'s self-promotion pattern to reference an explicit
  *other* tool rather than accepting a bare "this". Verified clean on
  `tests/fixtures/benign_poisoning` (session/admin/audit/auth-requirement
  descriptions) while `tests/fixtures/poisoned` / `poisoned2` still fire.
- **v3 recall fix — `next_action_redirect` family (V3-1).** New decisive family:
  sequencing tied to the agent's own act of responding ("before/after/once you
  respond/answer/reply", then a call/invoke/run/execute verb anywhere after it), an
  explicit non-"you"/"user" agent addressee ("the assistant/agent/model/system
  must/should call..."), a pseudo-system/instruction tag, or folding a secret-shaped
  value into "your next response/reply/message". Fires on its own, independent of
  the framing device, matching the report's "redirect the agent's next action"
  requirement without keying on any one phrasing.
- **Precision gate.** `sensitive_reference` alone is dropped; usage verbs
  ("provide a city", "specify the path") are separated from action verbs; a benign
  "send email to recipient"/"create file at path" does not fire (only external-shaped
  exfil destinations count).
- **v4: cross-evidence-location corroboration (Part-B "+ corroboration").**
  `calibration.py` groups all `tool-poisoning`/`agent-config-poisoning` findings
  by `(target, tool)`; when the SAME tool is poisoned across **two or more
  distinct evidence locations** (its description *and* a schema field
  description, or its description *and* its name), every finding in the group
  is raised to `confidence: high` — an honest tool essentially never has
  agent-directed language leak into two independent, separately-authored
  surfaces at once, so agreement across locations is real corroboration. This
  only ever *raises* confidence (additive); a single non-decisive match with no
  second location is left exactly as the detector graded it. See
  `tests/test_calibration.py::test_poisoning_corroborated_across_description_
  and_schema_raised_to_high` / `test_poisoning_single_evidence_location_not_
  corroborated`.
- **Blind spots.** Poison expressed as pure natural-language narrative with *no*
  imperative/exfil/concealment shape (e.g. a subtly misleading but grammatical
  description) can score below threshold. A brand-new obfuscation channel not in the
  confusables/zero-width tables. Non-English payloads (vocabularies are English).
  Descriptions built at runtime from data the static pass can't see (dynamic layer
  covers this). An override/redirect phrased with none of the decisive verb classes
  at all (e.g. "the instructions above are outdated, use these instead" with no
  ignore/disregard/bypass verb) is still a miss — left uncovered deliberately, since
  broadening it further risked reintroducing the clause-bridging FP class fixed
  above.

## `ast-taint`
- **Category:** `command-injection` / `path-traversal` / `ssrf` · **Evidence:** `source` · **Phase:** listing
- **Mechanism (rules 5.3b/5.6).** Tool parameters are tainted sources; taint propagates
  through assignments / f-strings / joins to sinks: command exec (`subprocess`,
  `os.system`, …), `eval`/`exec`, unsafe deserialize (`pickle`, `yaml.load` without
  SafeLoader), file open/read/write/delete, and network calls. Reports the
  source→sink path. Fires **only when a tainted value reaches the sink** —
  `shell=True` with taint is `critical`.
- **Precision gate.** A fixed/constant argument to the same sink is *not* flagged
  (`subprocess.run(['git','--version'])`); `yaml.safe_load` is not flagged.
- **Blind spots.** Intra-procedural only — taint through a helper function/method,
  across modules, or via object attributes is under-tracked (recall gap). Sanitizers
  are not modeled, so a properly-validated tainted path is still reported
  (false-positive risk — confidence is lowered when taint is indirect). Python only;
  JS/TS taint is not analyzed in v1. Dynamic `getattr`/reflection dispatch is missed.

