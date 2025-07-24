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

