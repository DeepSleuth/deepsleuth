"""Deterministic text-normalization pipeline (rule 5.1).

The single most brittle thing existing description-poisoning detectors do is match
exact phrasings. We defend generalization by *normalizing* text to a canonical
form before any rule runs, and by *flagging concealment* (zero-width, bidi,
homoglyphs, encoded blobs) as suspicious in its own right — regardless of what the
hidden content decodes to.

No neural nets, no downloads: NFKC, a curated confusables table, deterministic
base64/hex decoding, a light rule-based stemmer. Same input -> identical output.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Set

# --- character classes we care about ----------------------------------------

# Zero-width / invisible formatting characters (used to hide payloads).
ZERO_WIDTH = {
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "⁠",  # word joiner
    "⁡",
    "⁢",
    "⁣",
    "⁤",
    "﻿",  # BOM / zero width no-break space
    "­",  # soft hyphen
    "᠎",  # mongolian vowel separator
    "͏",  # combining grapheme joiner
}

# Bidirectional control characters (Trojan-Source style reordering).
BIDI_CONTROL = {
    "‪",
    "‫",
    "‬",
    "‭",
    "‮",
    "⁦",
    "⁧",
    "⁨",
    "⁩",
    "‎",
    "‏",
}

# Curated confusable -> ASCII map (Cyrillic/Greek/fullwidth lookalikes and a few
# punctuation confusables). Deterministic and general; not drawn from any sample.
CONFUSABLES: Dict[str, str] = {
    # Cyrillic lowercase lookalikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "ԁ": "d", "ԛ": "q", "ѕ": "s", "ґ": "g",
    # Cyrillic uppercase lookalikes
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    # Greek lookalikes
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ν": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Fullwidth ASCII
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
}

# characters that *are* homoglyph sources (used to raise the flag)
HOMOGLYPH_SOURCES = set(CONFUSABLES.keys())

# rule P0.2: fullwidth ASCII (used constantly in ordinary CJK typesetting — a
# fullwidth "！"/"："/"Ａ" is not an attack, it is how Chinese/Japanese text is
# normally written) is excluded from the "mixed-script word" homoglyph check
# below. It is still folded to plain ASCII during normalization (so downstream
# regex rules keep working on fullwidth text) — it is only never itself
# treated as a suspicious lookalike.
_FULLWIDTH_SOURCES = {chr(0xFF01 + i) for i in range(94)}
# the actual attack-shaped confusable set: Cyrillic/Greek letters that render
# identically (or near-identically) to a Latin letter.
_SCRIPT_HOMOGLYPH_SOURCES = HOMOGLYPH_SOURCES - _FULLWIDTH_SOURCES

_ASCII_LETTER_RE = re.compile(r"[A-Za-z]")
_WORD_CHARS_RE = re.compile(r"\w+", re.UNICODE)


def _word_mixes_latin_and_lookalike(text: str) -> bool:
    """The real homoglyph attack shape is a single WORD that mixes an
    ordinary ASCII Latin letter with a Cyrillic/Greek lookalike letter (e.g. a
    Cyrillic 'а' standing in for a Latin 'a' inside an otherwise-Latin word).
    A whole description written in Chinese, Russian, Hebrew or Greek has no
    such word — every letter in each word comes from the same script — so it
    must never raise the flag. A single Latin word with one substituted
    lookalike letter still does, because that one word itself mixes scripts."""
    for m in _WORD_CHARS_RE.finditer(text):
        word = m.group(0)
        has_latin = bool(_ASCII_LETTER_RE.search(word))
        has_lookalike = any(c in _SCRIPT_HOMOGLYPH_SOURCES for c in word)
        if has_latin and has_lookalike:
            return True
    return False


# --- rule 4.4 — non-English coverage note ----------------------------------------
# The text-rule engine's vocabulary (override/conceal/exfiltrate/redirect
# families, etc.) is English-only. A description genuinely written in another
# script should never be silently treated as "clean" (no finding fired ==
# assumed safe) OR misread as obfuscation — it should instead surface as a
# REDUCED-COVERAGE note. Coarse, purely script-based (unicode codepoint
# ranges), deliberately conservative: needs a real minimum amount of letter
# content and a clear non-Latin-script MAJORITY, so a short string, one
# foreign proper noun, or a stray symbol never trips it.
_LATIN_LETTER_RE = re.compile(r"[A-Za-z]")
_NON_LATIN_LETTER_RE = re.compile(
    r"[Ѐ-ӿͰ-Ͽ一-鿿぀-ヿㇰ-ㇿ"
    r"가-힣֐-׿؀-ۿ฀-๿ऀ-ॿ]"
)


def is_probably_non_english(text: str, min_letters: int = 12) -> bool:
    """Coarse script-majority check — a coverage signal only, never itself a
    finding (rule 4.4)."""
    if not text:
        return False
    latin = len(_LATIN_LETTER_RE.findall(text))
    non_latin = len(_NON_LATIN_LETTER_RE.findall(text))
    if latin + non_latin < min_letters:
        return False
    return non_latin > latin


# --- zero-width: a ZWJ (U+200D) directly between two emoji codepoints is the
# ordinary mechanism for composing an emoji sequence (a family emoji, a
# flag, a skin-tone modifier) — not concealment. Every OTHER zero-width
# character (ZWSP, word joiner, BOM, soft hyphen, the Mongolian vowel
# separator, the combining grapheme joiner, and a ZWJ NOT between emoji)
# keeps the original, stricter behavior: it has no honest reason to appear in
# a tool description at all.
_ZWJ = "‍"
_EMOJI_RANGES = (
    (0x1F1E6, 0x1F1FF),  # regional indicators (flags)
    (0x1F300, 0x1FAFF),  # misc symbols & pictographs .. symbols & pictographs ext-A
    (0x2600, 0x27BF),    # misc symbols / dingbats
    (0x2B00, 0x2BFF),    # misc symbols and arrows (some emoji live here)
    (0xFE0F, 0xFE0F),    # variation selector-16 (emoji presentation)
    (0x1F000, 0x1F0FF),  # playing cards / mahjong (rare, harmless to include)
)


def _is_emoji_char(c: str) -> bool:
    cp = ord(c)
    return any(lo <= cp <= hi for lo, hi in _EMOJI_RANGES)


def _has_real_zero_width(text: str) -> bool:
    n = len(text)
    for i, c in enumerate(text):
        if c not in ZERO_WIDTH:
            continue
        if c == _ZWJ:
            prev_emoji = i > 0 and _is_emoji_char(text[i - 1])
            next_emoji = i + 1 < n and _is_emoji_char(text[i + 1])
            if prev_emoji and next_emoji:
                continue  # legitimate emoji-sequence joiner
        return True
    return False


# --- bidi: LRM/RLM (the plain directional MARKS, as opposed to the
# embedding/override/isolate CONTROLS below) are ordinary, legitimate
# punctuation-direction fixups that appear constantly in real Hebrew/Arabic
# prose next to right-to-left letters. The actual Trojan-Source mechanism
# (reordering what renders vs. what a scanner reads) needs the embedding/
# override/isolate controls (LRE/RLE/PDF/LRO/RLO/LRI/RLI/FSI/PDI), which stay
# flagged unconditionally — they have no legitimate use in a tool description
# regardless of what text surrounds them.
_BIDI_MARKS = {"‎", "‏"}  # LRM, RLM
_RTL_SCRIPT_RANGES = (
    (0x0590, 0x05FF),  # Hebrew
    (0x0600, 0x06FF),  # Arabic
    (0x0700, 0x074F),  # Syriac
    (0x0750, 0x077F),  # Arabic Supplement
    (0x08A0, 0x08FF),  # Arabic Extended-A
    (0xFB1D, 0xFDFF),  # Hebrew/Arabic presentation forms A
    (0xFE70, 0xFEFF),  # Arabic presentation forms B
)


def _is_rtl_script_char(c: str) -> bool:
    cp = ord(c)
    return any(lo <= cp <= hi for lo, hi in _RTL_SCRIPT_RANGES)


def _has_real_bidi(text: str) -> bool:
    n = len(text)
    for i, c in enumerate(text):
        if c not in BIDI_CONTROL:
            continue
        if c in _BIDI_MARKS:
            window = text[max(0, i - 8):min(n, i + 9)]
            if any(_is_rtl_script_char(w) for w in window):
                continue  # legitimate directional mark next to RTL script
        return True
    return False

_WORD_RE = re.compile(r"[a-z0-9]+")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{32,}")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_FENCE_RE = re.compile(r"```|~~~")


@dataclass
class NormResult:
    original: str
    normalized: str  # NFKC + confusables->ascii + strip zero-width, collapsed, lower
    visible: str  # NFKC + confusables, zero-width/bidi stripped, case preserved
    tokens: List[str]
    stems: Set[str] = field(default_factory=set)
    # concealment flags
    has_zero_width: bool = False
    has_bidi: bool = False
    has_homoglyph: bool = False
    has_html_comment: bool = False
    has_code_fence: bool = False
    decoded_segments: List[str] = field(default_factory=list)  # base64/hex decodes
    stats: Dict[str, float] = field(default_factory=dict)

    @property
    def has_hidden_encoding(self) -> bool:
        return bool(self.decoded_segments)

    @property
    def obfuscated(self) -> bool:
        return (
            self.has_zero_width
            or self.has_bidi
            or self.has_homoglyph
            or self.has_html_comment
            or self.has_hidden_encoding
        )


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2

    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def _try_decode_blobs(text: str) -> List[str]:
    """Deterministically decode high-entropy base64/hex blobs to printable text."""
    out: List[str] = []
    seen: Set[str] = set()
    for m in _BASE64_RE.finditer(text):
        blob = m.group(0)
        if blob in seen:
            continue
        seen.add(blob)
        # entropy the gate: skip low-entropy runs (e.g. long words) to avoid noise
        if _shannon_entropy(blob) < 3.2:
            continue
        try:
            pad = "=" * (-len(blob) % 4)
            raw = base64.b64decode(blob + pad, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            dec = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(c.isprintable() or c.isspace() for c in dec)
        if dec and printable / max(1, len(dec)) > 0.85 and len(dec) >= 4:
            out.append(dec)
    for m in _HEX_RE.finditer(text):
        blob = m.group(0)
        h = blob[2:] if blob.lower().startswith("0x") else blob
        if len(h) % 2 or blob in seen:
            continue
        seen.add(blob)
        try:
            raw = bytes.fromhex(h)
            dec = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        printable = sum(c.isprintable() or c.isspace() for c in dec)
        if dec and printable / max(1, len(dec)) > 0.85 and len(dec) >= 4:
            out.append(dec)
    return out


# very small rule-based stemmer (no nltk / no downloads)
def stem(word: str) -> str:
    w = word.lower()
    for suf, repl in (
        ("sses", "ss"),
        ("ies", "y"),
        ("ications", "y"),
        ("ing", ""),
        ("edly", ""),
        ("edly", ""),
        ("ed", ""),
        ("ly", ""),
        ("ers", ""),
        ("er", ""),
        ("s", ""),
    ):
        if w.endswith(suf) and len(w) - len(suf) >= 3:
            return w[: -len(suf)] + repl
    return w


def normalize(text: str) -> NormResult:
    """Run the full normalization + concealment-flagging pipeline."""
    if text is None:
        text = ""
    if not isinstance(text, str):
        text = str(text)

    has_zw = _has_real_zero_width(text)
    has_bidi = _has_real_bidi(text)
    has_homoglyph = _word_mixes_latin_and_lookalike(text)
    has_comment = bool(_HTML_COMMENT_RE.search(text))
    has_fence = bool(_FENCE_RE.search(text))

    decoded = _try_decode_blobs(text)

    # 1) strip zero-width + bidi controls
    stripped = "".join(c for c in text if c not in ZERO_WIDTH and c not in BIDI_CONTROL)
    # 2) NFKC (folds fullwidth, compatibility forms, ligatures)
    nfkc = unicodedata.normalize("NFKC", stripped)
    # 3) map remaining confusables to ascii
    visible = "".join(CONFUSABLES.get(c, c) for c in nfkc)
    visible = unicodedata.normalize("NFKC", visible)
    # 4) canonical: lowercase + collapse whitespace
    lowered = visible.lower()
    collapsed = re.sub(r"\s+", " ", lowered).strip()

    tokens = _WORD_RE.findall(collapsed)
    stems = {stem(t) for t in tokens}

    # stats used by anomaly rules
    sentences = [s for s in re.split(r"[.!?\n]+", visible) if s.strip()]
    stats = {
        "char_len": float(len(text)),
        "visible_len": float(len(visible)),
        "token_count": float(len(tokens)),
        "sentence_count": float(len(sentences)),
        "avg_entropy": _shannon_entropy(collapsed),
        "nonascii_ratio": (
            sum(ord(c) > 127 for c in text) / len(text) if text else 0.0
        ),
    }

    return NormResult(
        original=text,
        normalized=collapsed,
        visible=visible,
        tokens=tokens,
        stems=stems,
        has_zero_width=has_zw,
        has_bidi=has_bidi,
        has_homoglyph=has_homoglyph,
        has_html_comment=has_comment,
        has_code_fence=has_fence,
        decoded_segments=decoded,
        stats=stats,
    )
