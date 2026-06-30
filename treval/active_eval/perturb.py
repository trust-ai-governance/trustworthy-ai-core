"""Deterministic adversarial perturbations for Tier-1 rule-robustness (EV-AE7).

Each transform is a PURE, DETERMINISTIC function str -> str (no RNG, no clock — the
harness forbids nondeterminism and bit-reproducibility is the whole point). They produce
**render-identical / canonicalization-defeatable** obfuscations of an attack input: the
attack stays human-readable and the same technique, only its surface bytes change. This
is exactly what P2-norm (NFKC + zero-width/homoglyph strip) should defeat — so EV-AE7 is
P2-norm's acceptance test (EV-AE7 §0/D1).

NOT in scope: SEMANTIC obfuscation (base64, translation, paraphrase) — those change
meaning, need decode/Tier-2 detection, and are already base-corpus cases Tier-1 misses.

One kind per variant (do NOT stack) — keeps the variant attributable (which obfuscation
evaded) and gives P2-norm a per-step acceptance test.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import replace

from treval.active_eval.corpus import CorpusCase

_ZWSP = "​"  # zero-width space
# Latin → visually-identical Cyrillic look-alikes (NFKC + confusables-fold reverses it).
_HOMOGLYPH = {
    "a": "а",
    "e": "е",
    "o": "о",
    "c": "с",
    "p": "р",
    "x": "х",
    "y": "у",
}


def _longest_word_span(s: str) -> re.Match[str] | None:
    """The first-longest maximal run of ASCII letters (a 'word'), or None. Deterministic
    tie-break: longest length, then earliest start."""
    words = list(re.finditer(r"[A-Za-z]+", s))
    if not words:
        return None
    return max(words, key=lambda m: (len(m.group()), -m.start()))


def _perturb_longest_word(s: str, joiner: str) -> str:
    """Rejoin the letters of the longest word with `joiner` (applied minimally — one word,
    not the whole string — so the variant stays the same attack)."""
    m = _longest_word_span(s)
    if m is None or len(m.group()) < 2:
        return s
    return s[: m.start()] + joiner.join(m.group()) + s[m.end() :]


def case_flip(s: str) -> str:
    """Alternating-case obfuscation: 'ignore' -> 'IgNoRe'.

    Attack principle: a case-sensitive keyword/substring rule ('ignore') misses the
    mixed-case form. Expected bypass: literal lower-case match fails. Canonicalization
    that defeats it: case-fold the input before matching (.casefold())."""
    out: list[str] = []
    seen = 0
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if seen % 2 == 0 else ch.lower())
            seen += 1
        else:
            out.append(ch)
    return "".join(out)


def zero_width(s: str) -> str:
    """Zero-width-space obfuscation: 'ignore' -> 'i​g​n​o​r​e'
    (renders identically).

    Attack principle: a ZWSP between letters breaks a contiguous-substring rule while the
    text looks unchanged to a human. Expected bypass: 'ignore' is no longer a substring.
    Canonicalization that defeats it: strip zero-width characters (NFKC + ZW strip)."""
    return _perturb_longest_word(s, _ZWSP)


def punctuate(s: str) -> str:
    """Punctuation-insertion obfuscation: 'ignore' -> 'i.g.n.o.r.e'.

    Attack principle: interleaved periods break a contiguous-substring rule, still
    readable. Expected bypass: 'ignore' is no longer a substring. Canonicalization that
    defeats it: strip non-alphanumerics within tokens before matching."""
    return _perturb_longest_word(s, ".")


def homoglyph(s: str) -> str:
    """Homoglyph obfuscation: Latin a/e/o/c/p/x/y -> visually-identical Cyrillic.

    Attack principle: confusable look-alikes render the SAME but are different code points,
    so a byte/substring rule misses them. Expected bypass: 'ignore' (with Cyrillic о/е) is
    not the ASCII 'ignore'. Canonicalization that defeats it: Unicode confusables-fold /
    skeleton (or NFKC for the foldable subset)."""
    return "".join(_HOMOGLYPH.get(ch, ch) for ch in s)


PERTURBATIONS: dict[str, Callable[[str], str]] = {
    "case_flip": case_flip,
    "zero_width": zero_width,
    "punctuate": punctuate,
    "homoglyph": homoglyph,
}


def perturb_case(case: CorpusCase, kind: str) -> CorpusCase:
    """A variant of `case` with `input` transformed by PERTURBATIONS[kind] (KeyError on an
    unknown kind). id = f'{case.id}::var.{kind}'. attack_class / owasp / success_when /
    dimension / severity / source / tool_id are preserved (still the same attack,
    obfuscated). output_marker / secret_canary / system_prompt are dropped — robustness
    reads the WAL catch signal only, markers are irrelevant (EV-AE7 §7)."""
    transform = PERTURBATIONS[kind]
    return replace(
        case,
        id=f"{case.id}::var.{kind}",
        input=transform(case.input),
        output_marker="",
        secret_canary="",  # nosec B106 — clearing a CorpusCase field, not a secret value
        system_prompt="",
    )


def perturb_corpus(
    cases: Iterable[CorpusCase], kinds: Iterable[str] | None = None
) -> list[CorpusCase]:
    """One variant per (case, kind), in deterministic (case, kind) order, with unique ids.
    `kinds` defaults to all of PERTURBATIONS. Callers pre-filter `cases` to the caught-at-
    base set (robustness is only meaningful for cases the rule caught) — the CLI does this."""
    selected = list(PERTURBATIONS) if kinds is None else list(kinds)
    return [perturb_case(case, kind) for case in cases for kind in selected]
